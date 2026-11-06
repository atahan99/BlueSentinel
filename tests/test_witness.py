"""Witness conversion and capture, with tshark and nrfutil stubbed. No hardware."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parse

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BAIT = "e1:84:87:02:b3:1e"


def test_clock_anchor_ignores_a_forward_clock_jump(tmp_path):
    """A single glitched frame must not drag the whole capture off the clock.

    Regression from the 2026-08-29 demo run: convert() anchored on
    max(timestamp), and exactly one frame in 43352 came back stamped 272s in
    the future. That moved every witness event 10s, pushing both radios more
    than CONNECT_MERGE_SECONDS apart, and the report split all four incidents
    into a canary-only half holding the RSSI and a witness-only half holding
    the ATT ops. Nothing errored; the incident count simply doubled.

    Real fixture frames, with only the timestamps rewritten -- the jump is the
    one thing being modelled. A stub stands in for tshark so this stays offline.
    """
    import witness

    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        frames = [l for l in fh if l.strip().startswith("{") and "layers" in l][:3]
    assert len(frames) == 3

    def restamp(line, ms):
        rec = json.loads(line)
        rec["timestamp"] = str(ms)
        return json.dumps(rec)

    # Middle frame is the glitch: 272s ahead, and not the last frame in the file.
    stream = "\n".join([restamp(frames[0], 1_000_000),
                        restamp(frames[1], 1_272_000),
                        restamp(frames[2], 1_004_000)]) + "\n"
    (tmp_path / "stream.ek").write_text(stream)

    shim = tmp_path / "fake_tshark"
    shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "stream.ek"))
    shim.chmod(0o755)

    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"")
    (tmp_path / "c.pcapng.end").write_text("1005.0\n")  # stopped 1s after t=1004

    out = tmp_path / "w.jsonl"
    n = witness.convert(str(shim), str(pcap), BAIT, str(out))
    assert n == 3, "fixture frames should all be about the bait"

    stamps = [parse.ts_seconds(json.loads(l)["ts"])
              for l in out.read_text().splitlines()]
    # Anchored on the last frame (1004) the offset is +1.0s. Anchored on the
    # glitch (1272) it would be -267s, and every stamp would be wrong by that.
    assert abs(stamps[0] - 1001.0) < 0.01, "glitched frame must not set the anchor"
    assert abs(stamps[2] - 1005.0) < 0.01


def test_capture_never_overwrites_a_segment(tmp_path, monkeypatch):
    """A new capture rotates into new numbered segments, each with its anchor.

    Regression: every witness run, and the console's re-follow, wrote to the
    same logs/witness.pcapng, so the previous capture -- the evidence -- was
    gone. A stub stands in for nrfutil so this stays hardware-free.
    """
    import witness

    nrfutil = tmp_path / "fake_nrfutil"
    nrfutil.write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        "  [ \"$1\" = --output-pcap-file ] && out=$2\n"
        "  shift\n"
        "done\n"
        "printf 'new' > \"$out\"\n"
        "trap 'exit 0' INT TERM\n"
        "sleep 30\n")
    nrfutil.chmod(0o755)

    run = tmp_path / "run"
    run.mkdir()
    (run / "witness-000.pcapng").write_bytes(b"old evidence")

    monkeypatch.setattr(witness, "SEGMENT_SECONDS", 0.4)
    start = time.time()
    witness.capture(str(nrfutil), "/dev/null", BAIT.upper(), str(run), duration=1.0)
    assert time.time() - start < 10, "stop sequence should not need escalation"

    assert (run / "witness-000.pcapng").read_bytes() == b"old evidence"
    new = witness.segments(str(run))[1:]
    assert len(new) >= 2, new
    for i, pcap in enumerate(new, 1):
        assert os.path.basename(pcap) == "witness-%03d.pcapng" % i
        assert open(pcap, "rb").read() == b"new"
        # Anchored on when the last frame was written, not when the stop came.
        assert abs(witness.capture_end(pcap) - os.path.getmtime(pcap)) < 0.01


def test_convert_warns_when_a_capture_is_not_monotonic(tmp_path, capsys):
    """Two streams in one pcap must be reported, not silently correlated.

    A `tshark -D` status poll ran the nRF extcap shim against the dongle every
    three seconds while nrfutil was capturing from it, and the pcap came out
    holding two entire captures of the same session -- the second of them
    advertising-only. The file opens fine and every frame in it is valid; only
    the seam between the streams gives it away, and clock_offset reads that
    seam as a multi-minute clock jump, after which no incident merges.
    """
    import witness

    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        frames = [l for l in fh if l.strip().startswith("{") and "layers" in l][:3]

    def restamp(line, ms):
        rec = json.loads(line)
        rec["timestamp"] = str(ms)
        return json.dumps(rec)

    shim = tmp_path / "fake_tshark"
    shim.chmod(0o755) if shim.exists() else None
    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"")

    def run(stamps):
        (tmp_path / "s.ek").write_text(
            "\n".join(restamp(f, ms) for f, ms in zip(frames, stamps)) + "\n")
        shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "s.ek"))
        shim.chmod(0o755)
        witness.convert(str(shim), str(pcap), BAIT, str(tmp_path / "o.jsonl"))
        return capsys.readouterr().err

    assert "not monotonic" not in run([1_000_000, 1_001_000, 1_002_000])
    err = run([1_000_000, 1_272_000, 1_004_000])   # time steps backwards once
    assert "not monotonic" in err, err
    assert "1 backward time step" in err, err


def test_convert_run_reconverts_only_unfinished_segments(tmp_path):
    """A refresh must cost one segment, not the whole run.

    Regression: the console re-converted the entire pcap every 30 s; at
    ~0.45 MB/min captured and ~0.9 MB/s converted, a long run became unusable.
    """
    import witness

    calls = tmp_path / "calls"
    shim = tmp_path / "fake_tshark"
    shim.write_text("#!/bin/sh\necho \"$2\" >> %s\n" % calls)  # tshark -r PCAP
    shim.chmod(0o755)

    run = tmp_path / "run"
    run.mkdir()
    for n in range(3):
        (run / ("witness-%03d.pcapng" % n)).write_bytes(b"x")
    for n in range(2):                            # 002 is still capturing
        (run / ("witness-%03d.pcapng.end" % n)).write_text("1000.0\n")

    witness.convert_run(str(shim), str(run), BAIT, live=True)
    assert len(calls.read_text().splitlines()) == 3
    calls.write_text("")
    witness.convert_run(str(shim), str(run), BAIT, live=True)
    assert calls.read_text().split() == [str(run / "witness-002.pcapng")]
    assert (run / "witness.jsonl").exists()
    assert not list(run.glob("*.tmp")), "temp files must be renamed into place"


def test_live_convert_anchors_on_the_last_write(tmp_path):
    """Without a .end, a live conversion must land near now, not in the future.

    Regression: the pcap clock was measured 4297 s ahead, and a live capture has
    no .end yet, so the console's live report stamped every event ~72 minutes
    ahead of the canary.
    """
    import witness

    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        frames = [l for l in fh if l.strip().startswith("{") and "layers" in l][:3]
    (tmp_path / "s.ek").write_text("".join(frames))
    shim = tmp_path / "fake_tshark"
    shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "s.ek"))
    shim.chmod(0o755)
    pcap = tmp_path / "witness-000.pcapng"
    pcap.write_bytes(b"x")
    # Last frame written five minutes ago -- a stalled sniffer. The anchor is
    # the file's mtime, not "now", or every frame would land 300 s late.
    written = time.time() - 300
    os.utime(str(pcap), (written, written))

    witness.convert(str(shim), str(pcap), BAIT, str(tmp_path / "o.jsonl"), live=True)
    stamps = [parse.ts_seconds(json.loads(l)["ts"])
              for l in (tmp_path / "o.jsonl").read_text().splitlines()]
    assert stamps and all(abs(s - written) < 5 for s in stamps), stamps


def test_scan_reqs_are_counted_per_scanner_per_minute(tmp_path):
    """Neighbours' phones scan constantly: 1741 SCAN_REQs from 4 of them in 4
    minutes. One event per scanner per minute, with a count, keeps the signal."""
    import witness

    def scan(ms, scanner):
        return json.dumps({"timestamp": str(ms), "layers": {"btle": {
            "btle_btle_advertising_header_pdu_type": "3",
            "btle_btle_advertising_address": BAIT,
            "btle_btle_scanning_address": scanner}}})

    a, b = "11:11:11:11:11:11", "22:22:22:22:22:22"
    stream = [scan(0, a), scan(1_000, a), scan(2_000, b), scan(30_000, a),
              scan(61_000, a)]
    (tmp_path / "s.ek").write_text("\n".join(stream) + "\n")
    shim = tmp_path / "fake_tshark"
    shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "s.ek"))
    shim.chmod(0o755)
    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"")
    (tmp_path / "c.pcapng.end").write_text("61.0\n")    # offset 0

    out = tmp_path / "o.jsonl"
    assert witness.convert(str(shim), str(pcap), BAIT, str(out)) == 3
    got = [(e["data"]["scanner"], e["data"]["count"], parse.ts_seconds(e["ts"]))
           for e in map(json.loads, out.read_text().splitlines())]
    assert got == [(a, 3, 0.0), (b, 1, 2.0), (a, 1, 61.0)]


def test_convert_run_skips_a_segment_with_nothing_written_yet(tmp_path):
    """Right after a rotation the live segment is still empty; tshark would fail on it."""
    import witness

    (tmp_path / "witness-000.pcapng").write_bytes(b"")
    assert witness.convert_run("/nonexistent/tshark", str(tmp_path), BAIT, live=True) == 0
    assert (tmp_path / "witness.jsonl").read_text() == ""


def test_a_second_sigint_during_shutdown_still_writes_the_anchor(tmp_path):
    """Regression from a live console run: the witness's --duration expired and,
    while it was stopping the sniffer, the console sent its own SIGINT. That
    interrupt aborted the shutdown, so no .end was written and nothing was
    converted."""
    import signal
    import threading
    import witness

    nrfutil = tmp_path / "fake_nrfutil"
    nrfutil.write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        "  [ \"$1\" = --output-pcap-file ] && out=$2\n"
        "  shift\n"
        "done\n"
        "printf 'frames' > \"$out\"\n"
        "trap 'sleep 1; exit 0' INT TERM\n"   # slow to exit, like the real sniffer
        "sleep 30\n")
    nrfutil.chmod(0o755)
    run = tmp_path / "run"

    t = threading.Timer(0.7, os.kill, (os.getpid(), signal.SIGINT))  # mid-shutdown
    t.start()
    try:
        witness.capture(str(nrfutil), "/dev/null", BAIT, str(run), duration=0.3)
    finally:
        t.cancel()
        signal.signal(signal.SIGINT, signal.default_int_handler)
    assert witness.capture_end(str(run / "witness-000.pcapng")) is not None
