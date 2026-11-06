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


def test_capture_drops_the_previous_runs_clock_anchor(tmp_path):
    """The last run's anchor must be gone *while* the next capture runs.

    Regression: the .end file is only meaningful for the capture it was written
    beside, but it outlived its pcap. Converting a still-growing capture -- how
    the console renders a live report -- then corrected fresh frames against
    the previous run's end time. Measured at 35 minutes off, which put every
    incident outside its profile window, filed them all under "unattributed",
    and stopped the two radios merging. Nothing errored.

    Checked mid-capture on purpose: capture() rewrites .end on the way out, so
    afterwards the file looks correct whether or not the stale one was cleared.

    A stub stands in for nrfutil so this stays hardware-free.
    """
    import threading
    import witness

    pcap = tmp_path / "w.pcapng"
    (tmp_path / "w.pcapng.end").write_text("1000.0\n")  # anchor from a dead run
    assert witness.capture_end(str(pcap)) == 1000.0

    nrfutil = tmp_path / "fake_nrfutil"
    nrfutil.write_text("#!/bin/sh\nsleep 2\n")
    nrfutil.chmod(0o755)

    seen = []
    t = threading.Thread(target=witness.capture,
                         args=(str(nrfutil), "/dev/null", BAIT.upper(), str(pcap)),
                         kwargs={"duration": 1.0})
    t.start()
    for _ in range(40):                       # inside the capture window
        time.sleep(0.025)
        if t.is_alive():
            seen.append(witness.capture_end(str(pcap)))
    t.join(timeout=20)
    assert not t.is_alive()

    assert seen, "should have sampled during the capture"
    assert set(seen) == {None}, "stale anchor was readable mid-capture: %r" % (
        sorted(s for s in set(seen) if s is not None),)
    # capture() still writes a fresh, valid anchor once it really is done.
    assert witness.capture_end(str(pcap)) > 1000.0


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
