"""Console logic that needs no terminal: the address handoff, log tailing, layout."""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tui

START = {"event": "advertising_start", "data": {"address": "E1:84:87:02:B3:1E"}}


def test_bait_address_handoff():
    assert tui.bait_address([START], None) == "E1:84:87:02:B3:1E"
    assert tui.bait_address([], "AA:BB") == "AA:BB", "no news must not clear the address"
    changed = {"event": "address_changed", "data": {"before": "A", "after": "C7:11"}}
    assert tui.bait_address([START, changed], None) == "C7:11", "rotation must win"
    assert tui.bait_address([{"event": "connect", "data": {"peer": "X"}}], "AA") == "AA"
    assert tui.bait_address([{"event": "advertising_start", "data": {}}], "AA") == "AA", \
        "an address-less start must not blank a known address"


def test_tail_holds_partial_lines(tmp_path):
    path = tmp_path / "canary.jsonl"
    path.write_text(json.dumps({"event": "old", "ts": "x"}) + "\n")
    t = tui.Tail(str(path))
    t.open_at_end()
    assert t.read() == [], "a previous run must not replay as live"
    with open(path, "a") as fh:
        fh.write(json.dumps(START) + "\n")
        fh.write('{"event": "part')          # a write caught mid-line
    got = t.read()
    assert len(got) == 1 and got[0]["event"] == "advertising_start"
    assert t.read() == [], "half a record must be held, not dropped"
    with open(path, "a") as fh:
        fh.write('ial"}\n')
    assert t.read() == [{"event": "partial"}], "the held half must complete"


def test_status_layout_fits_80_columns():
    fake = types.SimpleNamespace(
        device={"model": "BLEFRIEND32", "firmware": "0.9.0"},
        ports={"canary": "/dev/cu.usbserial-2140", "witness": "/dev/cu.usbmodem21301"},
        canary=None, witness=None, address="E1:84:87:02:B3:1E")
    lines = tui.status_lines(tui.status_rows(fake))
    assert "BLEFRIEND32 0.9.0  usbserial-2140" in lines[0], lines[0]
    assert lines[0].index("idle") == lines[1].index("idle"), lines
    assert not any(l.endswith(" ") for l in lines), lines
    assert max(len(l) for l in lines) + 3 < 80, "must fit an 80-column terminal"


def test_pcap_bytes_sums_segments(tmp_path):
    (tmp_path / "witness-000.pcapng").write_bytes(b"x" * 100)
    (tmp_path / "witness-001.pcapng").write_bytes(b"x" * 23)
    (tmp_path / "witness-000.pcapng.end").write_text("1")
    assert tui.pcap_bytes(str(tmp_path)) == 123
    assert tui.pcap_bytes(None) == 0
    assert tui.human_size(123) == "123 B"


def no_radios():
    return {"canary": None, "witness": None}


def test_tick_survives_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(tui, "LOGS", str(tmp_path))
    monkeypatch.setattr(tui, "probe_ports", no_radios)
    app = tui.App(types.SimpleNamespace())
    assert app.run_dir is None

    def boom():
        raise ValueError("bad line")
    monkeypatch.setattr(tui, "probe_ports", boom)
    app.tick()
    assert app.note == "worker error: bad line"

    app.note = ""
    monkeypatch.setattr(tui, "probe_ports", no_radios)
    monkeypatch.setattr(app, "refresh", boom)
    app.refresh_wanted = True
    app.tick()
    assert app.note == "worker error: bad line" and not app.refreshing


def test_app_seeds_from_latest_run(tmp_path, monkeypatch):
    run = tmp_path / "20261107-120000"
    run.mkdir()
    (run / "canary.jsonl").write_text(json.dumps(START) + "\n")
    os.symlink(str(run), str(tmp_path / "latest"))
    monkeypatch.setattr(tui, "LOGS", str(tmp_path))
    monkeypatch.setattr(tui, "probe_ports", no_radios)
    app = tui.App(types.SimpleNamespace())
    assert app.run_dir == os.path.realpath(str(run))
    assert app.address == "E1:84:87:02:B3:1E"


def test_a_dying_witness_is_not_respawned_every_frame(tmp_path, monkeypatch):
    """Regression from a live run: a witness that exits at startup was restarted
    on every frame, five times a second, each leaking a file handle."""
    monkeypatch.setattr(tui, "LOGS", str(tmp_path))
    monkeypatch.setattr(tui, "probe_ports", no_radios)
    started = []
    dead = types.SimpleNamespace(poll=lambda: 1)
    monkeypatch.setattr(tui, "spawn", lambda argv, path: started.append(argv) or dead)
    app = tui.App(types.SimpleNamespace(duration=0))
    app.run_dir, app.address = str(tmp_path), "E1:84:87:02:B3:1E"
    app.canary = types.SimpleNamespace(poll=lambda: None)   # canary running
    for _ in range(5):
        app.pump()
    assert len(started) == 1, "restarted %d times without waiting" % len(started)
    app.witness_started -= tui.WITNESS_RETRY
    app.pump()
    assert len(started) == 2 and app.note.startswith("witness exited")
