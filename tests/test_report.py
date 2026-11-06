"""report.py: log loading and export. No hardware."""
import csv
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report


def test_load_skips_corrupt_lines_with_one_warning(tmp_path, capsys):
    p = tmp_path / "canary.jsonl"
    p.write_text('{"event": "a"}\n{"event": "b", "da\n\n{"event": "c"}\n')
    assert [r["event"] for r in report.load(str(p))] == ["a", "c"]
    assert capsys.readouterr().err == "warning: skipped 1 unreadable line(s) in %s\n" % p


def test_load_missing_file_is_empty(tmp_path):
    assert report.load(str(tmp_path / "nope.jsonl")) == []


def test_csv_neutralises_formulas_but_keeps_numbers():
    """A prober's UART bytes end up in bytes_written; a spreadsheet must not run them."""
    inc = {"start": "2026-08-04T00:01:00.000Z", "end": "2026-08-04T00:01:09.000Z",
           "profile": "smartlock", "initiator": None, "canary_peer": "aa:bb",
           "initiator_random": None, "rssi_min": -50, "rssi_max": -40,
           "att_count": 1, "att_replies": 1, "att_ops": {}, "writes": ["=1+1"],
           "sources": ["canary"]}
    buf = io.StringIO()
    report.write_csv([inc], buf)
    row = list(csv.DictReader(io.StringIO(buf.getvalue())))[0]
    assert row["bytes_written"] == "'=1+1"
    assert row["rssi_min"] == "-50"
    assert row["att_replies"] == "1"


def test_table_escapes_a_canary_reported_peer():
    inc = {"initiator": None, "canary_peer": "\x1b]0;pwn\x07", "initiator_random": None}
    assert "\x1b" not in report.fmt_addr(inc) and "\\x1b" in report.fmt_addr(inc)
