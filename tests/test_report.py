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


def test_table_escapes_a_canary_reported_peer():
    inc = {"initiator": None, "canary_peer": "\x1b]0;pwn\x07", "initiator_random": None}
    assert "\x1b" not in report.fmt_addr(inc) and "\\x1b" in report.fmt_addr(inc)
