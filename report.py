#!/usr/bin/env python3
"""Read both collector logs, correlate them into incidents, print the result.
Offline and read-only: runs anywhere the logs are, as often as you like.
"""
import argparse
import csv
import json
import os
import sys

import parse


def load(path):
    """JSONL records from `path`; [] if missing. A torn or corrupt line (say, a
    crash mid-write) is skipped with one warning rather than killing the report."""
    out, bad = [], 0
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
                if isinstance(rec, dict):
                    out.append(rec)
                else:
                    bad += 1
    except FileNotFoundError:
        return []
    if bad:
        sys.stderr.write("warning: skipped %d unreadable line(s) in %s\n" % (bad, path))
    return out


def fmt_rssi(inc):
    lo, hi = inc["rssi_min"], inc["rssi_max"]
    if lo is None:
        return "-"
    return "%d" % lo if lo == hi else "%d..%d" % (lo, hi)


def fmt_addr(inc):
    # canary_peer is whatever the bait reported, so escape it before a terminal.
    addr = parse.safe(inc["initiator"] or inc["canary_peer"] or "unknown")
    if inc.get("initiator_random"):
        addr += " (random)"
    return addr


def table(incidents, scans, out):
    if not incidents:
        out.write("No incidents. Either nothing connected, or the collectors "
                  "were not running at the same time.\n")
    by_profile = {}
    for inc in incidents:
        by_profile.setdefault(inc["profile"] or "unattributed", []).append(inc)

    for profile in sorted(by_profile):
        rows = by_profile[profile]
        out.write("\n%s  (%d incident%s)\n" % (profile, len(rows), "" if len(rows) == 1 else "s"))
        out.write("  %-24s %-28s %-9s %-5s %-7s %s\n"
                  % ("started", "prober", "rssi", "att", "replies", "seen by"))
        for inc in sorted(rows, key=lambda i: i["start"]):
            out.write("  %-24s %-28s %-9s %-5d %-7d %s\n"
                      % (inc["start"], fmt_addr(inc), fmt_rssi(inc), inc["att_count"],
                         inc["att_replies"], "+".join(inc["sources"]) or "-"))
            for op, n in sorted(inc["att_ops"].items(), key=lambda kv: -kv[1]):
                out.write("      %4d x %s\n" % (n, op))
            for w in inc["writes"]:
                out.write("      wrote: %r\n" % w)

    if scans:
        out.write("\nscanned but did not connect\n")
        for addr, n in scans:
            out.write("  %-24s %d SCAN_REQ\n" % (addr, n))

    if any(i.get("initiator_random") for i in incidents):
        out.write("\nNote: addresses marked (random) are resolvable private "
                  "addresses.\nThey rotate, and do not identify a device across "
                  "sessions.\n")


def write_csv(incidents, out):
    w = csv.writer(out)
    w.writerow(["start", "end", "profile", "prober", "address_is_random",
                "rssi_min", "rssi_max", "att_count", "att_replies", "att_ops",
                "bytes_written", "sources"])
    for inc in incidents:
        w.writerow([
            inc["start"], inc["end"], inc["profile"] or "",
            inc["initiator"] or inc["canary_peer"] or "",
            inc.get("initiator_random") or "",
            inc["rssi_min"] if inc["rssi_min"] is not None else "",
            inc["rssi_max"] if inc["rssi_max"] is not None else "",
            inc["att_count"], inc["att_replies"],
            "; ".join("%dx %s" % (n, op) for op, n in sorted(inc["att_ops"].items())),
            "; ".join(str(x) for x in inc["writes"]),
            "+".join(inc["sources"]),
        ])


def summarize(canary, witness):
    """Incidents, plus the scanners that only ever looked. Shared with tui.py so
    the live view and the CLI agree on what counts as a scanner."""
    incidents = parse.incidents(canary, witness)
    # A device that connected is an incident, not a "scanned but did not connect".
    connected = {a for inc in incidents
                 for a in (inc["initiator"], inc["canary_peer"]) if a}
    scans = [(a, n) for a, n in parse.scan_summary(witness) if a not in connected]
    return incidents, scans


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel report")
    ap.add_argument("--dir", default="logs/latest", help="run folder")
    ap.add_argument("--format", choices=("table", "json", "csv"), default="table")
    args = ap.parse_args()
    if not os.path.isdir(args.dir):
        sys.exit("No run folder at %s -- start a run, or pass --dir." % args.dir)

    incidents, scans = summarize(load(os.path.join(args.dir, "canary.jsonl")),
                                 load(os.path.join(args.dir, "witness.jsonl")))

    if args.format == "json":
        json.dump({"incidents": incidents, "scanners": scans}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.format == "csv":
        write_csv(incidents, sys.stdout)
    else:
        table(incidents, scans, sys.stdout)


if __name__ == "__main__":
    main()
