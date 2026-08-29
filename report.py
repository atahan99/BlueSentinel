#!/usr/bin/env python3
"""Read both collector logs, correlate them into incidents, print the result.

Offline and read-only. Nothing here touches a radio, so it runs anywhere the
logs are, and it can be re-run as often as you like.
"""
import argparse
import csv
import json
import sys

import parse


def load(path):
    try:
        with open(path) as fh:
            return [json.loads(l) for l in fh if l.strip().startswith("{")]
    except FileNotFoundError:
        return []


def fmt_rssi(inc):
    lo, hi = inc["rssi_min"], inc["rssi_max"]
    if lo is None:
        return "-"
    return "%d" % lo if lo == hi else "%d..%d" % (lo, hi)


def fmt_addr(inc):
    addr = inc["initiator"] or inc["canary_peer"] or "unknown"
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
        out.write("  %-24s %-28s %-9s %-5s %s\n"
                  % ("started", "prober", "rssi", "att", "seen by"))
        for inc in sorted(rows, key=lambda i: i["start"]):
            out.write("  %-24s %-28s %-9s %-5d %s\n"
                      % (inc["start"], fmt_addr(inc), fmt_rssi(inc),
                         inc["att_count"], "+".join(inc["sources"]) or "-"))
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
                "rssi_min", "rssi_max", "att_count", "att_ops", "bytes_written",
                "sources"])
    for inc in incidents:
        w.writerow([
            inc["start"], inc["end"], inc["profile"] or "",
            inc["initiator"] or inc["canary_peer"] or "",
            inc.get("initiator_random") or "",
            inc["rssi_min"] if inc["rssi_min"] is not None else "",
            inc["rssi_max"] if inc["rssi_max"] is not None else "",
            inc["att_count"],
            "; ".join("%dx %s" % (n, op) for op, n in sorted(inc["att_ops"].items())),
            "; ".join(str(x) for x in inc["writes"]),
            "+".join(inc["sources"]),
        ])


def summarize(canary, witness):
    """Incidents, plus the scanners that only ever looked.

    Shared with tui.py so the live view and the CLI can never disagree about
    what counts as a scanner.
    """
    incidents = parse.incidents(canary, witness)
    # A device that connected is an incident, not a passing scanner. Listing it
    # under "scanned but did not connect" would make that heading a lie.
    connected = {a.lower() for inc in incidents
                 for a in (inc["initiator"], inc["canary_peer"]) if a}
    scans = [(a, n) for a, n in parse.scan_summary(witness)
             if a.lower() not in connected]
    return incidents, scans


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel report")
    ap.add_argument("--canary", default="logs/canary.jsonl")
    ap.add_argument("--witness", default="logs/witness.jsonl")
    ap.add_argument("--format", choices=("table", "json", "csv"), default="table")
    args = ap.parse_args()

    incidents, scans = summarize(load(args.canary), load(args.witness))

    if args.format == "json":
        json.dump({"incidents": incidents, "scanners": scans}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.format == "csv":
        write_csv(incidents, sys.stdout)
    else:
        table(incidents, scans, sys.stdout)


if __name__ == "__main__":
    main()
