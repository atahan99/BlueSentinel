#!/usr/bin/env python3
"""The witness: passively watches the bait's advertising address at link layer.

Transport only. All parsing lives in parse.py.

Two stages, deliberately kept apart:

  capture  nrfutil ble-sniffer sniff --follow <addr>  ->  logs/witness.pcapng
  convert  tshark -r <pcap> -T ek                     ->  logs/witness.jsonl

The pcap is the source of truth and the evidence; the JSONL is derived and can
be regenerated at any time with --convert. That means a crash mid-run loses no
data, and it is why there is no live-parsing path to maintain.

Why nrfutil and not the Wireshark extcap: the extcap plugin exposes
follow-an-address only through interactive control pipes driven by the
Wireshark GUI -- there is no command-line option for it. Measured side by side,
the extcap default mode captured 7 packets where this path captured 6163.
See docs/hardware-notes.md.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time

import parse

TSHARK_FALLBACKS = ["/Applications/Wireshark.app/Contents/MacOS/tshark"]
NRFUTIL_FALLBACKS = [os.path.expanduser("~/.local/bin/nrfutil")]
SNIFFER_MARK = "nRF Sniffer for Bluetooth LE"


def find_binary(name, fallbacks, flag):
    path = shutil.which(name)
    if path:
        return path
    for candidate in fallbacks:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    sys.exit("%s not found. Tried PATH and %s. Override with %s."
             % (name, ", ".join(fallbacks), flag))


def find_sniffer(tshark):
    """Interface name of the sniffer, from `tshark -D`.

    The nrfutil extcap shim names the interface after the serial device path,
    which is host-specific -- so this is discovered, never hardcoded. The name
    doubles as the serial port nrfutil wants.
    """
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if SNIFFER_MARK in line:
            return line.split(".", 1)[1].split("(")[0].strip()
    sys.exit("No sniffer interface found in `%s -D`. Is the dongle flashed and "
             "the extcap plugin installed? See README." % tshark)


def capture(nrfutil, port, address, pcap, duration=0):
    """Run the sniffer until Ctrl-C, or for `duration` seconds if given.

    Either way the pcap is already on disk when this returns, so a stop is
    never a data loss -- conversion happens afterwards from the file.
    """
    os.makedirs(os.path.dirname(pcap) or ".", exist_ok=True)
    # Drop the previous capture's anchor before overwriting its pcap. It is
    # only valid for the file it was written beside, and while this capture is
    # running any conversion of the growing pcap -- which is how the console
    # shows a live report -- would otherwise correct the new frames against the
    # old run's end time. Measured: a stale anchor put the witness 35 minutes
    # from the canary, so every incident missed its profile window and landed
    # under "unattributed" with the two radios never merging. No anchor yields
    # offset 0.0 and uncorrected timestamps, which is honest and close; a stale
    # one is confidently wrong, and nothing about the output looks broken.
    try:
        os.remove(pcap + ".end")
    except FileNotFoundError:
        pass
    cmd = [nrfutil, "ble-sniffer", "sniff", "--port", port,
           "--follow", address, "--output-pcap-file", pcap]
    print("$ " + " ".join(cmd), file=sys.stderr, flush=True)
    # start_new_session puts the sniffer in its own process group so it can be
    # killed as a group. `nrfutil` is only a launcher -- it spawns
    # `nrfutil-ble-sniffer` as a grandchild, and killing the launcher alone
    # leaves that orphan holding the serial port, so the next run cannot open
    # the radio. Signal the group, not the process.
    proc = subprocess.Popen(cmd, start_new_session=True)
    try:
        proc.wait(timeout=duration or None)
    except subprocess.TimeoutExpired:
        print("capture stopped after %gs" % duration, file=sys.stderr)
    except KeyboardInterrupt:
        print("capture stopped", file=sys.stderr)
    finally:
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    # Record when the capture really ended, next to the pcap. The sniffer's own
    # clock cannot be trusted (see parse.clock_offset) and a file's mtime is only
    # a good stand-in until someone copies, checks out or unpacks the file --
    # git clone alone shifts it by however old the repo is.
    with open(pcap + ".end", "w") as fh:
        fh.write("%.3f\n" % time.time())


def capture_end(pcap):
    """Wallclock seconds at which this capture finished, or None if unknown.

    Written by capture() beside the pcap. Falling back to the file's mtime is
    tempting and wrong: any copy, checkout or unpack rewrites it, and a stale
    anchor does not fail loudly -- it silently shifts every event in the file.
    Better to leave timestamps as the sniffer recorded them than to "correct"
    them against a number that means nothing.
    """
    try:
        with open(pcap + ".end") as fh:
            return float(fh.read().strip())
    except (OSError, ValueError):
        return None


def convert(tshark, pcap, address, out_path):
    """Turn the pcap into log events. Returns the number written.

    Everything not addressed to or from the bait is dropped here -- the sniffer
    hears the whole neighbourhood, and that traffic is neither ours to log nor
    signal for this tool.
    """
    if not os.path.exists(pcap):
        sys.exit("No capture at %s -- run without --convert first." % pcap)
    proc = subprocess.Popen([tshark, "-r", pcap, "-T", "ek"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    # Collect first, write second: correcting the sniffer clock offset needs
    # the last frame's timestamp, which is only known once the stream ends.
    events, last, backwards = [], None, 0
    for rec in parse.ek_records(proc.stdout):
        epoch = parse.ek_epoch(rec)
        if epoch is not None:
            if last is not None and epoch < last - 0.5:
                backwards += 1
            # File order, not max(). Some captures hold two frame streams --
            # the real --follow capture plus a sparse one whose timestamps run
            # far past the end of the run (docs/hardware-notes.md §1). The
            # maximum timestamp then belongs to that second stream and is not
            # when this capture ended: measured at 68 minutes past the end of a
            # 200-second run. Anchoring there shifts every event by the size of
            # the overshoot, which puts the two radios more than
            # CONNECT_MERGE_SECONDS apart, and every connection is reported
            # twice -- once per radio, ATT ops on one copy, RSSI on the other.
            # Nothing looks broken; the report just doubles. The last frame in
            # file order is the true end, and the only one whose timestamp can
            # be checked against the moment the capture stopped.
            last = epoch
        event = parse.witness_event(rec, address)
        if event:
            events.append((epoch, event))

    # A capture only ever moves forward. If it does not, this file holds more
    # than one stream: something else opened the dongle while nrfutil was
    # capturing and its frames ended up here too. Measured once -- a `tshark -D`
    # status poll every three seconds ran the nRF extcap shim against the busy
    # dongle, and the pcap came out holding two whole captures of the same
    # session, one of them advertising-only. Nothing about that file looks
    # wrong: it opens fine and every frame is valid. But the seam between the
    # two streams reads as a several-minute clock jump, which drags the anchor
    # below and pushes the two radios far enough apart that no incident merges.
    # Say so rather than reporting correlated-looking nonsense.
    if backwards:
        print("warning: %s is not monotonic (%d backward time step%s). It very "
              "likely holds more than one capture -- check that nothing else "
              "opened the sniffer while this ran. Timestamps and attribution "
              "from this file are unreliable."
              % (pcap, backwards, "" if backwards == 1 else "s"), file=sys.stderr)

    offset = parse.clock_offset(last, capture_end(pcap))
    with open(out_path, "w") as fh:
        for epoch, event in events:
            fh.write(json.dumps({
                "ts": parse.iso(None if epoch is None else epoch + offset),
                "source": "witness",
                "event": event["event"],
                "profile": None,  # attributed by report.py from the canary log
                "data": event["data"],
            }) + "\n")
        fh.flush()
    written = len(events)
    err = proc.stderr.read()
    # A failed tshark otherwise looks identical to a quiet capture: both write
    # zero events. "Nothing was probing you" and "your capture is unreadable"
    # must not be the same output.
    if proc.wait() != 0:
        sys.exit("tshark failed reading %s:\n%s" % (pcap, err.strip()))
    return written


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel witness (the sniffer)")
    ap.add_argument("address", help="bait advertising address, as printed by canary.py")
    ap.add_argument("--pcap", default="logs/witness.pcapng")
    ap.add_argument("--log", default="logs/witness.jsonl")
    ap.add_argument("--port", help="override sniffer serial port discovery")
    ap.add_argument("--tshark", help="override tshark location")
    ap.add_argument("--nrfutil", help="override nrfutil location")
    ap.add_argument("--duration", type=float, default=0,
                    help="capture for this many seconds then convert "
                         "(0 = until Ctrl-C). Use it for test runs.")
    ap.add_argument("--convert", action="store_true",
                    help="re-derive the JSONL from an existing pcap, no capture")
    args = ap.parse_args()

    tshark = args.tshark or find_binary("tshark", TSHARK_FALLBACKS, "--tshark")

    if not args.convert:
        nrfutil = args.nrfutil or find_binary("nrfutil", NRFUTIL_FALLBACKS, "--nrfutil")
        port = args.port or find_sniffer(tshark)
        capture(nrfutil, port, args.address, args.pcap, args.duration)

    n = convert(tshark, args.pcap, args.address, args.log)
    print("%d events -> %s" % (n, args.log), file=sys.stderr)


if __name__ == "__main__":
    main()
