#!/usr/bin/env python3
"""The witness: passively watches the bait's advertising address at link layer.

Transport only. All parsing lives in parse.py.

Two stages, deliberately kept apart:

  capture  nrfutil ble-sniffer sniff --follow <addr>  ->  <run>/witness-NNN.pcapng
  convert  tshark -r <pcap> -T ek                     ->  <run>/witness-NNN.jsonl
                                                          <run>/witness.jsonl (merged)

The pcaps are the source of truth and the evidence; the JSONL is derived and
can be regenerated at any time with --convert. Captures rotate every
SEGMENT_SECONDS into a new numbered file and never overwrite one, so a long run
only ever re-converts its newest segment.

nrfutil rather than the Wireshark extcap, because the extcap can follow an
address only through GUI control pipes (docs/hardware-notes.md §1, §4).
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import parse

TSHARK_FALLBACKS = ["/Applications/Wireshark.app/Contents/MacOS/tshark"]
NRFUTIL_FALLBACKS = [os.path.expanduser("~/.local/bin/nrfutil")]
SNIFFER_MARK = "nRF Sniffer for Bluetooth LE"
SEGMENT_SECONDS = 600


def find_binary(name, fallbacks, flag):
    path = shutil.which(name)
    if path:
        return path
    for candidate in fallbacks:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    sys.exit("%s not found. Tried PATH and %s. Override with %s."
             % (name, ", ".join(fallbacks), flag))


NRF_SNIFFER = (0x1915, 0x522A)  # Nordic nRF52840 Dongle running sniffer firmware


def find_sniffer(tshark):
    """Serial port of the sniffer: by USB id, else from `tshark -D`.

    USB first because `tshark -D` opens the dongle to identify it, which hides
    a busy one and can splice a second stream into a running capture
    (docs/hardware-notes.md §1).

    The nrfutil extcap shim names the interface after the serial device path,
    which is host-specific -- so this is discovered, never hardcoded. The name
    doubles as the serial port nrfutil wants.
    """
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if (p.vid, p.pid) == NRF_SNIFFER:
                return p.device
    except ImportError:
        pass
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if SNIFFER_MARK in line:
            return line.split(".", 1)[1].split("(")[0].strip()
    sys.exit("No sniffer interface found in `%s -D`. Is the dongle flashed and "
             "the extcap plugin installed? See README." % tshark)


def segments(run_dir):
    """The run's witness-NNN.pcapng files, in segment order."""
    names = [n for n in os.listdir(run_dir) if n.startswith("witness-")
             and n.endswith(".pcapng") and n[8:-7].isdigit()]
    return [os.path.join(run_dir, n)
            for n in sorted(names, key=lambda n: int(n[8:-7]))]


def stop(proc):
    """Stop the sniffer's process group: SIGINT, then SIGTERM, then SIGKILL.

    SIGINT is what Ctrl-C at a terminal sends; the sniffer handles it and exits
    cleanly, where SIGTERM makes the launcher print "unexpected exit code None".
    Waits on the group, not the launcher, which can exit before the sniffer.
    """
    def alive():
        proc.poll()  # reap the launcher, so its zombie does not count
        try:
            os.killpg(proc.pid, 0)
            return True
        except ProcessLookupError:
            return False

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        if not alive():
            break
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        for _ in range(50):
            if not alive():
                break
            time.sleep(0.1)
    proc.wait()


def capture(nrfutil, port, address, run_dir, duration=0):
    """Capture into numbered segments until Ctrl-C, or for `duration` seconds.

    Each segment is a new file numbered after the highest already in run_dir,
    so no rerun, re-follow or restart can overwrite earlier evidence. Every
    pcap is on disk when this returns; conversion happens afterwards.
    """
    os.makedirs(run_dir, exist_ok=True)
    deadline = time.time() + duration if duration else None
    while True:
        segs = segments(run_dir)
        n = int(os.path.basename(segs[-1])[8:-7]) + 1 if segs else 0
        pcap = os.path.join(run_dir, "witness-%03d.pcapng" % n)
        cmd = [nrfutil, "ble-sniffer", "sniff", "--port", port,
               "--follow", address, "--output-pcap-file", pcap]
        print("$ " + " ".join(cmd), file=sys.stderr, flush=True)
        # start_new_session puts the sniffer in its own process group so it can be
        # killed as a group. `nrfutil` is only a launcher -- it spawns
        # `nrfutil-ble-sniffer` as a grandchild, and killing the launcher alone
        # leaves that orphan holding the serial port, so the next run cannot open
        # the radio. Signal the group, not the process.
        proc = subprocess.Popen(cmd, start_new_session=True)
        wait = SEGMENT_SECONDS
        if deadline:
            wait = max(0, min(wait, deadline - time.time()))
        done = False
        try:
            proc.wait(timeout=wait)
            done = True  # nrfutil quit by itself; restarting would only spin
            print("nrfutil exited (%s)" % proc.returncode, file=sys.stderr)
        except subprocess.TimeoutExpired:
            done = deadline is not None and time.time() >= deadline
            if done:
                print("capture stopped after %gs" % duration, file=sys.stderr)
        except KeyboardInterrupt:
            done = True
            print("capture stopped", file=sys.stderr)
        finally:
            # A second SIGINT must not cut the shutdown short: the console
            # sends one just as --duration expires, and it skipped the .end
            # and the conversion. Once done, it stays ignored until exit, so
            # the conversion finishes too; SIGTERM still stops everything.
            try:
                previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            except ValueError:  # not the main thread (tests); nothing to guard
                previous = None
            stop(proc)
            # When the last frame was written, for capture_end(): the pcap's
            # mtime, read now, before any copy or checkout can move it. Not
            # the stop time -- a sniffer that stalled 96 s before the stop
            # shifted every frame 96 s late (docs/hardware-notes.md §1).
            if os.path.exists(pcap):
                with open(pcap + ".end", "w") as fh:
                    fh.write("%.3f\n" % os.path.getmtime(pcap))
            if previous is not None and not done:
                signal.signal(signal.SIGINT, previous)
        if done:
            return


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


def convert(tshark, pcap, address, out_path, live=False):
    """Turn one segment into log events. Returns the number written.

    Everything not addressed to or from the bait is dropped here -- the sniffer
    hears the whole neighbourhood, and that traffic is neither ours to log nor
    signal for this tool. `live` means the capture is still being written.
    """
    if not os.path.exists(pcap):
        sys.exit("No capture at %s -- run without --convert first." % pcap)
    # stderr to a file, not a pipe: it is read only after stdout is drained,
    # and a full stderr pipe would block tshark forever.
    err = tempfile.TemporaryFile()
    proc = subprocess.Popen([tshark, "-r", pcap, "-T", "ek"],
                            stdout=subprocess.PIPE, stderr=err, text=True)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    # Collect first, write second: correcting the sniffer clock offset needs
    # the last frame's timestamp, which is only known once the stream ends.
    events, last, backwards = [], None, 0
    for rec in parse.ek_records(proc.stdout):
        epoch = parse.ek_epoch(rec)
        if epoch is not None:
            if last is not None and epoch < last - 0.5:
                backwards += 1
            # File order, not max(): a second, sparse frame stream can run 68
            # minutes past the end, and anchoring there reports every
            # connection twice (docs/hardware-notes.md §1).
            last = epoch
        event = parse.witness_event(rec, address)
        if event:
            events.append((epoch, event))

    # A capture only ever moves forward. If it does not, this file holds two
    # streams, and the seam reads as a clock jump that stops incidents merging
    # (docs/hardware-notes.md §1). Say so rather than correlate nonsense.
    if backwards:
        print("warning: %s is not monotonic (%d backward time step%s). It very "
              "likely holds more than one capture -- check that nothing else "
              "opened the sniffer while this ran. Timestamps and attribution "
              "from this file are unreliable."
              % (pcap, backwards, "" if backwards == 1 else "s"), file=sys.stderr)

    anchor = capture_end(pcap)
    if anchor is None and live:
        # No .end until the segment stops, but the file is still ours, so its
        # mtime is when its last frame landed. Uncorrected, a live report was
        # measured 72 minutes in the future.
        anchor = os.path.getmtime(pcap)
    offset = parse.clock_offset(last, anchor)

    # One scan_req per scanner per minute, with a count: every phone nearby
    # scans, and 1741 SCAN_REQs from 4 neighbours in 4 minutes is just noise.
    kept, scans = [], {}
    for epoch, event in events:
        if event["event"] == "scan_req":
            key = (event["data"].get("scanner"),
                   None if epoch is None else (epoch + offset) // 60)
            if key in scans:
                scans[key]["count"] += 1
                continue
            scans[key] = event["data"]
            event["data"]["count"] = 1
        kept.append((epoch, event))

    # Temp file and rename, per process: the console's refresh and a stopping
    # witness can convert the same segment at once, and a torn file would be
    # cached as finished.
    tmp = "%s.%d.tmp" % (out_path, os.getpid())
    with open(tmp, "w") as fh:
        for epoch, event in kept:
            fh.write(json.dumps({
                "ts": parse.iso(None if epoch is None else epoch + offset),
                "source": "witness",
                "event": event["event"],
                "profile": None,  # attributed by report.py from the canary log
                "data": event["data"],
            }) + "\n")
    os.replace(tmp, out_path)
    # A failed tshark otherwise looks identical to a quiet capture: both write
    # zero events. "Nothing was probing you" and "your capture is unreadable"
    # must not be the same output.
    if proc.wait() != 0:
        err.seek(0)
        sys.exit("tshark failed reading %s:\n%s"
                 % (pcap, err.read().decode(errors="replace").strip()))
    err.close()
    return len(kept)


def convert_run(tshark, run_dir, address, live=False):
    """Convert a run's segments and merge them into <run>/witness.jsonl.

    A finished segment (it has .end) whose jsonl is newer than its pcap and
    .end is reused, so a refresh costs one segment however long the run is.
    Returns the number of events in witness.jsonl.
    """
    segs = segments(run_dir)
    for pcap in segs:
        out = pcap[:-len(".pcapng")] + ".jsonl"
        end = pcap + ".end"
        finished = os.path.exists(end)
        if not finished and os.path.getsize(pcap) == 0:
            continue  # nrfutil has not written its header yet; tshark would fail
        if (not finished or not os.path.exists(out)
                or os.path.getmtime(out) < max(os.path.getmtime(pcap),
                                               os.path.getmtime(end))):
            convert(tshark, pcap, address, out, live=live and not finished)
    merged = os.path.join(run_dir, "witness.jsonl")
    n = 0
    # Temp file and rename: the console reads witness.jsonl while this runs.
    tmp = "%s.%d.tmp" % (merged, os.getpid())
    with open(tmp, "w") as fh:
        for pcap in segs:
            if not os.path.exists(pcap[:-len(".pcapng")] + ".jsonl"):
                continue
            with open(pcap[:-len(".pcapng")] + ".jsonl") as src:
                for line in src:
                    fh.write(line)
                    n += 1
    os.replace(tmp, merged)
    return n


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel witness (the sniffer)")
    ap.add_argument("address", help="bait advertising address, as printed by canary.py")
    ap.add_argument("--dir", default="logs/latest",
                    help="run folder for the segments (default logs/latest)")
    ap.add_argument("--port", help="override sniffer serial port discovery")
    ap.add_argument("--tshark", help="override tshark location")
    ap.add_argument("--nrfutil", help="override nrfutil location")
    ap.add_argument("--duration", type=float, default=0,
                    help="capture for this many seconds then convert "
                         "(0 = until Ctrl-C). Use it for test runs.")
    ap.add_argument("--convert", action="store_true",
                    help="re-derive the JSONL from existing segments, no capture")
    args = ap.parse_args()
    # Resolved once: the canary may repoint logs/latest while this runs.
    run_dir = os.path.realpath(args.dir)

    tshark = args.tshark or find_binary("tshark", TSHARK_FALLBACKS, "--tshark")

    if args.convert:
        if not os.path.isdir(run_dir) or not segments(run_dir):
            sys.exit("No witness-NNN.pcapng in %s -- run without --convert first."
                     % run_dir)
    else:
        nrfutil = args.nrfutil or find_binary("nrfutil", NRFUTIL_FALLBACKS, "--nrfutil")
        port = args.port or find_sniffer(tshark)
        capture(nrfutil, port, args.address, run_dir, args.duration)

    n = convert_run(tshark, run_dir, args.address)
    print("%d events -> %s" % (n, os.path.join(run_dir, "witness.jsonl")),
          file=sys.stderr)


if __name__ == "__main__":
    main()
