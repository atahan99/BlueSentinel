#!/usr/bin/env python3
"""Non-interactive AT command probe for the Bluefruit LE Friend.

Send commands, print whatever comes back, verbatim. Check what your firmware
supports before trusting any documentation: the command set differs a lot
between versions (docs/hardware-notes.md §2).

    python3 tools/at_probe.py --commands ATI 'AT+HELP'

The slide switch must be on CMD; if every command times out, that is the most
likely cause.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import parse  # noqa: E402
from canary import Canary, find_port  # noqa: E402  -- one serial path


def main():
    ap = argparse.ArgumentParser(description="Probe the Bluefruit's AT interface")
    ap.add_argument("--commands", nargs="+", required=True)
    ap.add_argument("--port", help="override auto-discovery")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    port = args.port or find_port()
    if not port:
        sys.exit("No CP210x port found (VID 0x10C4 PID 0xEA60). "
                 "Is the Bluefruit plugged in?")

    print("# port:    %s" % port)
    print("# baud:    %d, 8N1, rtscts" % args.baud)
    print("# probed:  %s" % time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    dev = Canary(port, baud=args.baud, timeout=args.timeout)
    try:
        for cmd in args.commands:
            print("\n$ %s" % cmd)
            reply = dev.cmd(cmd)
            # Escaped per line: a connected peer's UART bytes are attacker data.
            print("\n".join(parse.safe(l) for l in reply.splitlines()) if reply
                  else "<no response within %.1fs>" % args.timeout)
    finally:
        dev.close()


if __name__ == "__main__":
    main()
