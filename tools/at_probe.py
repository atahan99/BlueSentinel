#!/usr/bin/env python3
"""Non-interactive AT command probe for the Bluefruit LE Friend.

Send commands, print whatever comes back, verbatim. Useful for checking what
your firmware actually supports before believing any documentation about it --
the AT command set differs substantially between firmware versions, and both
this project's design and its bugs came from probing rather than assuming.

    python3 tools/at_probe.py --commands ATI 'AT+HELP'

The slide switch must be on CMD. If every command times out, that is the most
likely cause -- far more likely than a broken device.
"""
import argparse
import os
import sys
import time

import serial

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canary import find_port  # noqa: E402  -- one source of truth for discovery


def send(ser, cmd, timeout):
    """Send one command, return the raw reply text. Stops on OK/ERROR."""
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    ser.flush()
    out, deadline = [], time.time() + timeout
    while time.time() < deadline:
        line = ser.readline().decode("utf-8", "replace")
        if not line:
            continue
        out.append(line)
        if line.strip() in ("OK", "ERROR"):
            break
    return "".join(out)


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

    with serial.Serial(port, args.baud, rtscts=True, timeout=0.5) as ser:
        time.sleep(0.5)  # the nRF51 drops bytes sent immediately after open
        ser.reset_input_buffer()
        for cmd in args.commands:
            print("\n$ %s" % cmd)
            reply = send(ser, cmd, args.timeout)
            print(reply if reply else "<no response within %.1fs>" % args.timeout)


if __name__ == "__main__":
    main()
