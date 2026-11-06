#!/usr/bin/env python3
"""Play the prober: connect to your own bait from this computer and write to its UART.

An alternative to doing it by hand from a phone app. It finds the bait by any of
the names in profiles/, connects, writes each payload to the Nordic UART RX
characteristic, and disconnects -- which is exactly what the canary is there to
log. Point it only at your own bait.

    python3 -m pip install bleak      # optional; not needed by the collectors
    python3 tools/prober.py           # the three security test payloads
    python3 tools/prober.py --hex 68656c6c6f --hold 20

The default payloads are the ones the README's security section is about: an
ANSI escape sequence, a fake "OK" line inside the data, and a spreadsheet
formula. On macOS the first run asks for Bluetooth permission for your terminal
app; a run from a context that cannot show the prompt is killed (exit 134).
"""
import argparse
import asyncio
import glob
import json
import os
import sys

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
except ImportError:
    sys.exit("tools/prober.py needs bleak: python3 -m pip install bleak")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UART_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Nordic UART, written by the central
DEFAULT_PAYLOADS = [
    "1b5b33316d50574e45441b5b306d",   # ESC[31mPWNED ESC[0m -- terminal escape injection
    "68690a4f4b0a736563726574",       # hi\nOK\nsecret       -- fake AT terminator
    "3d312b31",                       # =1+1                 -- CSV formula
]


def bait_names():
    names = set()
    for path in glob.glob(os.path.join(ROOT, "profiles", "*.json")):
        with open(path) as fh:
            names.add(json.load(fh)["name"])
    return names


async def probe(names, payloads, hold, gap, timeout):
    # The name rides in the scan response, so this needs an active scan, which
    # is bleak's default. macOS may report a cached name from an earlier disguise.
    dev = await BleakScanner.find_device_by_filter(
        lambda d, ad: (ad.local_name or d.name) in names, timeout=timeout)
    if not dev:
        sys.exit("no bait found in %ds (looked for %s)" % (timeout, ", ".join(sorted(names))))
    print("found     %s" % (dev.name or dev.address), flush=True)
    try:
        await _write(dev, payloads, hold, gap)
    except BleakError as e:  # the bait drops every link when it rotates its disguise
        sys.exit("connection dropped (%s); the bait may have rotated, run it again" % e)
    print("disconnected", flush=True)


async def _write(dev, payloads, hold, gap):
    async with BleakClient(dev) as client:
        print("connected", flush=True)
        await asyncio.sleep(hold)  # long enough for the canary's poll to see it
        for p in payloads:
            await client.write_gatt_char(UART_RX, p, response=True)
            print("wrote     %r" % p, flush=True)
            await asyncio.sleep(gap)  # one canary poll per write, so each is logged alone


def main():
    ap = argparse.ArgumentParser(description="Connect to your own bait and write to its UART")
    ap.add_argument("--hex", nargs="*", help="payloads as hex (default: the three security tests)")
    ap.add_argument("--name", action="append", help="bait name to look for (default: every profile)")
    ap.add_argument("--hold", type=float, default=5, help="seconds connected before writing")
    ap.add_argument("--gap", type=float, default=5, help="seconds between writes")
    ap.add_argument("--timeout", type=int, default=30, help="seconds to scan for the bait")
    args = ap.parse_args()
    payloads = [bytes.fromhex(h) for h in (DEFAULT_PAYLOADS if args.hex is None else args.hex)]
    asyncio.run(probe(set(args.name or bait_names()), payloads, args.hold, args.gap, args.timeout))


if __name__ == "__main__":
    main()
