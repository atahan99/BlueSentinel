#!/usr/bin/env python3
"""The canary: drives the Bluefruit LE Friend as bait and logs what touches it.

Transport only. All parsing lives in parse.py.

Written against firmware 0.6.2 and 0.9.0; the AT command set was probed, not
assumed (docs/hardware-notes.md §2). 0.6.2 cannot name a connected peer, so
identifying the prober falls to the witness.
"""
import argparse
import datetime
import glob
import json
import os
import sys
import time

import serial
from serial.tools import list_ports

import parse

CP210X = (0x10C4, 0xEA60)  # Silicon Labs CP2102N on the Bluefruit LE Friend
RESET_SETTLE = 2.0  # seconds for the nRF51 to come back after ATZ

# 0.6.2 caps advertising at 180 s and rejects 0 while answering OK, so the bait
# goes dark on its own and must be kicked (docs/hardware-notes.md §1).
ADV_TIMEOUT = 180

QUIET = {"rssi"}  # logged every poll while connected; noise on a terminal


def find_port(ids=CP210X):
    """First serial port matching a (vid, pid), or None. Never hardcode a path.

    On macOS pyserial lists /dev/cu.*, the right node: /dev/tty.* blocks on
    carrier detect. tui.py passes the sniffer's ids to reuse this.
    """
    for p in list_ports.comports():
        if (p.vid, p.pid) == ids:
            return p.device
    return None


def new_run(root="logs"):
    """Create root/<UTC YYYYmmdd-HHMMSS>[-N] and atomically repoint root/latest
    at it. The link target is relative so the logs folder stays relocatable."""
    base = os.path.join(root, time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
    run, n = base, 1
    while True:
        try:
            os.makedirs(run)
            break
        except FileExistsError:
            n += 1
            run = "%s-%d" % (base, n)
    tmp = os.path.join(root, ".latest-%d" % os.getpid())
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(os.path.basename(run), tmp)
    os.replace(tmp, os.path.join(root, "latest"))
    return run


def now():
    """ISO8601 UTC with milliseconds. One clock read, so the seconds and the
    milliseconds cannot disagree across a tick."""
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Canary:
    def __init__(self, port, baud=9600, timeout=3.0):
        self.ser = serial.Serial(port, baud, rtscts=True, timeout=0.5)
        self.timeout = timeout
        time.sleep(0.5)  # the nRF51 drops bytes sent immediately after open
        self.ser.reset_input_buffer()

    def cmd(self, c):
        """Send one AT command, return the raw reply text (echo included)."""
        self.ser.reset_input_buffer()
        self.ser.write((c + "\r\n").encode())  # explicit, never os.linesep
        self.ser.flush()
        out, deadline = [], time.time() + self.timeout
        while time.time() < deadline:
            line = self.ser.readline().decode("utf-8", "replace")
            if not line:
                continue
            out.append(line)
            if line.strip() in parse.TERMINATORS:
                break
        return "".join(out)

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass


def load_profiles(directory):
    profiles = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path) as fh:
            p = json.load(fh)
        p["id"] = os.path.splitext(os.path.basename(path))[0]
        profiles.append(p)
    if not profiles:
        sys.exit("No profiles found in %s" % directory)
    return profiles


def apply_profile(dev, profile):
    """Apply an identity: set the name, reset, set the payload, advertise.

    AT+GAPDEVNAME only takes effect after ATZ; the payload goes after the reset
    so it cannot be discarded. Never reopen the port per rotation: DTR resets
    the nRF51 and the payload lags one profile (docs/hardware-notes.md §1).
    Returns the AT statuses so a rejected payload is visible in the log.
    """
    replies = {"stop": dev.cmd("AT+GAPSTOPADV")}
    replies["name"] = dev.cmd("AT+GAPDEVNAME=" + profile["name"])
    replies["reset"] = dev.cmd("ATZ")
    time.sleep(RESET_SETTLE)
    dev.ser.reset_input_buffer()
    if profile.get("advdata"):
        replies["advdata"] = dev.cmd("AT+GAPSETADVDATA=" + profile["advdata"])
    # AT+GAPAUTOADV=1: already advertising, so a bare start would ERROR.
    # Stop first so an ERROR in the log is real (docs/hardware-notes.md §1).
    replies["stop_after_reset"] = dev.cmd("AT+GAPSTOPADV")
    replies["start"] = dev.cmd("AT+GAPSTARTADV")
    return {k: parse.status(v) for k, v in replies.items()}


class Log:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.fh = open(path, "a")

    def write(self, event, profile=None, **data):
        rec = {"ts": now(), "source": "canary", "event": event,
               "profile": profile, "data": data}
        self.fh.write(json.dumps(rec) + "\n")
        self.fh.flush()  # a honeypot log you lose on crash is worthless
        # stdout is for whoever is watching; the file is the machine interface.
        if event not in QUIET:
            print(parse.format_event(rec), flush=True)


def run_session(dev, log, profiles, args):
    """One serial session. Returns only when --duration is reached; a lost
    device raises SerialException/OSError, which main() catches to reconnect.
    Rotation restarts from the first profile after a reconnect."""
    info = parse.device_info(dev.cmd("ATI"))
    addr = parse.at_reply("AT+BLEGETADDR", dev.cmd("AT+BLEGETADDR"))[0]
    addr = addr[0] if addr else None
    addr_type = parse.at_reply("AT+BLEGETADDRTYPE", dev.cmd("AT+BLEGETADDRTYPE"))[0]

    # Ask for no advertising timeout. 0.6.2 refuses 0 but answers OK, so the
    # read-back, never the status, decides whether the keepalive is needed.
    dev.cmd("AT+GAPINTERVALS=,,,0")
    timeout = parse.adv_timeout(dev.cmd("AT+GAPINTERVALS"))
    if timeout != 0:
        dev.cmd("AT+GAPINTERVALS=,,,%d" % ADV_TIMEOUT)
        timeout = parse.adv_timeout(dev.cmd("AT+GAPINTERVALS"))

    # Stop a peer writing +++ from reaching the AT parser. 0.9.0 only; ERROR on
    # 0.6.2 leaves the exposure open (docs/hardware-notes.md §1).
    modeswitch = parse.status(dev.cmd("AT+MODESWITCHEN=0"))

    log.write("advertising_start", address=addr,
              address_type=addr_type[0] if addr_type else None,
              adv_timeout=timeout, modeswitch_disabled=(modeswitch == "OK"),
              **info)
    print("\n  bait address: %s   <-- point the witness at this\n" % addr,
          file=sys.stderr, flush=True)

    connected, prev = False, None
    stop_at = time.time() + args.duration if args.duration else None
    while True:
        for profile in profiles:
            if stop_at and time.time() >= stop_at:
                log.write("stopped", reason="duration reached")
                return
            if connected:
                # The ATZ in apply_profile drops the link; attribute it to the
                # profile the prober actually saw, not the next one.
                log.write("disconnect", profile=prev, reason="rotation")
                connected = False
            status = apply_profile(dev, profile)
            prev = profile["id"]
            # If this ever changes, the witness is following the wrong device.
            after = parse.at_reply("AT+BLEGETADDR", dev.cmd("AT+BLEGETADDR"))[0]
            after = after[0] if after else None
            if after != addr:
                log.write("address_changed", profile=profile["id"],
                          before=addr, after=after)
                addr = after
            log.write("profile_change", profile=profile["id"],
                      name=profile["name"], advdata=profile.get("advdata"),
                      at_status=status, address=addr)

            deadline = time.time() + args.dwell
            if stop_at:
                deadline = min(deadline, stop_at)
            last_adv = time.time()
            while time.time() < deadline:
                # Kick advertising before the firmware times it out; skipped when
                # the firmware accepted "never time out".
                if timeout != 0 and time.time() - last_adv >= args.readvertise:
                    dev.cmd("AT+GAPSTOPADV")
                    log.write("readvertise", profile=profile["id"],
                              status=parse.status(dev.cmd("AT+GAPSTARTADV")))
                    last_adv = time.time()

                is_conn = parse.conn_state(dev.cmd("AT+GAPGETCONN"))
                if is_conn and not connected:
                    # From 0.9.0 the canary can name the prober itself. On 0.6.2
                    # this is None and the witness is the only source.
                    log.write("connect", profile=profile["id"],
                              rssi=parse.rssi(dev.cmd("AT+BLEGETRSSI")),
                              peer=parse.peer_addr(dev.cmd("AT+BLEGETPEERADDR")))
                elif connected and not is_conn:
                    log.write("disconnect", profile=profile["id"])
                elif is_conn:
                    r = parse.rssi(dev.cmd("AT+BLEGETRSSI"))
                    if r is not None:
                        log.write("rssi", profile=profile["id"], rssi=r)
                connected = is_conn

                if is_conn:
                    written = parse.uart_rx(dev.cmd("AT+BLEUARTRX"))
                    if written:
                        log.write("uart_write", profile=profile["id"], bytes=written)

                time.sleep(args.poll)


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel canary (the bait)")
    ap.add_argument("--port", help="override CP210x auto-discovery")
    ap.add_argument("--profiles", default="profiles")
    ap.add_argument("--dir", help="run folder (default: a new logs/<UTC time>, "
                    "linked as logs/latest)")
    ap.add_argument("--dwell", type=float, default=900,
                    help="seconds per profile (default 900; below ~300 the "
                         "device looks broken rather than interesting)")
    ap.add_argument("--poll", type=float, default=2.0,
                    help="connection-state poll interval in seconds")
    ap.add_argument("--duration", type=float, default=0,
                    help="stop after this many seconds (0 = run forever). "
                         "Use it for test runs so nothing is left in the background.")
    ap.add_argument("--readvertise", type=float, default=ADV_TIMEOUT - 60,
                    help="seconds between advertising restarts; must stay below "
                         "the firmware's %ds advertising timeout" % ADV_TIMEOUT)
    args = ap.parse_args()

    profiles = load_profiles(args.profiles)
    if args.dir:
        os.makedirs(args.dir, exist_ok=True)
    run = args.dir or new_run()
    print("run folder: %s" % run, file=sys.stderr, flush=True)
    log = Log(os.path.join(run, "canary.jsonl"))
    try:
        while True:
            port = args.port or find_port()
            if not port:
                print("waiting for CP210x (VID 0x10C4 PID 0xEA60)...", file=sys.stderr)
                time.sleep(5)
                continue
            dev = None
            try:
                dev = Canary(port)
                run_session(dev, log, profiles, args)
                return  # run_session only returns when --duration is reached
            except (serial.SerialException, OSError) as e:
                log.write("serial_error", error=str(e))
                time.sleep(5)  # USB dropped; loop re-discovers the port
            finally:
                if dev:
                    dev.close()
    except KeyboardInterrupt:  # also covers the 5 s waits
        log.write("stopped")


if __name__ == "__main__":
    main()
