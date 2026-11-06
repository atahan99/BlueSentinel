#!/usr/bin/env python3
"""One screen that runs the whole rig: both radios, the live feed, the report.

Supervisor only: it creates a run folder (logs/<run>/), spawns canary.py and
witness.py into it, and reads what they write there. No serial, sniffer or
parsing logic lives here.

The point is the address handoff: the canary announces its address in its log
and the witness is started from it. A witness on the wrong address captures a
valid pcap of nothing. Stdlib curses so the dependency list stays short.
"""
import argparse
import collections
import contextlib
import curses
import glob
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time

import canary
import parse
import report
import witness

ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(ROOT, "logs")

PROBE_INTERVAL = 3.0     # seconds between USB presence checks
AUTO_REFRESH = 30.0      # seconds between background report rebuilds
FEED_MAX = 500           # feed lines kept in memory; the JSONL keeps everything
STOP_GRACE = 20.0        # seconds a collector gets to shut down on its own
# Generous: on SIGINT the witness stops nrfutil and converts before exiting;
# escalating early would kill that conversion mid-write.


# --- probing -----------------------------------------------------------------

NRF_SNIFFER = (0x1915, 0x522A)  # Nordic nRF52840 Dongle running sniffer firmware


def probe_ports():
    """Which radios are on the bus right now, as {name: port or None}.

    USB enumeration, not `tshark -D`: the sniffer vanishes from -D while it is
    capturing (docs/hardware-notes.md §1, "The sniffer").
    """
    try:
        return {"canary": canary.find_port(),
                "witness": canary.find_port(NRF_SNIFFER)}
    except OSError:
        return {"canary": None, "witness": None}


# --- log tailing -------------------------------------------------------------

class Tail:
    """Follow a JSONL file that another process is appending to."""

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.buf = ""

    def open_at_end(self):
        """Start reading at EOF, so a previous run's events do not scroll past
        as if they were happening now."""
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        open(self.path, "a").close()
        self.fh = open(self.path)
        self.fh.seek(0, 2)
        self.buf = ""

    def read(self):
        """Records completed since the last call. A read can land mid-line,
        so half a JSON object is held, not dropped."""
        if not self.fh:
            return []
        out = []
        self.buf += self.fh.read()
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out


def bait_address(records, current):
    """The address the witness should be following, given new canary records.
    advertising_start is the normal handoff; address_changed means a running
    witness now watches a device that no longer exists. Last one wins.
    """
    for rec in records:
        data = rec.get("data") or {}
        if rec.get("event") == "advertising_start" and data.get("address"):
            current = data["address"]
        elif rec.get("event") == "address_changed" and data.get("after"):
            current = data["after"]
    return current


# --- process control ---------------------------------------------------------

def spawn(argv, stderr_path):
    """Start a collector with stdout/stderr in a file (it would corrupt the
    curses screen; the status bar quotes its tail), in its own process group."""
    fh = open(stderr_path, "ab", buffering=0)
    return subprocess.Popen([sys.executable] + argv, cwd=ROOT,
                            stdin=subprocess.DEVNULL, stdout=fh, stderr=fh,
                            start_new_session=True)


def stop(proc):
    """Shut a collector down the way Ctrl-C would, then insist. SIGINT first:
    only on it does the canary log `stopped` and the witness write the .end
    clock anchor (docs/hardware-notes.md §1, "The sniffer")."""
    if not proc or proc.poll() is not None:
        return
    pgid = os.getpgid(proc.pid)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except OSError:
            return
        try:
            proc.wait(timeout=STOP_GRACE)
            return
        except subprocess.TimeoutExpired:
            continue


def tail_file(path, limit=200):
    """Last non-empty line of a file, for the status bar."""
    try:
        with open(path, errors="replace") as fh:
            lines = [l.strip() for l in fh.read()[-4096:].splitlines() if l.strip()]
        return lines[-1][:limit] if lines else ""
    except OSError:
        return ""


def running(proc):
    return proc is not None and proc.poll() is None


def pcap_bytes(run_dir):
    """Total size of the run's witness segments."""
    return sum(os.path.getsize(p) for p in
               glob.glob(os.path.join(run_dir or "", "witness-*.pcapng")))


# --- state -------------------------------------------------------------------

class App:
    def __init__(self, args):
        self.args = args
        self.canary = None
        self.witness = None
        # Seed from the last run so 'r' can still rebuild its report; without
        # the address its pcap cannot be converted.
        self.run_dir = self.address = None
        latest = os.path.join(LOGS, "latest")
        if os.path.exists(latest):
            self.run_dir = os.path.realpath(latest)
            self.address = bait_address(
                report.load(os.path.join(self.run_dir, "canary.jsonl")), None)
        self.witness_address = None   # what the running witness was told
        self.tail = None
        self.feed = collections.deque(maxlen=FEED_MAX)
        self.report_lines = []
        # Probed here too, or the first frame shows both radios unplugged.
        self.ports = probe_ports()
        self.last_probe = self.last_refresh = 0.0
        self.device = {}              # ATI fields, once the canary reports them
        self.note = ""
        self.mode = "feed"
        self.scroll = 0
        self.refresh_wanted = False
        self.refreshing = False
        self.quit = False

    # -- collectors --

    def start(self):
        if running(self.canary):
            return
        self.run_dir = canary.new_run(LOGS)
        self.address = None   # the previous run's address is not this bait's
        self.tail = Tail(os.path.join(self.run_dir, "canary.jsonl"))
        self.tail.open_at_end()
        argv = ["canary.py", "--dir", self.run_dir, "--dwell", str(self.args.dwell)]
        if self.args.duration:
            argv += ["--duration", str(self.args.duration)]
        if self.args.port:
            argv += ["--port", self.args.port]
        self.canary = spawn(argv, os.path.join(self.run_dir, "canary.stderr"))
        self.note = "canary started"

    def start_witness(self):
        """Only ever called with an address the canary has actually announced."""
        argv = ["witness.py", self.address, "--dir", self.run_dir]
        if self.args.duration:
            argv += ["--duration", str(self.args.duration)]
        self.witness = spawn(argv, os.path.join(self.run_dir, "witness.stderr"))
        self.witness_address = self.address
        self.note = "witness following %s" % self.address

    def stop_all(self):
        for p in (self.canary, self.witness):
            stop(p)
        self.canary = self.witness = None
        self.note = "stopped"

    # -- per-frame work --

    def pump(self):
        """Drain the canary's log and act on it. Runs on the draw thread; it
        only touches files that are already open, so it cannot block."""
        records = self.tail.read() if self.tail else []
        for rec in records:
            # canary.QUIET: the canary's own idea of terminal noise, so per-poll
            # RSSI does not scroll a connection away. The file keeps them all.
            if rec.get("event") not in canary.QUIET:
                self.feed.append(parse.format_event(rec))
            if rec.get("event") == "advertising_start":
                self.device = {k: v for k, v in (rec.get("data") or {}).items()
                               if k in ("model", "firmware", "softdevice")}
        before = self.address
        self.address = bait_address(records, self.address)

        if self.address and not running(self.witness) and running(self.canary):
            self.start_witness()
        elif self.address != before and running(self.witness):
            # Not restarted automatically; the operator decides with 'w'.
            self.note = ("address changed to %s; witness still on %s -- press w"
                         % (self.address, self.witness_address))

        if self.args.duration and self.canary and not running(self.canary):
            if running(self.witness):
                stop(self.witness)
                self.witness = None
            self.canary = None
            self.refresh_wanted = True
            self.note = "run finished"

    def refresh(self):
        """Rebuild the incident table, converting the run's segments first.

        The witness only converts when it stops; converting here is what makes
        a live report show ATT ops. live=True anchors the unfinished segment's
        clock on now, since it has no .end yet.
        """
        if not self.run_dir:
            return
        if self.address:
            # convert prints warnings to stderr, which would paint over curses.
            said = io.StringIO()
            try:
                with contextlib.redirect_stderr(said):
                    tshark = witness.find_binary("tshark",
                                                 witness.TSHARK_FALLBACKS,
                                                 "--tshark")
                    witness.convert_run(tshark, self.run_dir, self.address,
                                        live=running(self.witness))
            except (SystemExit, OSError) as e:
                self.note = "convert failed: %s" % e
            told = said.getvalue().strip().splitlines()
            if told:
                self.note = told[-1]
        incidents, scans = report.summarize(
            report.load(os.path.join(self.run_dir, "canary.jsonl")),
            report.load(os.path.join(self.run_dir, "witness.jsonl")))
        buf = io.StringIO()
        report.table(incidents, scans, buf)
        self.report_lines = buf.getvalue().splitlines()

    def tick(self):
        """One worker pass. Any error goes to the status line: a dead worker
        would silently stop USB probing and refreshes."""
        try:
            now = time.time()
            if now - self.last_probe >= PROBE_INTERVAL:
                self.last_probe = now
                self.ports = probe_ports()
            if self.refresh_wanted or (now - self.last_refresh >= AUTO_REFRESH
                                       and running(self.witness)):
                self.refresh_wanted = False
                self.last_refresh = now
                self.refreshing = True
                self.refresh()
        except Exception as e:
            self.note = "worker error: %s" % e
        finally:
            self.refreshing = False

    def worker(self):
        """USB probing and report rebuilds, off the draw thread, where a
        conversion would stutter the display."""
        while not self.quit:
            self.tick()
            time.sleep(0.25)


# --- drawing -----------------------------------------------------------------

OK, BAD, DIM, HEAD = 1, 2, 3, 4


def put(win, y, x, text, attr=0):
    """addstr that clips instead of raising on a small terminal."""
    h, w = win.getmaxyx()
    if not (0 <= y < h and 0 <= x < w - 1):
        return
    try:
        win.addnstr(y, x, text, w - x - 1, attr)
    except curses.error:
        pass


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def short_port(path):
    """Drop the constant /dev/cu. prefix. Eight characters that say nothing,
    bought back for the bait address, which is the field worth reading."""
    return (path or "").rsplit("/", 1)[-1].replace("cu.", "", 1) or None


def status_rows(app):
    """Per-radio status as (present, cells). Columns, not a padded string:
    status_lines sizes them from both rows. No curses, so it is testable."""
    dev = app.device
    ident = " ".join(filter(None, (dev.get("model"), dev.get("firmware"))))

    if running(app.canary):
        cstate, cextra = "running", app.address or "waiting for address"
    else:
        cstate, cextra = "idle", ("last %s" % app.address if app.address else "")

    if running(app.witness):
        wstate, wextra = "capturing", human_size(pcap_bytes(app.run_dir))
    elif app.address and running(app.canary):
        wstate, wextra = "starting", ""
    else:
        wstate, wextra = "idle", ""

    return [
        (bool(app.ports["canary"]),
         ["canary", ident or "Bluefruit",
          short_port(app.ports["canary"]) or "not plugged in", cstate, cextra]),
        (bool(app.ports["witness"]),
         ["witness", "nRF52840 sniffer",
          short_port(app.ports["witness"]) or "not plugged in", wstate, wextra]),
    ]


def status_lines(rows):
    """Rows as aligned columns with a two-space gutter. The last cell is not
    padded -- nothing follows it, and trailing blanks would only widen the
    line towards the clip."""
    cells = [c for _, c in rows]
    widths = [max(len(row[i]) for row in cells) for i in range(len(cells[0]) - 1)]
    return [("  ".join(c.ljust(w) for c, w in zip(row, widths))
             + "  " + row[-1]).rstrip() for row in cells]


def draw(win, app):
    win.erase()
    h, w = win.getmaxyx()
    put(win, 0, 0, "BlueSentinel".ljust(w - 1), curses.color_pair(HEAD) | curses.A_BOLD)

    rows = status_rows(app)
    for y, (line, (present, _)) in enumerate(zip(status_lines(rows), rows), start=1):
        put(win, y, 1, "*", curses.color_pair(OK if present else BAD) | curses.A_BOLD)
        put(win, y, 3, line)

    put(win, 3, 0, "-" * (w - 1), curses.color_pair(DIM))

    top, bottom = 4, h - 3
    if app.mode == "feed":
        lines = list(app.feed) or ["(nothing yet -- press s to start)"]
    else:
        lines = app.report_lines or ["(no report yet -- press r)"]
    # Clamped: a negative `end` slices from the wrong end and blanks the pane.
    end = max(1, len(lines) - app.scroll)
    for i, line in enumerate(lines[max(0, end - (bottom - top)):end]):
        put(win, top + i, 1, line)

    put(win, h - 2, 0, "-" * (w - 1), curses.color_pair(DIM))
    # The note wins; the canary's stderr tail is read only when there is none.
    if app.note:
        text, colour = app.note + ("  [refreshing]" if app.refreshing else ""), DIM
    else:
        text, colour = tail_file(os.path.join(app.run_dir or LOGS,
                                              "canary.stderr")), BAD
    if text:
        put(win, h - 2, 1, (" " + text + " ")[:w - 2], curses.color_pair(colour))
    keys = " s start/stop   w re-follow   r refresh   tab %s   q quit " % (
        "report" if app.mode == "feed" else "feed")
    put(win, h - 1, 0, keys.ljust(w - 1), curses.color_pair(HEAD))
    win.noutrefresh()
    curses.doupdate()


def loop(stdscr, app):
    curses.curs_set(0)
    for pair, fg in ((OK, curses.COLOR_GREEN), (BAD, curses.COLOR_RED),
                     (DIM, curses.COLOR_YELLOW), (HEAD, curses.COLOR_CYAN)):
        curses.init_pair(pair, fg, -1)
    stdscr.timeout(200)

    if app.args.start:
        app.start()

    while not app.quit:
        app.pump()
        draw(stdscr, app)
        ch = stdscr.getch()
        if ch in (ord("q"), 27):
            app.quit = True
        elif ch == ord("s"):
            app.stop_all() if running(app.canary) else app.start()
        elif ch == ord("w"):
            # A restarted witness opens a new segment; the old one is kept.
            if app.address and app.run_dir:
                stop(app.witness)
                app.start_witness()
        elif ch == ord("r"):
            app.refresh_wanted = True
        elif ch == ord("\t"):
            app.mode = "report" if app.mode == "feed" else "feed"
            app.scroll = 0
        elif ch == curses.KEY_UP:
            app.scroll += 1
        elif ch == curses.KEY_DOWN:
            app.scroll = max(0, app.scroll - 1)


def main():
    ap = argparse.ArgumentParser(description="BlueSentinel unified console")
    ap.add_argument("--dwell", type=float, default=900,
                    help="seconds per profile, passed to the canary")
    ap.add_argument("--duration", type=float, default=0,
                    help="stop both collectors after this many seconds "
                         "(0 = until you quit)")
    ap.add_argument("--port", help="override CP210x auto-discovery")
    ap.add_argument("--start", action="store_true",
                    help="start the collectors immediately instead of on 's'")
    args = ap.parse_args()

    os.makedirs(LOGS, exist_ok=True)
    app = App(args)
    worker = threading.Thread(target=app.worker, daemon=True)
    worker.start()
    try:
        curses.wrapper(lambda scr: (curses.use_default_colors(), loop(scr, app)))
    except KeyboardInterrupt:
        pass
    finally:
        app.quit = True
        # Never leave a collector holding a serial port after the screen is gone.
        app.stop_all()
        # Let an in-flight conversion land. Bounded: the pcap is the evidence
        # and witness.jsonl can always be rebuilt.
        worker.join(timeout=15)
    if app.run_dir:
        print("logs in %s -- python3 report.py --dir %s" % (app.run_dir, app.run_dir))
    else:
        print("logs in %s" % LOGS)


if __name__ == "__main__":
    main()
