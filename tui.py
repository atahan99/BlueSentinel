#!/usr/bin/env python3
"""One screen that runs the whole rig: both radios, the live feed, the report.

Supervisor only. It spawns canary.py and witness.py as subprocesses and reads
what they already write to disk -- logs/canary.jsonl is the canary's machine
interface, and witness.py's --convert path is offline and idempotent. Nothing
here re-implements serial, sniffer or parsing logic, and none of the four
existing scripts had to change to support it (beyond report.summarize being
lifted out of report.main so both views count scanners the same way).

The point of the whole thing is the address handoff. The canary picks its
advertising address at runtime and the witness has to be told it; doing that by
eye between two terminals is the one step that silently ruins a run, because a
witness following the wrong address captures a perfectly valid pcap of nothing.
Here the canary's own log announces the address and the witness is started from
it, including after an unexpected address_changed.

Stdlib curses on purpose: the project's dependency list is pyserial and pytest,
and a live view is not worth a third entry.
"""
import argparse
import collections
import contextlib
import curses
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
CANARY_LOG = os.path.join(LOGS, "canary.jsonl")
WITNESS_LOG = os.path.join(LOGS, "witness.jsonl")
PCAP = os.path.join(LOGS, "witness.pcapng")

PROBE_INTERVAL = 3.0     # seconds between USB presence checks
AUTO_REFRESH = 30.0      # seconds between background report rebuilds
FEED_MAX = 500           # feed lines kept in memory; the JSONL keeps everything
STOP_GRACE = 20.0        # seconds a collector gets to shut down on its own
# Generous on purpose: on SIGINT the witness kills nrfutil, then converts the
# whole pcap before exiting, and that scales with capture size. Escalating
# through it would kill a conversion mid-write. The canary exits immediately,
# so this only ever costs time when there is real work to wait for.


# --- probing -----------------------------------------------------------------

NRF_SNIFFER = (0x1915, 0x522A)  # Nordic nRF52840 Dongle running sniffer firmware


def probe_ports():
    """Which radios are on the bus right now, as {name: port or None}.

    USB enumeration rather than witness.find_sniffer, and not as a shortcut.
    `tshark -D` only lists the sniffer by running the extcap shim, which opens
    the dongle to ask what it is -- so once nrfutil is capturing and holds the
    port, the interface vanishes from the list. A status poll built on that
    reports the dongle as unplugged during exactly the window where it is
    working, which is worse than not showing it at all. Presence is a property
    of the bus, not of who has the port open.

    The extcap interface *name* is still witness.py's business; it discovers
    its own and does not need one from here.
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
        """Records completed since the last call.

        Buffered by line rather than read line-at-a-time: the canary flushes
        per record, but a read can still land mid-line, and half a JSON object
        must be held rather than dropped.
        """
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

    Both events matter. advertising_start is the normal handoff; the canary
    also emits address_changed if a rotation ever moves the address, which
    means an already-running witness is now watching a device that no longer
    exists. Last one wins -- these arrive in order.
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
    """Start a collector with its output pinned to a file.

    Both collectors print to stdout and stderr. Left alone that lands on top of
    the curses screen and corrupts it, so it goes to a file that the status bar
    quotes the tail of -- an error still reaches you, it just does not eat the
    display.

    start_new_session so the whole thing can be signalled as a group.
    """
    fh = open(stderr_path, "ab", buffering=0)
    return subprocess.Popen([sys.executable] + argv, cwd=ROOT,
                            stdin=subprocess.DEVNULL, stdout=fh, stderr=fh,
                            start_new_session=True)


def stop(proc):
    """Shut a collector down the way Ctrl-C would, then insist.

    SIGINT first, and not as politeness: it is the only signal either collector
    handles usefully. The canary logs a `stopped` event on it, and the witness
    converts its pcap and writes the .end anchor that parse.clock_offset needs
    to put sniffer timestamps on the host's clock. A plain SIGTERM skips both,
    leaving a capture whose events land an hour from the canary's.
    """
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


# --- state -------------------------------------------------------------------

class App:
    def __init__(self, args):
        self.args = args
        self.canary = None
        self.witness = None
        # Seed from the log of the last run, so opening the console after the
        # fact can still convert and attribute an existing pcap. Without this
        # the address is only ever learned live, and a report built between
        # runs silently omits everything the witness saw.
        self.address = bait_address(report.load(CANARY_LOG), None)
        self.witness_address = None   # what the running witness was told
        self.tail = Tail(CANARY_LOG)
        self.feed = collections.deque(maxlen=FEED_MAX)
        self.report_lines = []
        # Probed once here as well as on the worker: enumeration is a few
        # milliseconds, and without it the first frame claims both radios are
        # unplugged until the worker's first pass lands.
        self.ports = probe_ports()
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
        self.tail.open_at_end()
        argv = ["canary.py", "--dwell", str(self.args.dwell)]
        if self.args.duration:
            argv += ["--duration", str(self.args.duration)]
        if self.args.port:
            argv += ["--port", self.args.port]
        self.canary = spawn(argv, os.path.join(LOGS, "canary.stderr"))
        self.note = "canary started"

    def start_witness(self):
        """Only ever called with an address the canary has actually announced."""
        argv = ["witness.py", self.address]
        if self.args.duration:
            argv += ["--duration", str(self.args.duration)]
        self.witness = spawn(argv, os.path.join(LOGS, "witness.stderr"))
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
        records = self.tail.read()
        for rec in records:
            # canary.QUIET, not a list of our own: the canary already decided
            # which events are noise on a terminal and suppresses them from its
            # own stdout. Reading the JSONL instead of its stdout must not undo
            # that -- a connection is otherwise scrolled away by its own
            # per-poll RSSI readings. The file still keeps every one of them.
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
            # Deliberately not restarted here: killing the witness to re-follow
            # would end the capture mid-run. Say it loudly instead and let the
            # operator decide -- 'w' restarts it.
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
        """Rebuild the incident table, converting the live pcap first.

        witness.py writes a pcap continuously but only converts when it stops,
        which is why a running report shows `att 0`. Its --convert path is
        offline and rewrites the JSONL from scratch, so it is safe to run
        against a capture still being appended to: it simply sees the frames
        written so far.
        """
        if self.address and os.path.exists(PCAP):
            # convert() reports trouble -- a non-monotonic capture above all --
            # by printing to stderr, which is right for the CLI and would paint
            # over the curses screen here. Catch it and give it the status line.
            said = io.StringIO()
            try:
                with contextlib.redirect_stderr(said):
                    tshark = witness.find_binary("tshark",
                                                 witness.TSHARK_FALLBACKS,
                                                 "--tshark")
                    witness.convert(tshark, PCAP, self.address, WITNESS_LOG)
            except (SystemExit, OSError) as e:
                self.note = "convert failed: %s" % e
            told = said.getvalue().strip().splitlines()
            if told:
                self.note = told[-1]
        incidents, scans = report.summarize(report.load(CANARY_LOG),
                                            report.load(WITNESS_LOG))
        buf = io.StringIO()
        report.table(incidents, scans, buf)
        self.report_lines = buf.getvalue().splitlines()

    def worker(self):
        """USB probing and report rebuilds, off the draw thread.

        `tshark -D` and a conversion over a multi-megabyte pcap both take long
        enough to stutter the display if done inline.
        """
        last_probe = last_refresh = 0.0
        while not self.quit:
            now = time.time()
            if now - last_probe >= PROBE_INTERVAL:
                self.ports = probe_ports()
                last_probe = now
            due = self.refresh_wanted or (now - last_refresh >= AUTO_REFRESH
                                          and running(self.witness))
            if due:
                self.refresh_wanted = False
                self.refreshing = True
                try:
                    self.refresh()
                finally:
                    self.refreshing = False
                last_refresh = time.time()
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


def human_size(path):
    try:
        n = os.path.getsize(path)
    except OSError:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def short_port(path):
    """Drop the constant /dev/cu. prefix. Eight characters that say nothing,
    bought back for the bait address, which is the field worth reading."""
    return (path or "").rsplit("/", 1)[-1].replace("cu.", "", 1) or None


def status_rows(app):
    """Per-radio status as (present, cells), cells being columns.

    Columns rather than one preformatted string: fixed padding went ragged the
    moment a device name or port path changed length -- an ident that exactly
    filled its field left no gutter at all, and shorter ones left six. Widths
    belong to whatever is actually on screen, so they are computed in
    status_lines from both rows together.

    No curses here, so the layout stays checkable without a terminal.
    """
    dev = app.device
    ident = " ".join(filter(None, (dev.get("model"), dev.get("firmware"))))

    if running(app.canary):
        cstate, cextra = "running", app.address or "waiting for address"
    else:
        cstate, cextra = "idle", ("last %s" % app.address if app.address else "")

    if running(app.witness):
        wstate, wextra = "capturing", human_size(PCAP)
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
    # Clamped: KEY_UP has no upper bound of its own, and an unclamped scroll
    # drives `end` negative, where the slice silently reads from the wrong end
    # of the list and the pane goes blank.
    end = max(1, len(lines) - app.scroll)
    for i, line in enumerate(lines[max(0, end - (bottom - top)):end]):
        put(win, top + i, 1, line)

    put(win, h - 2, 0, "-" * (w - 1), curses.color_pair(DIM))
    # The note wins the status line; the collector's last stderr line only
    # shows when there is nothing else to say. Read the file only then -- draw
    # runs five times a second and this is otherwise a wasted read per frame.
    if app.note:
        text, colour = app.note + ("  [refreshing]" if app.refreshing else ""), DIM
    else:
        text, colour = tail_file(os.path.join(LOGS, "canary.stderr")), BAD
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
            if app.address:
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


def demo():
    """Self-check for the non-curses logic. Run: python3 tui.py --selfcheck"""
    import tempfile
    import types

    # The handoff, which is the whole reason this program exists.
    start = {"event": "advertising_start", "data": {"address": "E1:84:87:02:B3:1E"}}
    assert bait_address([start], None) == "E1:84:87:02:B3:1E"
    assert bait_address([], "AA:BB") == "AA:BB", "no news must not clear the address"
    changed = {"event": "address_changed", "data": {"before": "A", "after": "C7:11"}}
    assert bait_address([start, changed], None) == "C7:11", "rotation must win"
    assert bait_address([{"event": "connect", "data": {"peer": "X"}}], "AA") == "AA"
    assert bait_address([{"event": "advertising_start", "data": {}}], "AA") == "AA", \
        "an address-less start must not blank a known address"

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "canary.jsonl")
        with open(path, "w") as fh:
            fh.write(json.dumps({"event": "old", "ts": "x"}) + "\n")
        t = Tail(path)
        t.open_at_end()
        assert t.read() == [], "a previous run must not replay as live"
        with open(path, "a") as fh:
            fh.write(json.dumps(start) + "\n")
            fh.write('{"event": "part')          # a write caught mid-line
        got = t.read()
        assert len(got) == 1 and got[0]["event"] == "advertising_start"
        assert t.read() == [], "half a record must be held, not dropped"
        with open(path, "a") as fh:
            fh.write('ial"}\n')
        assert t.read() == [{"event": "partial"}], "the held half must complete"

    # Layout. Broken twice already: once clipping the bait address off the
    # right edge, once leaving no gutter between an ident and its port.
    fake = types.SimpleNamespace(
        device={"model": "BLEFRIEND32", "firmware": "0.9.0"},
        ports={"canary": "/dev/cu.usbserial-2140",
               "witness": "/dev/cu.usbmodem21301"},
        canary=None, witness=None, address="E1:84:87:02:B3:1E")
    lines = status_lines(status_rows(fake))
    assert "BLEFRIEND32 0.9.0  usbserial-2140" in lines[0], lines[0]
    assert lines[0].index("idle") == lines[1].index("idle"), lines
    assert not any(l.endswith(" ") for l in lines), lines
    assert max(len(l) for l in lines) + 3 < 80, "must fit an 80-column terminal"

    print("tui.py self-check ok")


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
    ap.add_argument("--selfcheck", action="store_true", help="run the self-check and exit")
    args = ap.parse_args()
    if args.selfcheck:
        return demo()

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
        # A conversion writes witness.jsonl in one pass at the end. Quitting
        # through it truncates the file and the next report silently reads a
        # short capture, so give the worker a moment to land it. Bounded, since
        # the pcap is the evidence and the JSONL can always be rebuilt.
        worker.join(timeout=15)
    print("logs in %s -- python3 report.py for the full table" % LOGS)


if __name__ == "__main__":
    main()
