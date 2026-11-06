"""Pure functions over collector output. No I/O, no globals.

Everything here is testable with no hardware attached, which is what CI runs.
Transport lives in canary.py and witness.py and is deliberately not tested.

Shapes are driven by what firmware 0.6.2 actually returns -- see
docs/hardware-notes.md. The AT parser echoes each command before replying, so
every reply starts with the command itself.
"""

import datetime
import json

TERMINATORS = ("OK", "ERROR")


def at_reply(cmd, raw):
    """Split a raw AT reply into (value_lines, status).

    status is "OK", "ERROR", or None when the device never terminated the
    reply (timeout). The echoed command is dropped.

    >>> at_reply("AT+BLEGETADDR", "AT+BLEGETADDR\\r\\nE1:84:87:02:B3:1E\\r\\nOK\\r\\n")
    (['E1:84:87:02:B3:1E'], 'OK')
    """
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if lines and lines[0] == cmd.strip():
        lines.pop(0)
    status = lines.pop() if lines and lines[-1] in TERMINATORS else None
    return lines, status


def status(raw):
    """Just the OK/ERROR/None terminator of a reply, ignoring any values.

    For fire-and-forget commands where only success matters. Avoids the
    at_reply("", raw)[1] idiom, which looks like a mistake at a glance.
    """
    return at_reply("", raw)[1]


def _first(cmd, raw):
    values, status = at_reply(cmd, raw)
    return values[0] if status == "OK" and values else None


def conn_state(raw):
    """True if AT+GAPGETCONN reports a live connection."""
    return _first("AT+GAPGETCONN", raw) == "1"


def rssi(raw):
    """Peer RSSI in dBm, or None. Firmware returns 0 when not connected,
    which is not a real reading -- report it as None rather than 0 dBm."""
    v = _first("AT+BLEGETRSSI", raw)
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return None if n == 0 else n


def uart_rx(raw):
    """Bytes a peer wrote to the UART characteristic, or None if nothing
    was buffered. AT+BLEUARTRX returns a bare OK when the buffer is empty."""
    values, status = at_reply("AT+BLEUARTRX", raw)
    if status != "OK" or not values:
        return None
    return "\n".join(values)


def peer_addr(raw):
    """Connected peer's address, or None.

    AT+BLEGETPEERADDR exists from firmware 0.9.0 and returns ERROR on 0.6.2,
    where identifying the prober is entirely the witness's job.
    """
    return _first("AT+BLEGETPEERADDR", raw)


def gap_intervals(raw):
    """AT+GAPINTERVALS as a list of ints. Field count is firmware dependent:
    0.6.2 returns 4 (min conn, max conn, adv interval, adv timeout), 0.9.0
    returns 5 (adds connection supervision timeout)."""
    values, status = at_reply("AT+GAPINTERVALS", raw)
    if status != "OK" or not values:
        return []
    out = []
    for f in values[0].split(","):
        try:
            out.append(int(f))
        except ValueError:
            out.append(None)
    return out


def adv_timeout(raw):
    """Advertising timeout in seconds; 0 means never stop. None if unreadable.

    0.6.2 caps this at 180 and silently refuses 0. 0.9.0 accepts 0. Read it
    back rather than assuming the write took -- both firmwares answer OK either
    way, so the reply status tells you nothing.
    """
    v = gap_intervals(raw)
    return v[3] if len(v) > 3 else None


def device_info(raw):
    """Parse ATI into a dict. Field order is fixed by the firmware:
    model, chip, serial, fw, bootloader, build date, softdevice."""
    values, status = at_reply("ATI", raw)
    keys = ("model", "chip", "serial", "firmware", "bootloader", "built", "softdevice")
    return dict(zip(keys, values)) if status == "OK" else {}


# --- witness side: tshark -T ek records -------------------------------------
#
# Field names come from a real capture (tests/fixtures/witness_adv.ek.jsonl).
# tshark's ek output doubles the layer prefix ("btle_btle_advertising_address"),
# which is ugly and version-dependent, so fields are looked up by suffix rather
# than by exact key. That also means a prefix change upstream does not silently
# turn every field into None.

PDU_TYPES = {
    0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
    4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND",
}

# ek reports the ATT opcode in decimal. Named here because "Read By Group Type
# Request" tells you someone is enumerating the GATT table and "8" does not.
ATT_OPCODES = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response",
    0x04: "Find Information Request", 0x05: "Find Information Response",
    0x08: "Read By Type Request", 0x09: "Read By Type Response",
    0x0A: "Read Request", 0x0B: "Read Response",
    0x0C: "Read Blob Request", 0x0D: "Read Blob Response",
    0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response",
    0x12: "Write Request", 0x13: "Write Response",
    0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
    0x52: "Write Command",
}


def field(layers, suffix):
    """First value whose key ends with `suffix`, across all layers."""
    for layer in layers.values():
        if not isinstance(layer, dict):
            continue
        for k, v in layer.items():
            if k.endswith(suffix):
                return v
    return None


def ifield(layers, suffix):
    """Like field(), but coerced to int.

    tshark's ek writer emits numeric fields as JSON *strings* ("0", "6157",
    "-24") while booleans stay real booleans. Verified against a real capture --
    do not assume these arrive as numbers.
    """
    v = field(layers, suffix)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def ek_records(lines):
    """Yield the packet records from `tshark -T ek` output.

    ek alternates a bare {"index":...} line with the actual record, and our
    fixtures carry '#' provenance headers. Both are skipped.
    """
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "layers" in rec:
            yield rec


def witness_event(rec, bait_addr):
    """Map one ek record to a log event, or None if it is not about the bait.

    The sniffer hears the whole neighbourhood; everything not addressed to or
    from the bait is dropped here. That is what keeps the log all-signal.
    """
    layers = rec.get("layers", {})

    # Drop packets that failed CRC. The sniffer hands them over anyway, and a
    # single flipped bit in an address invents a device that was never there --
    # observed in a real run as a dozen phantom scanners one bit away from a
    # genuine address, including one "scanner" that was the bait itself.
    if field(layers, "nordic_ble_crcok") is False:
        return None

    data = {
        "rssi": ifield(layers, "nordic_ble_rssi"),
        "channel": ifield(layers, "nordic_ble_channel"),
    }

    # ATT first, and deliberately not address-filtered. Once a connection is up,
    # link-layer data packets carry no device addresses at all -- filtering them
    # by address drops every ATT operation. The sniffer is following the bait's
    # address, so connection traffic in this capture is ours by construction.
    if any(k.startswith("btatt") for k in layers):
        opcode = ifield(layers, "btatt_opcode")
        data["pdu"] = "ATT"
        data["opcode"] = opcode
        data["op"] = ATT_OPCODES.get(opcode, "0x%02x" % opcode if opcode else None)
        data["handle"] = field(layers, "btatt_handle")
        data["value"] = field(layers, "btatt_value")
        return dict(event="att_op", data=data)

    adv = field(layers, "btle_advertising_address")
    initiator = field(layers, "btle_initiator_address")
    scanning = field(layers, "btle_scanning_address")
    if bait_addr.lower() not in [a.lower() for a in (adv, initiator, scanning) if a]:
        return None

    pdu = PDU_TYPES.get(ifield(layers, "advertising_header_pdu_type"))
    data["pdu"] = pdu

    if pdu == "SCAN_REQ":
        data["scanner"] = scanning
        return dict(event="scan_req", data=data)
    if pdu == "CONNECT_IND":
        data["initiator"] = initiator
        # randomized_tx tells you whether the initiator address is random or
        # public -- the difference between a meaningful MAC and a rotating one.
        data["initiator_random"] = field(layers, "advertising_header_randomized_tx")
        return dict(event="connect", data=data)
    return None  # plain advertising from our own bait is not an incident


def ek_epoch(rec):
    """Epoch seconds from an ek record, or None.

    tshark's ek writer emits epoch milliseconds as a string.
    """
    try:
        return int(rec.get("timestamp")) / 1000.0
    except (TypeError, ValueError):
        return None


def iso(epoch):
    """Epoch seconds -> ISO8601 UTC with milliseconds, matching the canary."""
    if epoch is None:
        return None
    dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(epoch * 1000) % 1000)


def clock_offset(last_frame, capture_end):
    """Seconds to add to sniffer timestamps to put them on the host's clock.

    The nRF sniffer's pcap clock jumps. In one measured run its timestamps sat
    a constant 71 minutes ahead of real time, and the pcap spanned 78 minutes
    for 389 seconds of capture. The *rate* is correct -- intervals between
    events matched the canary's to within two seconds across a six-minute run
    -- so a single offset corrects the whole file. Do not rescale: fitting a
    slope to the endpoints assumes a drift that is not there and smears every
    event across the capture window.

    Anchor it on the *last frame in file order* against the moment the capture
    stopped (witness.capture_end, never the file's mtime, which any copy or
    checkout rewrites). Never on max(): some captures hold a second, sparse
    frame stream whose timestamps run well past the end of the run -- 68
    minutes past, on a 200-second capture -- so the largest timestamp in the
    file belongs to that stream and is not when this capture ended. Anchoring
    there shifts every event by the size of the overshoot, far enough to push
    the two radios past CONNECT_MERGE_SECONDS, and every connection is then
    reported twice, once per radio, with the ATT ops on one copy and the RSSI
    on the other. witness.convert warns when it sees such a file.
    See docs/hardware-notes.md §1; the 71 minutes above may be the same effect.

    Without this the witness log lands over an hour from the canary log, every
    event falls outside its true profile window, and attribution silently
    credits whichever profile happened to be live last. Nothing looks broken:
    the timestamps are well-formed, just false.

    A healthy clock gives an offset near zero, so this is always safe.
    """
    if last_frame is None or capture_end is None:
        return 0.0
    return capture_end - last_frame


# Fields worth showing on a terminal, in the order they read best. Anything not
# listed is still in the log file -- this is a view, not a filter.
DETAIL = ("name", "address", "peer", "initiator", "scanner", "rssi", "op",
          "bytes", "before", "after", "error", "reason", "status")


def format_event(rec):
    """One human-readable line for a log record.

    The JSONL file stays canonical and machine-readable; this exists only so a
    running collector is legible over your shoulder. Unknown event types render
    fine rather than needing a branch each.

    >>> format_event({"ts": "2026-08-04T01:01:28.817Z", "event": "connect",
    ...               "profile": "keyboard", "data": {"rssi": -50}})
    '01:01:28  connect         keyboard    -50 dBm'
    """
    data = rec.get("data") or {}
    detail = ["%d dBm" % v if k == "rssi" else str(v)
              for k, v in ((k, data.get(k)) for k in DETAIL) if v is not None]
    return "%s  %-15s %-11s %s" % ((rec.get("ts") or "")[11:19] or "--:--:--",
                                   rec.get("event") or "-",
                                   rec.get("profile") or "",
                                   "  ".join(detail))


def profile_windows(canary_events):
    """Build [(start_ts, end_ts_or_None, profile)] from canary log events.

    A window runs from one profile_change to the next; the last one is open
    ended. This is what gives every incident the name of the bait that was
    live when it happened -- the most interesting variable in the experiment.
    """
    changes = [e for e in canary_events if e.get("event") == "profile_change"]
    changes.sort(key=lambda e: e["ts"])
    windows = []
    for i, e in enumerate(changes):
        end = changes[i + 1]["ts"] if i + 1 < len(changes) else None
        windows.append((e["ts"], end, e.get("profile")))
    return windows


def profile_at(windows, ts):
    """Which profile was live at `ts`. None if it predates the first window.

    ponytail: linear scan. These logs are hundreds of lines, not millions;
    switch to bisect over start timestamps if that ever stops being true.
    """
    for start, end, profile in windows:
        if start <= ts and (end is None or ts < end):
            return profile
    return None


# --- correlation ------------------------------------------------------------

# The canary and the witness both report the same connection a few seconds
# apart -- one over serial, one off the air. Connects from different sources
# inside this window are treated as one incident.
CONNECT_MERGE_SECONDS = 10


def ts_seconds(ts):
    """ISO8601 -> epoch seconds. None if unparseable."""
    try:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()


def _new_incident(e, windows):
    data = e.get("data") or {}
    return {
        "start": e["ts"], "end": e["ts"],
        "profile": e.get("profile") or profile_at(windows, e["ts"]),
        "initiator": data.get("initiator"),
        "initiator_random": data.get("initiator_random"),
        "canary_peer": data.get("peer"),
        "rssi": [r for r in [data.get("rssi")] if r is not None],
        "att_ops": {}, "writes": [], "sources": {e.get("source")},
    }


def _merge_connect(inc, e):
    data = e.get("data") or {}
    for key, src in (("initiator", "initiator"), ("initiator_random", "initiator_random"),
                     ("canary_peer", "peer")):
        if inc.get(key) is None and data.get(src) is not None:
            inc[key] = data[src]
    if data.get("rssi") is not None:
        inc["rssi"].append(data["rssi"])
    inc["sources"].add(e.get("source"))
    if not inc.get("profile"):
        inc["profile"] = e.get("profile")


def incidents(canary_events, witness_events):
    """Merge both streams into incidents keyed by connection window.

    Every incident names the profile that was live when it happened -- without
    that the report says "something connected" and loses the most interesting
    variable in the experiment: which bait actually works.
    """
    windows = profile_windows(canary_events)
    events = [e for e in list(canary_events) + list(witness_events) if e.get("ts")]
    events.sort(key=lambda e: e["ts"])

    out, cur = [], None
    for e in events:
        ev = e.get("event")
        data = e.get("data") or {}
        if ev == "connect":
            gap = None
            if cur:
                a, b = ts_seconds(cur["start"]), ts_seconds(e["ts"])
                gap = None if a is None or b is None else b - a
            # Same connection seen by the other radio, or a genuinely new one?
            if (cur and e.get("source") not in cur["sources"]
                    and gap is not None and gap <= CONNECT_MERGE_SECONDS):
                _merge_connect(cur, e)
            else:
                if cur:
                    out.append(cur)
                cur = _new_incident(e, windows)
            continue
        if cur is None:
            continue
        if ev == "disconnect":
            cur["end"] = e["ts"]
            out.append(cur)
            cur = None
        elif ev == "att_op":
            name = data.get("op") or "unknown"
            cur["att_ops"][name] = cur["att_ops"].get(name, 0) + 1
            cur["end"] = e["ts"]
        elif ev == "uart_write":
            cur["writes"].append(data.get("bytes"))
            cur["end"] = e["ts"]
        elif ev == "rssi" and data.get("rssi") is not None:
            cur["rssi"].append(data["rssi"])
            cur["end"] = e["ts"]
    if cur:
        out.append(cur)

    for inc in out:
        inc["sources"] = sorted(s for s in inc["sources"] if s)
        inc["rssi_min"] = min(inc["rssi"]) if inc["rssi"] else None
        inc["rssi_max"] = max(inc["rssi"]) if inc["rssi"] else None
        inc["att_count"] = sum(inc["att_ops"].values())
        del inc["rssi"]
    return out


def scan_summary(witness_events):
    """Who scanned the bait without connecting. Counted per scanner address."""
    counts = {}
    for e in witness_events:
        if e.get("event") == "scan_req":
            addr = (e.get("data") or {}).get("scanner")
            if addr:
                counts[addr] = counts.get(addr, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])
