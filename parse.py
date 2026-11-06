"""Pure functions over collector output. No I/O, no globals, so CI tests it all.

Shapes follow what the real firmware returns; see docs/hardware-notes.md §2.
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
    """Just the OK/ERROR/None terminator, for commands where only success matters."""
    return at_reply("", raw)[1]


def _first(cmd, raw):
    values, status = at_reply(cmd, raw)
    return values[0] if status == "OK" and values else None


def conn_state(raw):
    """True if AT+GAPGETCONN reports a live connection."""
    return _first("AT+GAPGETCONN", raw) == "1"


def rssi(raw):
    """Peer RSSI in dBm, or None. 0 means "not connected", not 0 dBm (§2)."""
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
    """Connected peer's address, or None. ERROR on 0.6.2, where naming the
    prober is entirely the witness's job (§2)."""
    return _first("AT+BLEGETPEERADDR", raw)


def gap_intervals(raw):
    """AT+GAPINTERVALS as a list of ints: min conn, max conn, adv interval, adv
    timeout, and on 0.9.0 only a fifth, supervision timeout (§1)."""
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
    Read it back: both firmwares answer OK even when the write was refused (§1).
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
# ek doubles the layer prefix ("btle_btle_advertising_address") and that prefix is
# version-dependent, so fields are looked up by suffix, not exact key.

PDU_TYPES = {
    0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
    4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND",
}

# Named because "Read By Group Type Request" says someone is enumerating the
# GATT table and "16" does not. Even opcodes come from the client, odd from us.
ATT_OPCODES = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response",
    0x04: "Find Information Request", 0x05: "Find Information Response",
    0x06: "Find By Type Value Request", 0x07: "Find By Type Value Response",
    0x08: "Read By Type Request", 0x09: "Read By Type Response",
    0x0A: "Read Request", 0x0B: "Read Response",
    0x0C: "Read Blob Request", 0x0D: "Read Blob Response",
    0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response",
    0x12: "Write Request", 0x13: "Write Response",
    0x16: "Prepare Write Request", 0x17: "Prepare Write Response",
    0x18: "Execute Write Request", 0x19: "Execute Write Response",
    0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x52: "Write Command",
}


def att_dir(opcode):
    """"prober" for requests/commands/confirmations (even), "bait" for responses,
    errors, notifications and indications (odd). Unknown counts as prober."""
    return "bait" if opcode is not None and opcode % 2 else "prober"


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
    """Like field(), but coerced to int: ek emits numbers as JSON strings (§1)."""
    v = field(layers, suffix)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def ek_records(lines):
    """Yield the packet records from `tshark -T ek` output, skipping ek's bare
    {"index":...} lines and our fixtures' '#' provenance headers."""
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        if "layers" in rec:
            yield rec


def witness_event(rec, bait_addr):
    """Map one ek record to a log event, or None if it is not about the bait.
    The sniffer hears the whole neighbourhood; dropping the rest keeps the log
    all-signal."""
    layers = rec.get("layers", {})

    # CRC failures invent phantom devices one bit off a real address (§1).
    if field(layers, "nordic_ble_crcok") is False:
        return None

    data = {
        "rssi": ifield(layers, "nordic_ble_rssi"),
        "channel": ifield(layers, "nordic_ble_channel"),
    }

    # ATT is not address-filtered: connection packets carry no addresses, and
    # the sniffer follows the bait, so they are ours by construction (§1).
    if any(k.startswith("btatt") for k in layers):
        opcode = ifield(layers, "btatt_opcode")
        data["pdu"] = "ATT"
        data["opcode"] = opcode
        data["dir"] = att_dir(opcode)
        data["op"] = ATT_OPCODES.get(opcode, "0x%02x" % opcode if opcode else None)
        data["handle"] = field(layers, "btatt_handle")
        data["value"] = field(layers, "btatt_value")
        return dict(event="att_op", data=data)

    adv, initiator, scanning = (_addr(field(layers, "btle_%s_address" % k))
                                for k in ("advertising", "initiator", "scanning"))
    if bait_addr.lower() not in (adv, initiator, scanning):
        return None

    pdu = PDU_TYPES.get(ifield(layers, "advertising_header_pdu_type"))
    data["pdu"] = pdu

    if pdu == "SCAN_REQ":
        data["scanner"] = scanning
        return dict(event="scan_req", data=data)
    if pdu == "CONNECT_IND":
        data["initiator"] = initiator
        # randomized_tx: random (rotating) vs public -- whether the MAC means anything.
        data["initiator_random"] = field(layers, "advertising_header_randomized_tx")
        return dict(event="connect", data=data)
    return None  # plain advertising from our own bait is not an incident


def ek_epoch(rec):
    """Epoch seconds from an ek record (epoch ms as a string), or None."""
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

    One offset, no rescaling: the rate is right. Anchor on the last frame in
    *file order* (never max(), never mtime) against the recorded capture end.
    See docs/hardware-notes.md §1 (clock offset, two frame streams).
    """
    if last_frame is None or capture_end is None:
        return 0.0
    return capture_end - last_frame


# Fields worth showing on a terminal; a view, not a filter -- the log keeps all.
DETAIL = ("name", "address", "peer", "initiator", "scanner", "rssi", "op",
          "bytes", "before", "after", "error", "reason", "status")


def format_event(rec):
    """One human-readable line for a log record. Unknown event
    types render fine rather than needing a branch each.

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
    """[(start_ts, end_ts_or_None, profile)], one per profile_change; the last
    is open ended. This is what names the bait live at each incident."""
    changes = [e for e in canary_events if e.get("event") == "profile_change"]
    changes.sort(key=lambda e: e["ts"])
    windows = []
    for i, e in enumerate(changes):
        end = changes[i + 1]["ts"] if i + 1 < len(changes) else None
        windows.append((e["ts"], end, e.get("profile")))
    return windows


def profile_at(windows, ts):
    """Which profile was live at `ts`. None if it predates the first window.
    Linear scan; logs are small."""
    for start, end, profile in windows:
        if start <= ts and (end is None or ts < end):
            return profile
    return None


# --- correlation ------------------------------------------------------------

# Both radios report one connection a few seconds apart; connects from
# different sources inside this window are one incident.
CONNECT_MERGE_SECONDS = 10


def ts_seconds(ts):
    """ISO8601 -> epoch seconds. None if unparseable."""
    try:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()


def _addr(v):
    return v.lower() if isinstance(v, str) else v


def _new_incident(e, windows):
    data = e.get("data") or {}
    return {
        "start": e["ts"], "end": e["ts"],
        "profile": e.get("profile") or profile_at(windows, e["ts"]),
        "initiator": _addr(data.get("initiator")),
        "initiator_random": data.get("initiator_random"),
        "canary_peer": _addr(data.get("peer")),
        "rssi": [r for r in [data.get("rssi")] if r is not None],
        "att_ops": {}, "att_replies": 0, "writes": [], "sources": {e.get("source")},
    }


def _merge_connect(inc, e):
    data = e.get("data") or {}
    for key, src in (("initiator", "initiator"), ("initiator_random", "initiator_random"),
                     ("canary_peer", "peer")):
        if inc.get(key) is None and data.get(src) is not None:
            inc[key] = _addr(data[src])
    if data.get("rssi") is not None:
        inc["rssi"].append(data["rssi"])
    inc["sources"].add(e.get("source"))
    if not inc.get("profile"):
        inc["profile"] = e.get("profile")


def incidents(canary_events, witness_events):
    """Merge both streams into incidents, each naming the profile that was live:
    which bait actually works is the point of the experiment."""
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
            # Only the prober's ops measure interest; our replies just echo them.
            if (data.get("dir") or att_dir(data.get("opcode"))) == "bait":
                cur["att_replies"] += 1
            else:
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
    """Who scanned the bait, as [(address, SCAN_REQ count)], busiest first.
    Events may be pre-aggregated with data.count; older logs default to 1."""
    counts = {}
    for e in witness_events:
        if e.get("event") == "scan_req":
            data = e.get("data") or {}
            addr = _addr(data.get("scanner"))
            if addr:
                counts[addr] = counts.get(addr, 0) + data.get("count", 1)
    return sorted(counts.items(), key=lambda kv: -kv[1])
