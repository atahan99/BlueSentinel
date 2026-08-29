"""Fixture-driven tests. No hardware, no network -- this is what CI runs.

Every fixture in tests/fixtures/ came off real hardware on 2026-08-04; see the
provenance header inside each file and docs/hardware-notes.md. Nothing here is
synthesised, which is the point: these tests fail if the parsers stop matching
what the actual devices emit.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parse

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BAIT = "e1:84:87:02:b3:1e"


def replies(fw):
    """Split a recorded probe transcript back into {command: raw reply}.

    Both firmwares are kept as fixtures. The parsers must handle the device as
    shipped (0.6.2, 2015) and as upgraded (0.9.0, 2025) -- the AT command set
    differs substantially between them.
    """
    with open(os.path.join(FIXTURES, "at_session_%s.txt" % fw)) as fh:
        text = fh.read()
    out, cmd, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("$ "):
            if cmd:
                out[cmd] = "\n".join(buf)
            cmd, buf = line[2:].strip(), []
        elif cmd is not None and not line.startswith("#"):
            buf.append(line)
    if cmd:
        out[cmd] = "\n".join(buf)
    return out


# --- canary / AT ------------------------------------------------------------

def test_device_info_both_firmwares():
    for fw, built in (("0.6.2", "Apr 30 2015"), ("0.9.0", "Dec 18 2025")):
        info = parse.device_info(replies(fw)["ATI"])
        assert info["model"] == "BLEFRIEND32"
        assert info["firmware"] == fw
        assert info["built"] == built
        assert info["softdevice"] == "S110 8.0.0, 0.2"


def test_address_survived_the_firmware_upgrade():
    """BD_ADDR is fixed in the chip. If this ever changes, the witness has been
    following the wrong device and every incident since is misattributed."""
    for fw in ("0.6.2", "0.9.0"):
        values, status = parse.at_reply("AT+BLEGETADDR", replies(fw)["AT+BLEGETADDR"])
        assert status == "OK"
        assert values[0].lower() == BAIT
        assert parse.at_reply("AT+BLEGETADDRTYPE",
                              replies(fw)["AT+BLEGETADDRTYPE"])[0] == ["1"]


def test_commands_absent_on_0_6_2():
    """Both exist on 0.9.0 but not on the shipped firmware. ERROR is a valid
    answer, not a parse failure -- the collector must keep going."""
    r = replies("0.6.2")
    for cmd in ("AT+GAPGETADDR", "AT+MODESWITCHEN"):
        assert parse.at_reply(cmd, r[cmd]) == ([], "ERROR")
    assert "AT+BLEGETPEERADDR" not in r, "0.6.2 has no peer-address command"


def test_0_9_0_reports_the_peer_address():
    """The capability that did not exist on 0.6.2: the canary naming the
    prober itself instead of leaving it entirely to the witness."""
    r = replies("0.9.0")
    assert parse.conn_state(r["AT+GAPGETCONN"]) is True
    assert parse.rssi(r["AT+BLEGETRSSI"]) == -44
    assert parse.peer_addr(r["AT+BLEGETPEERADDR"]) == "7C:9C:4C:FF:FF:FF"


def test_advertising_timeout_differs_by_firmware():
    """0.6.2 caps at 180s and silently refuses 0, so the bait goes dark and
    needs a keepalive. 0.9.0 accepts 0 (never stop) and does not."""
    assert parse.adv_timeout(replies("0.6.2")["AT+GAPINTERVALS"]) == 180
    assert parse.adv_timeout(replies("0.9.0")["AT+GAPINTERVALS"]) == 0


def test_gap_intervals_field_count_varies():
    assert len(parse.gap_intervals(replies("0.6.2")["AT+GAPINTERVALS"])) == 4
    assert len(parse.gap_intervals(replies("0.9.0")["AT+GAPINTERVALS"])) == 5


def test_not_connected_state_0_6_2():
    r = replies("0.6.2")
    assert parse.conn_state(r["AT+GAPGETCONN"]) is False
    assert parse.rssi(r["AT+BLEGETRSSI"]) is None, "0 dBm means not connected"
    assert parse.uart_rx(r["AT+BLEUARTRX"]) is None


def test_timeout_is_not_success():
    assert parse.at_reply("AT+X", "AT+X\r\n") == ([], None)


def test_rssi_real_value():
    assert parse.rssi("AT+BLEGETRSSI\r\n-67\r\nOK\r\n") == -67


# --- witness / tshark ek ----------------------------------------------------

def ek_records():
    with open(os.path.join(FIXTURES, "witness_adv.ek.jsonl")) as fh:
        return list(parse.ek_records(fh))


def test_ek_fixture_parses():
    recs = ek_records()
    assert recs, "fixture yielded no records"
    assert all("layers" in r for r in recs)


def test_bait_advertising_recognised():
    """The recorded frames are our own bait advertising -- correctly not an
    incident, but the fields must still resolve or the filter is meaningless."""
    layers = ek_records()[0]["layers"]
    assert parse.field(layers, "btle_advertising_address").lower() == BAIT
    assert parse.PDU_TYPES[parse.ifield(layers, "advertising_header_pdu_type")] == "ADV_IND"
    assert parse.field(layers, "nordic_ble_rssi") is not None
    assert parse.witness_event(ek_records()[0], BAIT) is None


def test_heartrate_profile_was_on_air():
    """0x180D == 6157. Proves the profile the canary applied actually reached
    the air, not just that the AT command returned OK."""
    assert parse.ifield(ek_records()[0]["layers"], "eir_ad_entry_uuid_16") == 6157


def test_traffic_from_other_devices_is_dropped():
    assert parse.witness_event(ek_records()[0], "aa:bb:cc:dd:ee:ff") is None


def test_field_lookup_is_prefix_independent():
    layers = {"btle": {"btle_btle_advertising_address": "ab:cd"}}
    assert parse.field(layers, "btle_advertising_address") == "ab:cd"
    assert parse.field(layers, "nope") is None


# --- correlation ------------------------------------------------------------

def test_profile_attribution():
    events = [
        {"ts": "2026-08-04T00:00:00.000Z", "event": "profile_change", "profile": "smartlock"},
        {"ts": "2026-08-04T00:15:00.000Z", "event": "profile_change", "profile": "heartrate"},
    ]
    w = parse.profile_windows(events)
    assert parse.profile_at(w, "2026-08-04T00:07:00.000Z") == "smartlock"
    assert parse.profile_at(w, "2026-08-04T00:15:00.000Z") == "heartrate"
    assert parse.profile_at(w, "2026-08-04T23:00:00.000Z") == "heartrate"
    assert parse.profile_at(w, "2026-08-03T23:59:00.000Z") is None


def test_profile_windows_sorts_out_of_order_input():
    events = [
        {"ts": "2026-08-04T00:15:00.000Z", "event": "profile_change", "profile": "b"},
        {"ts": "2026-08-04T00:00:00.000Z", "event": "profile_change", "profile": "a"},
        {"ts": "2026-08-04T00:05:00.000Z", "event": "connect", "profile": "a"},
    ]
    assert [p for _, _, p in parse.profile_windows(events)] == ["a", "b"]


def test_incidents_from_the_real_demo_capture():
    """End-to-end correlation over the recorded S24 connection: a CONNECT_IND
    plus the ATT operations that followed it become one attributed incident."""
    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        witness = []
        for rec in parse.ek_records(fh):
            ev = parse.witness_event(rec, BAIT)
            if ev:
                witness.append({"ts": parse.iso(parse.ek_epoch(rec)), "source": "witness",
                                "event": ev["event"], "data": ev["data"]})
    canary = [{"ts": "2026-08-03T21:00:00.000Z", "source": "canary",
               "event": "profile_change", "profile": "heartrate", "data": {}}]

    incs = parse.incidents(canary, witness)
    assert len(incs) == 1, "one connection should produce one incident"
    inc = incs[0]
    assert inc["profile"] == "heartrate", "incident must name the live bait"
    assert inc["initiator"] == "77:18:1c:ff:ff:ff"
    assert inc["initiator_random"] is True
    assert inc["att_count"] > 0
    assert "Read By Type Request" in inc["att_ops"], "GATT enumeration is the fingerprint"
    assert inc["rssi_min"] is not None


def test_att_opcodes_are_named():
    assert parse.ATT_OPCODES[0x08] == "Read By Type Request"
    assert parse.ATT_OPCODES[0x01] == "Error Response"


def test_witness_timestamps_match_the_canary_envelope():
    """Witness timestamps must be comparable with canary ones or profile
    attribution silently yields nothing."""
    ts = parse.iso(parse.ek_epoch({"timestamp": "1785793021316"}))
    assert ts.endswith("Z") and ts.count(":") == 2
    assert parse.ts_seconds(ts) == 1785793021.316


def test_two_radios_reporting_one_connection_merge():
    canary = [
        {"ts": "2026-08-04T00:00:00.000Z", "source": "canary",
         "event": "profile_change", "profile": "smartlock", "data": {}},
        {"ts": "2026-08-04T00:01:00.000Z", "source": "canary", "event": "connect",
         "data": {"rssi": -44, "peer": "aa:bb:cc:dd:ee:ff"}},
    ]
    witness = [{"ts": "2026-08-04T00:01:03.000Z", "source": "witness",
                "event": "connect", "data": {"initiator": "11:22:33:44:55:66",
                                             "initiator_random": True, "rssi": -33}}]
    incs = parse.incidents(canary, witness)
    assert len(incs) == 1, "same connection seen twice is one incident"
    assert incs[0]["sources"] == ["canary", "witness"]
    assert incs[0]["canary_peer"] == "aa:bb:cc:dd:ee:ff"
    assert incs[0]["initiator"] == "11:22:33:44:55:66"
    assert incs[0]["profile"] == "smartlock"


def test_distant_connects_are_separate_incidents():
    canary = [{"ts": "2026-08-04T00:00:00.000Z", "source": "canary",
               "event": "profile_change", "profile": "smartlock", "data": {}}]
    witness = [
        {"ts": "2026-08-04T00:01:00.000Z", "source": "witness", "event": "connect",
         "data": {"initiator": "11:22:33:44:55:66"}},
        {"ts": "2026-08-04T00:09:00.000Z", "source": "witness", "event": "connect",
         "data": {"initiator": "aa:aa:aa:aa:aa:aa"}},
    ]
    assert len(parse.incidents(canary, witness)) == 2


def test_scan_summary_ranks_by_volume():
    witness = [{"event": "scan_req", "data": {"scanner": "a"}}] * 3 + \
              [{"event": "scan_req", "data": {"scanner": "b"}}]
    assert parse.scan_summary(witness) == [("a", 3), ("b", 1)]


def test_crc_failures_are_dropped():
    """The sniffer hands over packets that failed CRC. A single flipped bit in
    an address invents a device that never existed -- observed live as phantom
    scanners one bit away from real addresses, including the bait itself."""
    good = {"layers": {"nordic_ble": {"nordic_ble_nordic_ble_crcok": True,
                                      "nordic_ble_nordic_ble_rssi": "-40"},
                       "btle": {"btle_btle_advertising_address": BAIT,
                                "btle_btle_advertising_header_pdu_type": "3",
                                "btle_btle_scanning_address": "aa:bb:cc:dd:ee:ff"}}}
    assert parse.witness_event(good, BAIT)["event"] == "scan_req"

    bad = json.loads(json.dumps(good))
    bad["layers"]["nordic_ble"]["nordic_ble_nordic_ble_crcok"] = False
    assert parse.witness_event(bad, BAIT) is None


def test_real_capture_has_no_bait_as_scanner():
    """The bait cannot scan itself. If it appears as a scanner the CRC filter
    has stopped working."""
    with open(os.path.join(FIXTURES, "witness_adv.ek.jsonl")) as fh:
        for rec in parse.ek_records(fh):
            ev = parse.witness_event(rec, BAIT)
            if ev and ev["event"] == "scan_req":
                assert ev["data"]["scanner"].lower() != BAIT


def test_clock_offset_corrects_sniffer_timestamps():
    """The nRF sniffer's pcap clock sits at a constant offset -- 71 minutes in
    one measured run. Uncorrected, every witness event lands outside its true
    profile window and attribution silently credits the wrong bait."""
    last_frame, capture_end = 1000.0 + 4293.0, 1000.0
    off = parse.clock_offset(last_frame, capture_end)
    assert off == -4293.0
    assert last_frame + off == capture_end


def test_clock_offset_is_harmless_on_a_healthy_clock():
    assert parse.clock_offset(500.0, 500.0) == 0.0
    assert parse.clock_offset(None, 500.0) == 0.0
    assert parse.clock_offset(500.0, None) == 0.0


def test_iso_round_trips_through_ts_seconds():
    assert parse.ts_seconds(parse.iso(1785793021.316)) == 1785793021.316


def test_format_event_is_readable():
    line = parse.format_event({"ts": "2026-08-04T01:01:28.817Z", "event": "connect",
                               "profile": "keyboard",
                               "data": {"rssi": -50, "peer": "43:5C:DF:ED:90:CB"}})
    assert line.startswith("01:01:28  connect")
    assert "keyboard" in line and "-50 dBm" in line and "43:5C:DF:ED:90:CB" in line


def test_format_event_handles_unknown_events():
    """New event types must render rather than needing a branch each."""
    line = parse.format_event({"ts": "2026-08-04T01:01:28.817Z",
                               "event": "something_new", "data": {"whatever": 1}})
    assert "01:01:28" in line and "something_new" in line


def test_format_event_survives_a_bare_record():
    """A malformed record must not crash a running collector."""
    assert parse.format_event({}).split() == ["--:--:--", "-"]


def test_clock_anchor_ignores_a_forward_clock_jump(tmp_path):
    """A single glitched frame must not drag the whole capture off the clock.

    Regression from the 2026-08-29 demo run: convert() anchored on
    max(timestamp), and exactly one frame in 43352 came back stamped 272s in
    the future. That moved every witness event 10s, pushing both radios more
    than CONNECT_MERGE_SECONDS apart, and the report split all four incidents
    into a canary-only half holding the RSSI and a witness-only half holding
    the ATT ops. Nothing errored; the incident count simply doubled.

    Real fixture frames, with only the timestamps rewritten -- the jump is the
    one thing being modelled. A stub stands in for tshark so this stays offline.
    """
    import witness

    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        frames = [l for l in fh if l.strip().startswith("{") and "layers" in l][:3]
    assert len(frames) == 3

    def restamp(line, ms):
        rec = json.loads(line)
        rec["timestamp"] = str(ms)
        return json.dumps(rec)

    # Middle frame is the glitch: 272s ahead, and not the last frame in the file.
    stream = "\n".join([restamp(frames[0], 1_000_000),
                        restamp(frames[1], 1_272_000),
                        restamp(frames[2], 1_004_000)]) + "\n"
    (tmp_path / "stream.ek").write_text(stream)

    shim = tmp_path / "fake_tshark"
    shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "stream.ek"))
    shim.chmod(0o755)

    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"")
    (tmp_path / "c.pcapng.end").write_text("1005.0\n")  # stopped 1s after t=1004

    out = tmp_path / "w.jsonl"
    n = witness.convert(str(shim), str(pcap), BAIT, str(out))
    assert n == 3, "fixture frames should all be about the bait"

    stamps = [parse.ts_seconds(json.loads(l)["ts"])
              for l in out.read_text().splitlines()]
    # Anchored on the last frame (1004) the offset is +1.0s. Anchored on the
    # glitch (1272) it would be -267s, and every stamp would be wrong by that.
    assert abs(stamps[0] - 1001.0) < 0.01, "glitched frame must not set the anchor"
    assert abs(stamps[2] - 1005.0) < 0.01


def test_capture_drops_the_previous_runs_clock_anchor(tmp_path):
    """The last run's anchor must be gone *while* the next capture runs.

    Regression: the .end file is only meaningful for the capture it was written
    beside, but it outlived its pcap. Converting a still-growing capture -- how
    the console renders a live report -- then corrected fresh frames against
    the previous run's end time. Measured at 35 minutes off, which put every
    incident outside its profile window, filed them all under "unattributed",
    and stopped the two radios merging. Nothing errored.

    Checked mid-capture on purpose: capture() rewrites .end on the way out, so
    afterwards the file looks correct whether or not the stale one was cleared.

    A stub stands in for nrfutil so this stays hardware-free.
    """
    import threading
    import witness

    pcap = tmp_path / "w.pcapng"
    (tmp_path / "w.pcapng.end").write_text("1000.0\n")  # anchor from a dead run
    assert witness.capture_end(str(pcap)) == 1000.0

    nrfutil = tmp_path / "fake_nrfutil"
    nrfutil.write_text("#!/bin/sh\nsleep 2\n")
    nrfutil.chmod(0o755)

    seen = []
    t = threading.Thread(target=witness.capture,
                         args=(str(nrfutil), "/dev/null", BAIT.upper(), str(pcap)),
                         kwargs={"duration": 1.0})
    t.start()
    for _ in range(40):                       # inside the capture window
        time.sleep(0.025)
        if t.is_alive():
            seen.append(witness.capture_end(str(pcap)))
    t.join(timeout=20)
    assert not t.is_alive()

    assert seen, "should have sampled during the capture"
    assert set(seen) == {None}, "stale anchor was readable mid-capture: %r" % (
        sorted(s for s in set(seen) if s is not None),)
    # capture() still writes a fresh, valid anchor once it really is done.
    assert witness.capture_end(str(pcap)) > 1000.0


def test_convert_warns_when_a_capture_is_not_monotonic(tmp_path, capsys):
    """Two streams in one pcap must be reported, not silently correlated.

    A `tshark -D` status poll ran the nRF extcap shim against the dongle every
    three seconds while nrfutil was capturing from it, and the pcap came out
    holding two entire captures of the same session -- the second of them
    advertising-only. The file opens fine and every frame in it is valid; only
    the seam between the streams gives it away, and clock_offset reads that
    seam as a multi-minute clock jump, after which no incident merges.
    """
    import witness

    with open(os.path.join(FIXTURES, "witness_connect.ek.jsonl")) as fh:
        frames = [l for l in fh if l.strip().startswith("{") and "layers" in l][:3]

    def restamp(line, ms):
        rec = json.loads(line)
        rec["timestamp"] = str(ms)
        return json.dumps(rec)

    shim = tmp_path / "fake_tshark"
    shim.chmod(0o755) if shim.exists() else None
    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"")

    def run(stamps):
        (tmp_path / "s.ek").write_text(
            "\n".join(restamp(f, ms) for f, ms in zip(frames, stamps)) + "\n")
        shim.write_text("#!/bin/sh\nexec cat %s\n" % (tmp_path / "s.ek"))
        shim.chmod(0o755)
        witness.convert(str(shim), str(pcap), BAIT, str(tmp_path / "o.jsonl"))
        return capsys.readouterr().err

    assert "not monotonic" not in run([1_000_000, 1_001_000, 1_002_000])
    err = run([1_000_000, 1_272_000, 1_004_000])   # time steps backwards once
    assert "not monotonic" in err, err
    assert "1 backward time step" in err, err
