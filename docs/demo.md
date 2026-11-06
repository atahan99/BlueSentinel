# Demo run

A live run on 2026-08-04, with the output of `report.py` as it printed then. That version
counted ATT packets in both directions under `att` and listed responses with requests; the
current report counts only the prober's operations under `att` and puts the bait's answers
in a separate `replies` column, and lists only the prober's operations underneath. The run's raw logs are not in the repository, so the output
has not been re-derived with the current code; the bundled [sample run](sample-run/) shows
the current format.

Addresses are redacted to the OUI. The prober is the author's own Galaxy S24 Ultra.

## Setup

| | |
|---|---|
| Bait | Bluefruit LE Friend, firmware 0.9.0 |
| Witness | nRF52840 Dongle PCA10059, nRF Sniffer firmware 4.1.1 |
| Host | Mac16,5 (M4 Max), macOS 26.6, Python 3.13.3, tshark 4.6.7 |
| Bait address | `E1:84:87:02:B3:1E`, random static |
| Profiles | all six, 60 s dwell each |
| Prober | Galaxy S24 Ultra running nRF Connect |
| Duration | 6.5 minutes, one full rotation |

```bash
python3 canary.py --duration 400 --dwell 60
python3 witness.py E1:84:87:02:B3:1E --duration 390
python3 report.py
```

At the time the logs went to a flat `logs/`. Today the same three commands write into a
new `logs/<run>/` folder, which the witness and the report find through `logs/latest`.

Collected: 8127 witness events (7961 `SCAN_REQ`, 6 `CONNECT_IND`, 160 ATT packets in both
directions) and 54 canary events across 7 profile windows and 6 connections. The phone
connected once under each disguise and browsed the GATT table each time.

## Canary timeline

```
00:59:16  profile_change fitness    FitBand-52C0
01:00:01  connect        fitness    7F:53:4E:XX:XX:XX
01:00:07  disconnect     fitness    
01:00:19  profile_change heartrate  HRM-0442
01:00:22  connect        heartrate  5A:5F:08:XX:XX:XX
01:00:53  disconnect     heartrate  
01:01:22  profile_change keyboard   KB-8802
01:01:28  connect        keyboard   43:5C:DF:XX:XX:XX
01:01:53  disconnect     keyboard   
01:02:26  profile_change smartlock  SmartLock-7A21
01:02:32  connect        smartlock  67:0C:D9:XX:XX:XX
01:02:44  disconnect     smartlock  
01:03:29  profile_change thermostat ThermoNode-11
01:04:02  connect        thermostat 66:D7:3A:XX:XX:XX
01:04:21  disconnect     thermostat 
01:04:32  profile_change tracker    Tag-3F19
01:04:44  connect        tracker    54:B0:61:XX:XX:XX
01:05:12  disconnect     tracker    
01:05:35  profile_change fitness    FitBand-52C0
```

## Report

```
fitness  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T00:59:59.172Z 7f:53:4e:XX:XX:XX (random)   -59..-52  5     canary+witness
         2 x Read By Type Response
         1 x Read By Type Request
         1 x Read By Group Type Response
         1 x Exchange MTU Request

heartrate  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:00:20.891Z 5a:5f:08:XX:XX:XX (random)   -47..-44  30    canary+witness
         9 x Read By Type Request
         7 x Read By Type Response
         5 x Error Response
         4 x Read By Group Type Response
         4 x Find Information Request
         1 x Find Information Response

keyboard  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:01:27.692Z 43:5c:df:XX:XX:XX (random)   -50..-40  31    canary+witness
        14 x Read By Type Request
         4 x Read By Type Response
         4 x Read By Group Type Response
         4 x Error Response
         4 x Find Information Request
         1 x Find Information Response

smartlock  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:02:31.623Z 67:0c:d9:XX:XX:XX (random)   -49..-31  32    canary+witness
        10 x Read By Type Request
         8 x Read By Type Response
         6 x Error Response
         4 x Read By Group Type Response
         3 x Find Information Response
         1 x Find Information Request

thermostat  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:04:02.212Z 66:d7:3a:XX:XX:XX (random)   -46..-31  31    canary+witness
        11 x Read By Type Response
        10 x Error Response
         4 x Read By Group Type Response
         3 x Find Information Request
         2 x Find Information Response
         1 x Read By Type Request

tracker  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:04:41.818Z 54:b0:61:XX:XX:XX (random)   -55..-33  31    canary+witness
         9 x Error Response
         8 x Read By Type Request
         6 x Read By Type Response
         4 x Read By Group Type Response
         3 x Find Information Response
         1 x Find Information Request

scanned but did not connect
  4f:21:af:XX:XX:XX        1209 SCAN_REQ
  6f:92:ed:XX:XX:XX        584 SCAN_REQ
  7c:d4:fa:XX:XX:XX        457 SCAN_REQ
  42:a9:7c:XX:XX:XX        162 SCAN_REQ
  76:61:20:XX:XX:XX        128 SCAN_REQ
  67:53:8c:XX:XX:XX        27 SCAN_REQ

Note: addresses marked (random) are resolvable private addresses.
They rotate, and do not identify a device across sessions.
```

## What this shows

Six connections under six disguises produced one incident each, every one filed under the
bait that was live at that moment.

All six incidents are marked `canary+witness`: reported independently over USB serial and
off the air, then merged by matching connection windows. The canary contributed connection
state, RSSI range and the peer address; the witness contributed the `CONNECT_IND`, the
address type, and every ATT operation. Cross-checked afterwards, the two radios'
timestamps agreed to within 0.4 to 2.8 seconds and the addresses matched in all six.

The BD_ADDR never moved. Seven profile changes, each with an `ATZ` reset, produced no
`address_changed` event, and the witness followed one address for the whole session.

Android used a fresh resolvable private address for each of the six connections from the
one phone. Treating MACs as identity would report six separate attackers; the report marks
them `(random)` instead.

Twelve devices scanned the bait and six of them connected. The six listed under `scanned
but did not connect` sent scan requests but never opened a connection. This is ambient
traffic: every actively scanning phone asks every advertiser in range for its scan
response, and on 2026-11-06 four neighbouring devices sent 1,741 of them in a 4-minute run
in which nothing targeted the bait. Scans show who was around; connections are what to
look at.

Every ATT burst is a GATT enumeration, and every one gets an `Error Response`. The bait
advertises services it does not implement, so reads against the expected handles are
rejected, and a patient prober would learn the device is not what it claims.

The keyboard drew the heaviest enumeration: 14 `Read By Type Request` against a device
advertising as an unpaired HID, more than any other disguise. One run shows no trend, but
this is the comparison the profile column is for.

## What this run caught

Two defects, visible only when the two radios' logs were compared: the sniffer's pcap
clock offset, and a first correction for it that assumed drift rather than offset. Both
are written up in [hardware-notes.md](hardware-notes.md) §1.
