# BlueSentinel

**A Bluetooth LE honeypot that finds out who is probing the devices around you.**

<img src="docs/banner.jpg" alt="BlueSentinel — Bluetooth LE honeypot" width="100%">

BlueSentinel advertises a fake BLE peripheral — a smart lock, a heart rate monitor, a
lost-item tag, a keyboard — that no legitimate client has any reason to touch. A second
radio watches that device at the link layer and records everything that approaches it.

Because nothing has a legitimate reason to connect, **anything that does is unsolicited by
definition.** There is no false-positive problem to solve: every line in the log is
something that came looking.

Plug it in, leave it, read the logs later.

---

## Results

One 6.5-minute run, with a phone connecting once under each of the six disguises:

| | |
|---|---|
| Devices that scanned the bait | 12 |
| …that went on to connect | 6 |
| Distinct addresses those six used | **6** |
| ATT operations captured | 160 |
| Incidents seen by *both* radios | 6 of 6 |

```
keyboard  (1 incident)
  started                  prober                       rssi      att   seen by
  2026-08-04T01:01:27.692Z 43:5c:df:XX:XX:XX (random)   -50..-40  31    canary+witness
        14 x Read By Type Request
         4 x Error Response
```

Every ATT burst is a client enumerating the GATT table of a device it has never seen, and
every one hits `Error Response` — the bait advertises services it does not implement. The
six connections came from one phone that minted a fresh address each time: a tool treating
MACs as identity would report six attackers here.

**→ [Read the full run](docs/demo.md)** — all six incidents, the canary timeline, what each
disguise caught, and the two bugs the run exposed.

---

## Requirements

| Item | Notes |
|---|---|
| [Adafruit Bluefruit LE Friend](https://www.adafruit.com/product/2267) | the bait. Any board reporting `BLEFRIEND32` |
| [Nordic nRF52840 Dongle (PCA10059)](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle) | the witness |
| macOS or Linux | Python 3.9+, two USB ports |

Software: `pyserial`, plus `pytest` for the tests and `tshark` as an external
binary. That is the whole dependency list.

Verified on macOS 26.6 (Apple Silicon) with Bluefruit firmware 0.6.2 and 0.9.0, sniffer
firmware 4.1.1, nrfutil 8.2.0, tshark 4.6.7. **Windows is out of scope.**

---

## Install

```bash
git clone https://github.com/atahan99/BlueSentinel.git
cd BlueSentinel
python3 -m pip install -r requirements.txt
python3 -m pytest tests/ -q          # 33 tests, no hardware needed
```

That is enough to run the test suite and to replay the bundled capture. Setting up the
two radios — tshark, nrfutil, flashing the dongle, the Wireshark plugin — is a further
five steps, each with a check:

**→ [docs/installation.md](docs/installation.md)**

---

## Usage

One command. It finds both radios, starts the bait, reads the advertising address out of
the canary's own log, and points the sniffer at it — the one step you otherwise do by hand,
and the one that silently ruins a run when you get it wrong.

```bash
python3 tui.py
```

Press `s`. `q` quits and shuts both collectors down cleanly.

<img src="docs/screenshot-tui.png" alt="The BlueSentinel console: both radios detected, the live event feed, and a warning in the status line" width="100%">

*A finished 200-second run. Both radios detected by USB id, the bait address handed to the
sniffer without anyone typing it, and four disguises probed in three minutes. The status
line is carrying a real warning from the converter — see [hardware notes](docs/hardware-notes.md#1-findings-that-shaped-the-code).
Vertical whitespace cropped; nothing else altered.*

| key | |
|---|---|
| `s` | start / stop both collectors |
| `tab` | switch between the live feed and the incident report |
| `r` | rebuild the report from the capture so far |
| `w` | re-point the sniffer after an `address_changed` |
| `q` | quit |

The feed shows what the canary shows — per-poll RSSI stays in the log rather than on the
screen. The report pane re-derives incidents from the growing pcap, so ATT counts appear
while the run is still going rather than only after it stops.

### Or drive the three scripts yourself

The console is a supervisor; it adds no collection logic, and the scripts remain the
interface. Two terminals, and the canary prints the bait address on startup:

```bash
python3 canary.py                                    # terminal 1
python3 witness.py E1:84:87:02:B3:1E                 # terminal 2
python3 report.py                                    # any time
```

The canary prints each event as it happens, so you can see the thing working:

```
01:00:14  advertising_start             E1:84:87:02:B3:1E
01:01:22  profile_change  keyboard      KB-8802
01:01:28  connect         keyboard      43:5C:DF:ED:90:CB  -50 dBm
01:01:44  uart_write      keyboard      hello
01:01:53  disconnect      keyboard
```

<img src="docs/screenshot-live-run.png" alt="Three terminals: the canary logging connections, the witness capturing, and report.py refreshing" width="100%">

*The same thing before the console existed — canary bottom left, witness top right,
`report.py` on a two-second loop bottom right. Run this way the witness converts only when
it stops, which is why those incidents say `canary` and `att 0`. Prober addresses and the
local username are redacted.*

That is a view for whoever is watching. `logs/canary.jsonl` is the machine interface and
keeps everything, including the per-poll RSSI readings the terminal suppresses as noise.

For a running summary rather than a feed, re-run the report on a loop; it re-reads both
logs each time:

```bash
while true; do clear; python3 report.py; sleep 2; done
```

Both collectors stop cleanly on Ctrl-C. For a trial run, `--duration` makes them stop by
themselves:

```bash
python3 canary.py --duration 60 --dwell 20
python3 witness.py <address> --duration 50 && python3 report.py
```

`--dwell 20` cycles the disguise every 20 seconds so you see rotation in a minute instead
of waiting the 900-second default.

**No hardware?** A real capture ships with the repo:

```bash
python3 witness.py E1:84:87:02:B3:1E --convert --pcap docs/sample-capture.pcapng
python3 report.py
```

Reports come out as `--format table` (default), `json`, or `csv`.

### All flags

`canary.py` — `--dwell` seconds per profile (900) · `--poll` connection poll interval (2.0)
· `--duration` stop after N seconds (0 = forever) · `--readvertise` advertising restart
interval, used only on firmware that needs it · `--port` override discovery · `--profiles`
directory · `--log` output path

`witness.py` — `--duration` capture length (0 = until Ctrl-C) · `--convert` re-derive
events from an existing pcap · `--pcap` / `--log` paths · `--port` / `--tshark` /
`--nrfutil` overrides

`report.py` — `--format table|json|csv` · `--canary` / `--witness` log paths

`tui.py` — `--dwell` / `--duration` / `--port` passed through to the canary · `--start`
begin collecting immediately instead of on `s` · `--selfcheck` run the built-in checks and
exit

---

## The bait

The canary cycles through disguises, because different probers hunt for different things.
Six ship with it:

| Profile | Advertises as | Service |
|---|---|---|
| `smartlock` | `SmartLock-7A21` | Automation IO `0x1815` |
| `heartrate` | `HRM-0442` | Heart Rate `0x180D` |
| `tracker` | `Tag-3F19` | Immediate Alert `0x1802` + Battery — a lost-item tag |
| `keyboard` | `KB-8802` | HID `0x1812`, appearance Keyboard |
| `thermostat` | `ThermoNode-11` | Environmental Sensing `0x181A` |
| `fitness` | `FitBand-52C0` | Cycling Speed and Cadence `0x1816` + Battery |

The keyboard is the most interesting: an unpaired HID is what anything hunting for input
injection would go for.

Add your own by dropping a JSON file in `profiles/`:

```json
{
  "name": "HRM-0442",
  "advdata": "02-01-06-03-03-0d-18"
}
```

`advdata` is the raw advertising payload as dash-separated hex — here, flags plus a
16-bit service UUID list containing `0x180D`. Pick UUIDs from the Bluetooth SIG's
[assigned numbers](https://www.bluetooth.com/specifications/assigned-numbers/), and see
Adafruit's [AT command reference](https://learn.adafruit.com/introducing-adafruit-ble-bluetooth-low-energy-friend/command-mode)
for what else the bait will accept. Keep profiles generic: a plausible *category* of
device, never a clone of a real product's identifiers.

The device name rides in the **scan response**, not the advertisement. A passive scanner
sees an unnamed device offering a service; only an active scanner that sends a `SCAN_REQ`
learns the name.

---

## How it works

The bait knows *that* something connected, its signal strength, and how long it stayed.
What it cannot reliably tell you is *who* — older firmware has no command for the peer's
address at all.

The sniffer reads the initiator address straight off the air, along with the address type
and every ATT operation the prober performed inside the connection. Neither radio sees the
whole picture; together they do.

```
Bluefruit LE Friend ──USB serial──> canary.py  ──> logs/canary.jsonl  ─┐
                                                                      ├─> report.py
nRF52840 Dongle ────────nrfutil──> witness.py ──> logs/witness.jsonl ─┘
                                                        ^
                                     tui.py  ───────────┘  supervises both,
                                                           reads the same logs
```

The collectors never talk to each other. If one dies the other keeps running, and
correlation happens offline at read time. `tui.py` supervises rather than participates: it
spawns the same two scripts and reads the same files on disk, so anything it shows you can
be reproduced by running them by hand.

| Module | Does |
|---|---|
| `canary.py` | drives the bait over AT commands, rotates disguises, logs connections |
| `witness.py` | runs the sniffer following the bait's address, converts the capture to events |
| `parse.py` | pure functions: bytes and JSON in, event dicts out. No I/O |
| `report.py` | merges both logs into incidents, each attributed to the disguise that was live |
| `tui.py` | one console over the other four: finds the radios, runs the collectors, hands the bait address from one to the other, shows the feed and the report |

Transport is separated from parsing deliberately. `canary.py` and `witness.py` own the
serial port and the subprocess and are not unit-tested; everything they emit is parsed by
pure functions that are. That is what lets the test suite verify the pipeline with no
radio attached.

The pcap is the source of truth; the JSONL is derived. `witness.py --convert` regenerates
events from an existing capture, so a crash mid-run costs nothing.

Logs are one JSON object per line, shared envelope across both collectors:

```json
{"ts":"2026-08-04T00:22:53.373Z","source":"canary","event":"profile_change",
 "profile":"heartrate","data":{"name":"HRM-0442"}}
```

Events: `advertising_start`, `profile_change`, `connect`, `disconnect`, `rssi`,
`uart_write`, `att_op`, `scan_req`, `address_changed`, `serial_error`, `stopped`.

### Reading captures in Wireshark

`witness.py` writes `logs/witness.pcapng` alongside the JSONL, with full BLE dissection.

```bash
open -a Wireshark logs/witness.pcapng          # macOS
wireshark logs/witness.pcapng                  # Linux
open -a Wireshark docs/sample-capture.pcapng   # the bundled sample
```

| Filter | Shows |
|---|---|
| `btle.advertising_address == e1:84:87:02:b3:1e` | everything from your bait |
| `btle.advertising_header.pdu_type == 5` | `CONNECT_IND` — who connected |
| `btle.advertising_header.pdu_type == 3` | `SCAN_REQ` — who is looking |
| `btatt` | every ATT operation inside a connection |
| `btatt.opcode == 0x08` | Read By Type — the signature of GATT enumeration |
| `nordic_ble.crcok == 0` | corrupted frames, which the collectors drop |

Two things worth doing once. **Confirm your disguise reached the air**: select an
`ADV_IND` from the bait and expand *Advertising Data* — the service UUID there is proof,
where an `OK` from the device is not. **Look at a CRC failure**: filter
`nordic_ble.crcok == 0` and compare addresses with real ones. They sit one or two bits
away, and unfiltered they invent devices that never existed.

`docs/sample-capture.pcapng` is a real recording, trimmed twice over. Third-party
`SCAN_REQ` frames were **removed rather than obscured** — a sniffer capture of a
residential area is not ours to publish. Repeated `ADV_IND` and `SCAN_RSP` frames were
then thinned out: the bait re-advertises on three channels several times a second, so
3223 of the original 3817 packets were byte-identical repeats. Both connections, all 142
ATT operations, and enough advertising to read the profile off the air are intact. The
remaining non-bait addresses are the author's own phone, using resolvable private
addresses that have long since rotated.

---

### Going deeper

| | |
|---|---|
| [docs/demo.md](docs/demo.md) | A full run, start to finish — six disguises, six incidents, the canary timeline, and what each bait caught |
| [docs/hardware-notes.md](docs/hardware-notes.md) | Verbatim output from both devices, both firmware versions, and every quirk found by running them: the AT commands that do not exist, the sniffer's clock offset, the kernel panic |
| [docs/installation.md](docs/installation.md) | Setting up both radios, step by step, with a check after each |
| [docs/sample-capture.pcapng](docs/sample-capture.pcapng) | A real capture you can open in Wireshark or feed to `witness.py --convert` |

The hardware notes are worth a look before you buy anything: they are the record of what
these two boards actually do, as opposed to what their documentation says.

---

## Limitations

- **The bait accepts one connection at a time.** While a prober is connected it stops
  advertising, so nobody else can see it. A busy honeypot is an invisible honeypot.
- **Rotating a disguise drops any live connection**, because applying a new identity needs
  a reset. Short dwell times cut off the prober you are trying to observe.
- **A fixed address wearing different names is detectable** as a decoy by a careful
  observer. Deliberate trade for coverage.
- The Bluefruit is BLE 4.x — no extended advertising, no 2M or Coded PHY. Some modern
  probers will ignore it.
- The sniffer is passive, follows one device, and drops packets under load. Run it on a
  quiet USB bus.
- Resolvable private addresses are meaningless across sessions, and the report says so
  rather than implying identity.

There is no alerting, web UI, database, or ML anomaly detection, and none is planned.
Events land in JSONL and you read them later — the format is stable enough to bolt
anything on externally without touching the collectors.

Something not behaving? [Troubleshooting](docs/installation.md#8-troubleshooting) covers
the usual causes — a switch in the wrong position, a charge-only USB cable, an orphaned
sniffer holding the port.

---

## Notes

Run this on RF space you control. Captures will incidentally contain traffic from
neighbouring devices — treat `logs/` as sensitive, keep it out of git (it is gitignored),
and redact addresses in anything you publish. The bait must advertise as a generic fake
device, never as a clone of a real product.

Every capture, transcript and sample committed here was recorded from real hardware. There
is no synthetic data in this repository; where a fixture is trimmed or an address
redacted, a comment at the top of the file says so.
