# Hardware notes

What the two boards do in practice, where that differs from their documentation. Every
block below is verbatim output from a real command, failures included.

Host: Mac16,5 (M4 Max), macOS 26.6 (25G72), Darwin 25.6.0 arm64, Python 3.13.3.
Date: 2026-08-04, later findings dated inline (latest 2026-11-06). Third-party addresses
are redacted; the bait's own is kept because the witness is configured with it.

## Current state

| | Bait | Witness |
|---|---|---|
| Board | Bluefruit LE Friend, nRF51822 | nRF52840 Dongle, PCA10059 |
| Firmware | **0.9.0** (Dec 18 2025), SoftDevice S110 8.0.0 | nRF Sniffer 4.1.1 |
| Port | `/dev/cu.usbserial-2130` (CP2102N, `0x10C4`/`0xEA60`) | `/dev/tty.usbmodem21401` |
| Address | `E1:84:87:02:B3:1E`, random static | n/a |

The bait shipped with **0.6.2** (Apr 2015) and was upgraded (§5). The parsers are tested
against fixtures from both firmwares, so 0.6.2 behaviour is documented wherever the code
still accommodates it.

---

## 1. Findings that shaped the code

Each of these changed how a collector is written, and each would silently break a
reimplementation.

### The bait

- **`AT+GAPGETADDR` does not exist.** The command is `AT+BLEGETADDR`.
- **BD_ADDR is fixed in the chip.** Unchanged across host reboots, power cycles, the
  firmware upgrade and every profile rotation; `address_changed` has never fired. The
  witness can follow one address while the identity above it changes.
- **`AT+GAPAUTOADV` is `1`**, so the device is already advertising after `ATZ` and a bare
  `AT+GAPSTARTADV` returns `ERROR`. The collector stops before starting, so an `ERROR` in
  the log means something real.
- **0.6.2 caps the advertising timeout at 180 s and silently rejects `0`** while answering
  `OK`. 0.9.0 accepts `0`. Neither status reply shows whether the write took, so
  `canary.py` reads the value back and arms its keepalive only if the firmware refused.
- **`AT+GAPINTERVALS` returns 4 fields on 0.6.2 and 5 on 0.9.0**: min and max connection
  interval, advertising interval, advertising timeout, and on 0.9.0 the supervision
  timeout. Check the length before indexing.
- **`AT+GAPDEVNAME` takes effect only after `ATZ`**, so a profile is applied as name,
  reset, then advertising payload. A payload set before the reset is discarded.
- **Open `/dev/cu.*` on macOS, not `/dev/tty.*`.** The `tty` node blocks on carrier
  detect; pyserial's port listing returns the `cu` node, which is why the port is
  discovered rather than typed. The nRF51 drops bytes sent immediately after the port
  opens, so the canary waits 0.5 s before its first command.
- **A peer's UART bytes can end the AT reply that carries them.** `AT+BLEUARTRX` returns
  the buffered bytes followed by `OK`. A prober writing `hi\nOK\nsecret` produced a reply
  whose first `OK` was the prober's; a reader that stopped there logged `hi` and lost
  `secret`. The canary reads until the line has been silent for 0.5 s, so the last `OK` is
  the terminator.
- **Rotation drops any live connection.** `disconnect` fires ~29 ms after
  `profile_change`, because applying an identity requires `ATZ`. Too short a dwell time
  cuts off the prober being observed.
- **One connection at a time.** S110 is peripheral-only with a single link, and the bait
  stops advertising entirely while a peer is connected.
- **Keep one serial session open across rotations.** Opening the CP2102N port asserts DTR,
  which resets the nRF51. A harness that reconnected per `apply_profile` made the
  advertised payload lag exactly one profile behind while every AT command still answered
  `OK`. `canary.py` holds a single session.
- **An `OK` from `AT+GAPSETADVDATA` proves only that the command parsed.** All six shipped
  profiles were verified off the radio, each advertising its own service UUID during its
  own dwell window: `smartlock` `0x1815`, `heartrate` `0x180D`, `tracker`
  `0x1802`+`0x180F`, `keyboard` `0x1812` (appearance Keyboard), `thermostat` `0x181A`,
  `fitness` `0x1816`+`0x180F`.
- **On 0.6.2 a prober could in principle reach the AT parser.** `+++`, the mode-switch
  escape, is in the command set and 0.6.2 has no `AT+MODESWITCHEN`, so a peer writing to
  the UART characteristic might issue `AT+FACTORYRESET`. Never tested; the expectation is
  that UART RX buffers for `AT+BLEUARTRX` instead. On 0.9.0 `canary.py` issues
  `AT+MODESWITCHEN=0` at every session start and logs `modeswitch_disabled`.

### The sniffer

- **The extcap plugin cannot follow an address from the command line** (§4).
  `nrfutil ble-sniffer sniff --follow` can, so `witness.py` uses it.
- **`--follow` captures connection-phase packets**: real `CONNECT_IND` plus ATT. Extcap
  default mode captured 7 packets in 25 s where `nrfutil --follow` captured 6163 in 40 s
  on the same radio.
- **Connection-phase packets carry no device addresses**, so ATT operations cannot be
  address-filtered. They belong to the bait by construction, because the sniffer follows
  one address for the whole session.
- **The sniffer emits packets that failed CRC.** Unfiltered, they produced seven phantom
  scanner addresses one or two bits away from real ones, one of them the bait itself.
  `nordic_ble.crcok` is now checked.
- **The pcap clock reads ahead of host time; whether the offset is genuine is open (§7).**
  2026-08-04: 71 minutes, with the pcap spanning 78 minutes for 389 s of capture.
  Intervals between six `CONNECT_IND`s matched the canary's connect intervals to within
  two seconds (22/67/64/90/40 s against 21/66/64/90/42 s), so the rate is right: an
  offset, not drift. 2026-08-30: the two-stream effect below produces the same numbers
  with no clock wrong, and was not known when the offset was measured. 2026-11-06: during
  a live capture the last frame in file order read 4297 s ahead of the host clock, which
  points to a genuine offset of the same size, though it does not prove that frame came
  from the dense stream.
- **A pcap can contain two frame streams, and the seam reads as a clock offset.**
  *(2026-08-29/30.)* Some captures from `nrfutil ble-sniffer sniff` hold two streams
  written as two blocks, both starting when the capture started:

  ```
  200 s run, --duration 200:
    sparse   frames     1-5544   23:06:49 -> 00:14:51   5544 fr    1.4/s     0 ATT
    dense    frames  5545-26460  23:06:49 -> 23:10:09  20916 fr  104.8/s   101 ATT
  400 s run:
    sparse   frames     1-5283   15:10:10 -> 15:14:42   5283 fr   19.0/s     0 ATT
    dense    frames  5284-43352  15:10:10 -> 15:14:32  38069 fr  145.0/s   120 ATT
  ```

  The dense block is the real `--follow` capture; its span matches the requested duration
  to a fraction of a second, and it holds every ATT frame. The sparse block has no ATT and
  stretched timestamps, so `max(timestamp) - min(timestamp)` reads 68 minutes for a 200 s
  capture, the same shape as the 2026-08-04 reading. The last frame in file order is
  correct (23:10:09, the true end); only the maximum is not.

  *(2026-11-06.)* A 240 s capture with the sniffer found by USB id (so no `tshark -D` ran
  against it) held frames 1-5444 spanning the first 36 s, then frames from 0.6 s after the
  start to the true end. Both blocks sit on the real clock (they line up with the canary's
  connects) and are not copies: no frame matches on time, length and CRC.

  Cause not established. Radio contention was the first suspicion: a three-second
  `tshark -D` poll runs the extcap shim, which opens the dongle to identify it, and four
  shim processes were seen against it at once during a live capture. Runs with no
  `tshark -D` anywhere still produced two blocks, so that is at most a contributing
  factor. `nrfutil` runs three processes that all carry `--output-pcap-file`; that is the
  next thing to check. Some captures come out as a single block, including the 2026-08-04
  sample. `witness.py` warns on any backward time step.
- **Correct the clock with one offset, anchored on the last frame in file order** against
  the host time that frame was written; on a healthy clock it comes out near zero. Every
  wrong correction produced well-formed but false timestamps and no error:
  - Uncorrected, every witness event fell outside its true profile window and the
    correlator credited all incidents to whichever profile was live last.
  - Scaling between two endpoints (an earlier fix) assumes drift the measurements do not
    show, and smeared every event across the capture window.
  - Anchoring on `max()` shifts every event by however far that frame overshoots. Past
    `CONNECT_MERGE_SECONDS` (10 s) the two radios' views of one connection stop merging
    and every incident is reported twice, ATT ops on one copy and RSSI on the other.
  - Anchoring on the stop time is right only if the sniffer wrote until the end. Measured
    2026-11-06: one segment's sniffer stopped writing 96 s before the segment was stopped,
    so every frame landed 96 s late and the radios stopped merging. `witness.py` now
    records the pcap's mtime, read when the segment stops, in a `.end` file beside it; it
    matched the last frame to within a second. A later mtime is worthless, since any copy
    or checkout rewrites it (that shifted the bundled sample by four hours).
  - Mid-run there is no `.end` yet, so live conversion was uncorrected and the 4297 s
    offset put every witness event about 72 minutes in the future. A live segment is now
    anchored on its pcap's mtime at conversion, since the file is still being written.
  - A stale anchor from an earlier capture once put fresh frames 35 minutes off and filed
    every incident as "unattributed". Every capture now goes to a new segment file and
    names are never reused, so no `.end` can belong to anything else.
- **The pcap can be read while the capture is running** *(2026-08-29; formerly in §7)*.
  `tui.py` re-derives the incident table from the growing file every 30 s. The
  authoritative conversion still happens after each segment stops.
- **`tshark -D` cannot see the sniffer while it is capturing.** The shim cannot open a port
  `nrfutil` holds, so the interface vanishes from the listing and a presence poll reports
  the dongle unplugged. Presence comes from USB enumeration instead (VID `0x1915`, PID
  `0x522A`), as for the bait's CP210x. The interface name is read from `-D` once, before
  a capture starts.
- **Two collectors on one radio corrupt each other quietly.** A second console opened the
  bait's serial port alongside the first; the two canaries interleaved AT replies, and one
  logged a peer address missing its first byte. The canary now takes an exclusive lock and
  a second instance fails with `Could not exclusively lock port`. The second witness could
  not find the held sniffer and the console restarted it five times a second; restarts
  are now ten seconds apart and the status line says why the witness died.
- **Captures rotate into 10-minute segments.** Measured 2026-11-06: a capture grows about
  0.45 MB a minute and tshark converts about 0.9 MB a second. One file per 24-hour run
  would mean re-reading some 650 MB per live refresh, about 12 minutes of work every 30
  seconds; a 4.5 MB segment takes a few seconds. `witness.py` restarts `nrfutil` into
  `witness-NNN.pcapng` every 600 s, numbering after the highest segment in the folder, and
  re-converts only changed segments. A re-follow from the console (`w`) starts the next
  segment.
- **Stop the sniffer with SIGINT, not SIGTERM.** `nrfutil-ble-sniffer` handles SIGINT via
  the Rust `ctrlc` crate and prints `SIGINT received. Exiting...`. SIGTERM kills it
  outright and the `nrfutil` launcher reports `failed with unexpected exit code None`.
  `witness.py` sends SIGINT, then SIGTERM, then SIGKILL to the process group and waits for
  the whole group, since the launcher can exit before the sniffer. Not yet verified on
  hardware that this silences the `exit code None` message.
- **ATT direction follows opcode parity.** Even opcodes (requests, commands) come from the
  client, the prober; odd opcodes (responses, `Error Response`, notifications,
  indications) from the server, the bait. The report counts the prober's as `att` and the
  bait's as `replies`; an earlier version summed both, roughly doubling every count.
- **Scan requests are ambient.** Measured 2026-11-06: 1,741 `SCAN_REQ`s from 4
  neighbouring devices in a 4-minute run in which nothing targeted the bait; every
  actively scanning phone asks every advertiser for its scan response. The witness folds
  them into one event per scanner per minute with a `count`, and the report lists
  scanners apart from incidents.

### Tooling

- **tshark `-T ek` encodes numeric fields as JSON strings** (`"0"`, `"6157"`, `"-24"`);
  booleans stay booleans and timestamps are epoch milliseconds, not ISO8601. The field
  name's layer prefix varies between versions, so `parse.py` matches on suffix; a prefix
  change would otherwise null every field silently.
- **In a display filter, `field != value` is false when the field is absent.**
  `btle.advertising_header.pdu_type != 0` silently drops every ATT frame; use
  `!(... == 0)`.
- A phone mints a fresh resolvable private address per connection: six connections from
  one handset gave six addresses.
- Scanner apps cache stale profile names across a rotation, and connecting to the stale
  entry fails silently.

### The collectors and the console

- **SIGINT is the only signal either collector handles usefully.** On Ctrl-C the canary
  logs `stopped` and the witness stops the sniffer, writes the `.end` anchor and runs its
  final conversion; SIGTERM skips all of that. `tui.py` stops both with SIGINT and allows
  20 s before escalating.
- **A wrong address handoff silently ruins a run**: the witness records a valid pcap of
  nothing. The console reads the bait's address from the canary's log and starts the
  witness with it.
- Status columns are sized from their content, so a long port name or firmware string
  does not push the state off the screen.
- The console feed uses the canary's `QUIET` set: while a prober is connected the canary
  logs RSSI on every poll, which would scroll the connection out of view within seconds.
  The log keeps every line.

Every defect above was invisible in one log alone and obvious once the two radios were
compared.

---

## 2. The bait: AT interface

Port `/dev/cu.usbserial-2130`, 9600 8N1 RTS/CTS, slide switch on `CMD`.

```
$ ATI
ATI
BLEFRIEND32
nRF51822 0x0146
61CD26CB0CB259E9
0.9.0
0.9.0
Dec 18 2025
S110 8.0.0, 0.2
OK
```

The parser echoes each command before replying; `parse.py` discards the echo line.

State queries, captured with a phone connected:

```
$ AT+BLEGETADDR          $ AT+GAPGETCONN        $ AT+BLEGETPEERADDR
E1:84:87:02:B3:1E        1                      7C:9C:4C:XX:XX:XX
OK                       OK                     OK

$ AT+BLEGETADDRTYPE      $ AT+BLEGETRSSI        $ AT+GAPINTERVALS
1                        -44                    20,40,20,0,418
OK                       OK                     OK
```

`AT+BLEGETRSSI` returns `0` when nothing is connected; `parse.py` reports that as `None`,
not 0 dBm.

Commands that return `ERROR` even on 0.9.0:

```
$ AT+GAPGETADDR          $ AT+MODESWITCHEN
ERROR                    ERROR        <- needs an argument; AT+MODESWITCHEN=0 works
```

### What differs on 0.6.2

Full command sets: `tests/fixtures/at_session_0.6.2.txt` and `at_session_0.9.0.txt`.
0.9.0 adds 32 commands; these matter here:

| Command | Effect |
|---|---|
| `AT+BLEGETPEERADDR` | the canary can name the prober itself. On 0.6.2 that job falls entirely to the witness, the original reason for the two-radio design |
| `AT+MODESWITCHEN` | closes the AT-parser exposure described in §1 |
| `AT+EVENTENABLE` / `AT+EVENTSTATUS` | event-driven state instead of polling. Not used; polling works and is simpler |
| `AT+GAPCONNECTABLE`, `AT+BAUDRATE`, `AT+UARTFLOW`, `AT+GATTCHARRAW` | not used |

Also new: HID, MIDI and Eddystone support, and NVM read/write.

---

## 3. The witness: sniffer setup

The dongle arrived in `Open DFU Bootloader` mode (Nordic VID `0x1915`), so no button press
was needed. After flashing it enumerates as `nRF Sniffer for Bluetooth LE`.

```
$ nrfutil --version
nrfutil 8.2.0 (c910332 2026-04-21)
host: aarch64-apple-darwin

$ nrfutil list
Command      Version  Description
ble-sniffer  0.20.0   Bluetooth Low Energy (Bluetooth LE) sniffer for Nordic Semiconductor devices.
device       2.19.4   Device discovery, programming, and operations such as erase, reset, and recovery.
```

Sniffer firmware `sniffer_nrf52840dongle_nrf52840_4.1.1.zip`. tshark 4.6.7, at
`/opt/homebrew/bin/tshark` → `/Applications/Wireshark.app/Contents/MacOS/tshark`.
Plugin installed into the personal extcap directory, no sudo:

```
$ tshark -G folders | grep -i extcap
Personal Extcap path:	/Users/atahan/.local/lib/wireshark/extcap
Global Extcap path:  	/Applications/Wireshark.app/Contents/MacOS/extcap

$ nrfutil ble-sniffer bootstrap --extcap-dir ~/.local/lib/wireshark/extcap
Bootstrapping ble-sniffer...
Bootstrap succeeded

$ tshark -D | grep -i nrf
23. /dev/tty.usbmodem21401 (nRF Sniffer for Bluetooth LE)
```

The interface is named after the serial device path, not `nrf_sniffer_ble`, so
`witness.py` discovers it at runtime.

```
$ tshark -i /dev/tty.usbmodem21401 -a duration:15 -w smoke.pcapng
Capturing on 'nRF Sniffer for Bluetooth LE: /dev/tty.usbmodem21401'
2 packets captured

$ tshark -r smoke.pcapng
    1   0.000000 <REDACTED-NEIGHBOUR> → Broadcast    LE LL 50 ADV_IND
    2   0.000640 <REDACTED-NEIGHBOUR> → Broadcast    LE LL 50 ADV_IND
```

The count is low because the bait was not advertising yet and the default mode is "All
advertising devices" on a quiet band.

---

## 4. Why not the Wireshark extcap

`tshark` does not proxy the extcap protocol, so the options were read from the shim:

```
$ tshark -i /dev/tty.usbmodem21401 --extcap-config
tshark: unrecognized option: extcap-config

$ ~/.local/lib/wireshark/extcap/nrfutil-ble-sniffer-shim --extcap-interfaces
extcap {version=0.20.0}{display=nRF Sniffer for Bluetooth LE}{help=...}
interface {value=/dev/tty.usbmodem21401}{display=nRF Sniffer for Bluetooth LE}
control {number=0}{type=selector}{display=Device}{tooltip=Device list}
control {number=1}{type=selector}{display=Key}{tooltip=}
control {number=2}{type=string}{display=Value}{tooltip=6 digit passkey or ...}
control {number=3}{type=string}{display=Adv Hop}{default=37,38,39}{required=true}
value {control=0}{value= }{display=All advertising devices}{default=true}
value {control=1}{value=7}{display=Follow LE address}
[trimmed: button controls, and 8 further control=1 key types]

$ ~/.local/lib/wireshark/extcap/nrfutil-ble-sniffer-shim \
    --extcap-interface /dev/tty.usbmodem21401 --extcap-dlts
dlt {number=272}{name=NORDIC_BLE}{display=nRF Sniffer for Bluetooth LE}
```

"Follow LE address" is `control 1, value 7`, a control-pipe message the Wireshark GUI
sends interactively over a pair of FIFOs. Driving it from `tshark` would mean
implementing the control protocol by hand. `nrfutil ble-sniffer sniff` exposes it as a
flag, and the witness uses `--follow` with `--output-pcap-file`:

```
$ nrfutil ble-sniffer sniff --help
Usage: nrfutil-ble-sniffer sniff [OPTIONS] --port <port>

Options:
      --output-pcap-file <path>      Path to file of captured BLE data, stored in PCAP format.
      --follow <address>             Follow device with this address
      --follow-by-name <device name> Follow device with this user-friendly name
      --irk-key <key>                Provide an Identity Resolve Key
      --port <port>                  Sniffer serial port
      --rssi-cut-off <RSSI>          RSSI cut-off value
```

---

## 5. Upgrading the bait firmware

The board ships with 0.6.2 (April 2015). 0.9.0 adds `AT+BLEGETPEERADDR`,
`AT+MODESWITCHEN`, and an advertising timeout that can be set to "never".

The upgrade is over the air from the phone app only; Adafruit's guide confirms there is
no host-side route for the Bluefruit LE Friend. The Android build of Bluefruit Connect
crashed repeatedly during DFU; the iPad build of the same app completed it first try. If
Android crashes, try iOS before suspecting the device or the image.

Afterwards, re-run `tools/at_probe.py` and regenerate the fixtures: the recorded
transcripts and the version assertions in `tests/test_parse.py` describe whichever
firmware produced them. BD_ADDR and the device name survive the upgrade unchanged.

If an upgrade leaves the board unresponsive, the stock images are in
[Adafruit_BluefruitLE_Firmware](https://github.com/adafruit/Adafruit_BluefruitLE_Firmware)
and the guide's [downloads page](https://learn.adafruit.com/introducing-adafruit-ble-bluetooth-low-energy-friend/downloads)
covers recovery.

---

## 6. Kernel panic when flashing the dongle

The host kernel-panicked during DFU.
`/Library/Logs/DiagnosticReports/panic-full-2026-08-04-001132.0002.panic`:

```
"timestamp":"2026-08-04 00:11:32.00 +0300"
"product" : "Mac16,5"
"kernel" : "Darwin Kernel Version 25.6.0 ... RELEASE_ARM64_T6041"

panic(cpu 4 caller 0xfffffe0050c3d9ac): Kernel data abort.
  at pc 0xfffffe004ea13664, lr 0xfffffe004ea14a0c
  far: 0x0000000000000000        <- null dereference

Panicked task 0xfffffe1f258a2b18: 1225 pages, 8 threads: pid 8268: nrfutil-device

Kernel Extensions in backtrace:
   com.apple.iokit.IOSerialFamily(11.0)
   com.apple.driver.usb.cdc(5.0)
```

A null-pointer dereference in Apple's USB CDC-ACM driver, triggered by `nrfutil-device`
during DFU, most likely by the dongle re-enumerating mid-transfer with the CDC port still
open. It is a macOS driver bug, not an nrfutil misconfiguration; no flag avoids it.

- The flash succeeded anyway; the dongle came back as `nRF Sniffer for Bluetooth LE`.
- Ordinary capture has never panicked across many runs. Only the DFU path did.
- Concurrent AT probing of the Bluefruit, on the separate CP210x/`AppleUSBSerial` path,
  was unaffected and completed cleanly 72 seconds before the panic.

Save your work before flashing. It is a one-time step.

---

## 7. Still unverified

- What produces the second, sparse frame stream (§1). Radio contention is ruled out as the
  sole cause; whether more than one of the three `nrfutil` processes carrying
  `--output-pcap-file` writes has not been checked.
- Whether the pcap clock offset is genuine or the 2026-08-04 reading was a stream seam
  (§1). The 2026-11-06 live reading (+4297 s) suggests a real offset. Needs a capture
  verified to hold a single block, compared against the canary log.
- Whether SIGINT rather than SIGTERM silences the launcher's `unexpected exit code None`
  (§1).
- Whether a BLE peer writing `+++` can reach the AT parser on 0.6.2 (§1). Moot now that
  0.9.0 is installed.
- Whether the sniffer drops packets under load on this USB topology; both devices sit
  behind hubs.
- Whether `AT+EVENTENABLE`/`AT+EVENTSTATUS` could replace polling. Not tried.
