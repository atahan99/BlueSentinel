# Hardware notes

What these two boards actually do, as opposed to what their documentation says. Every
block below is verbatim output from a real command; failures are recorded with the failure
intact, and nothing is reconstructed from general knowledge.

**Host:** Mac16,5 (M4 Max), macOS 26.6 (25G72), Darwin 25.6.0 arm64, Python 3.13.3.
**Date:** 2026-08-04. Third-party addresses are redacted; the bait's own address is not
secret and is left intact, since the witness has to be configured with it.

## Current state

| | Bait | Witness |
|---|---|---|
| Board | Bluefruit LE Friend, nRF51822 | nRF52840 Dongle, PCA10059 |
| Firmware | **0.9.0** (Dec 18 2025), SoftDevice S110 8.0.0 | nRF Sniffer 4.1.1 |
| Port | `/dev/cu.usbserial-2130` (CP2102N, `0x10C4`/`0xEA60`) | `/dev/tty.usbmodem21401` |
| Address | `E1:84:87:02:B3:1E`, random static | — |

The bait shipped with **0.6.2** (Apr 2015) and was upgraded — see §5. Both firmwares are
kept as test fixtures and the parsers are tested against both, so 0.6.2 behaviour is
documented wherever the code still accommodates it.

---

## 1. Findings that shaped the code

The reason this file exists. Each of these changed how a collector is written, and each
would silently break a reimplementation.

### The bait

- **`AT+GAPGETADDR` does not exist.** The command is `AT+BLEGETADDR`. Writing the collector
  from documentation rather than probing would have failed on the first call.
- **BD_ADDR is fixed in the chip.** Unchanged across host reboots, power cycles, the
  firmware upgrade, and every profile rotation; `address_changed` has never fired. This is
  what lets the witness follow one address while the identity above it changes.
- **`AT+GAPAUTOADV` is `1`**, so the device is already advertising after `ATZ` and a bare
  `AT+GAPSTARTADV` returns `ERROR`. The collector stops before starting, so an `ERROR` in
  the log means something real.
- **0.6.2 caps the advertising timeout at 180 s and silently rejects `0`** while still
  answering `OK`. 0.9.0 accepts `0`. Neither firmware's status reply tells you whether the
  write took, so `canary.py` reads the value back and only arms its keepalive if the
  firmware refused.
- **`AT+GAPINTERVALS` returns 4 fields on 0.6.2 and 5 on 0.9.0.** Do not index it
  positionally without checking length.
- **Rotation drops any live connection** — `disconnect` fires ~29 ms after
  `profile_change`, because applying an identity requires `ATZ`. Dwell time is not only
  about being seen; too short and you cut off the prober you are observing.
- **One connection at a time.** S110 is peripheral-only with a single link, and the bait
  stops advertising entirely while occupied. A busy honeypot is an invisible honeypot.
- **Keep one serial session open across rotations.** Opening the CP2102N port asserts DTR,
  which resets the nRF51. A harness that reconnected per `apply_profile` made the
  advertised payload lag exactly one profile behind while every AT command still answered
  `OK`. `canary.py` holds a single session and is unaffected.
- **An `OK` from `AT+GAPSETADVDATA` proves only that the command parsed.** Confirming a
  profile reached the air means reading it back off the radio. All six shipped profiles
  were verified that way, each advertising its own service UUID during its own dwell
  window: `smartlock` `0x1815`, `heartrate` `0x180D`, `tracker` `0x1802`+`0x180F`,
  `keyboard` `0x1812` (appearance Keyboard), `thermostat` `0x181A`, `fitness`
  `0x1816`+`0x180F`.
- **A prober can reach the AT parser on 0.6.2.** `+++`, the mode-switch escape, is in the
  command set and 0.6.2 has no `AT+MODESWITCHEN` to disable it, so a peer writing to the
  UART characteristic could in principle issue `AT+FACTORYRESET`. Whether `+++` from a BLE
  peer actually reaches the parser was never tested — the expectation is that UART RX
  buffers for `AT+BLEUARTRX` instead. On 0.9.0 it is moot: `canary.py` issues
  `AT+MODESWITCHEN=0` at every session start and logs `modeswitch_disabled`.

### The sniffer

- **The extcap plugin cannot follow an address from the command line.** "Follow LE
  address" is an interactive control-pipe message (§4). `nrfutil ble-sniffer sniff
  --follow` does it directly, which is why `witness.py` uses that instead.
- **`--follow` does capture connection-phase packets** — real `CONNECT_IND` plus ATT, not
  just advertising.
- **Connection-phase packets carry no device addresses**, so ATT operations cannot be
  address-filtered. They are ours by construction, because the sniffer is following one
  address for the whole session.
- **The sniffer emits packets that failed CRC.** Unfiltered these produced seven phantom
  scanner addresses one or two bits away from real ones, including one that was the bait
  itself. `nordic_ble.crcok` is now checked.
- **The pcap clock sits at a constant offset from host time** — 71 minutes in the measured
  run, with the pcap spanning 78 minutes for 389 s of capture. The *rate* is correct:
  intervals between six `CONNECT_IND`s matched the canary's connect intervals to within two
  seconds (22/67/64/90/40 s against 21/66/64/90/42 s), which is what distinguishes an
  offset from drift. An earlier fix assumed drift and rescaled between endpoints, smearing
  every event across the capture window. `witness.py` applies a single offset, anchored on
  the capture-end time it records beside the pcap — a file's mtime looks like the same
  thing but is rewritten by any copy or checkout, which shifted the bundled sample by four
  hours. Uncorrected, every witness event fell outside its
  true profile window and the correlator credited all incidents to whichever profile was
  live last — with well-formed JSONL throughout.
- **Extcap default mode captured 7 packets in 25 s where `nrfutil --follow` captured 6163
  in 40 s** on the same radio.

### Tooling

- **tshark `-T ek` encodes numeric fields as JSON strings**, and timestamps as epoch
  milliseconds rather than ISO8601.
- **In a display filter, `field != value` is false when the field is absent.** Filtering
  ATT frames with `btle.advertising_header.pdu_type != 0` silently drops all of them; use
  `!(... == 0)`.
- A phone mints a **fresh resolvable private address per connection** — six connections
  from one handset produced six distinct addresses.
- Scanner apps cache stale profile names across a rotation, and connecting to the stale
  entry fails silently.

**The general lesson.** Every defect above was invisible in one log alone and obvious the
moment the two radios were compared. The second radio is a debugging instrument as well as
a sensor.

---

## 2. The bait — AT interface

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

The parser echoes each command back before replying, so `parse.py` discards the echo line.

State queries, captured with a phone connected:

```
$ AT+BLEGETADDR          $ AT+GAPGETCONN        $ AT+BLEGETPEERADDR
E1:84:87:02:B3:1E        1                      7C:9C:4C:XX:XX:XX
OK                       OK                     OK

$ AT+BLEGETADDRTYPE      $ AT+BLEGETRSSI        $ AT+GAPINTERVALS
1                        -44                    20,40,20,0,418
OK                       OK                     OK
```

`AT+BLEGETRSSI` returns `0` when nothing is connected, which is not a real reading —
`parse.py` reports it as `None` rather than 0 dBm.

Commands that return `ERROR` even on 0.9.0:

```
$ AT+GAPGETADDR          $ AT+MODESWITCHEN
ERROR                    ERROR        <- needs an argument; AT+MODESWITCHEN=0 works
```

### What differs on 0.6.2

The full command sets are in `tests/fixtures/at_session_0.6.2.txt` and
`at_session_0.9.0.txt`. 0.9.0 adds 32 commands, of which these matter here:

| Command | Effect |
|---|---|
| `AT+BLEGETPEERADDR` | the canary can name the prober itself. On 0.6.2 that job falls **entirely** to the witness — the original reason for the two-radio design |
| `AT+MODESWITCHEN` | closes the AT-parser exposure described in §1 |
| `AT+EVENTENABLE` / `AT+EVENTSTATUS` | event-driven state instead of polling. Not used; polling works and is simpler |
| `AT+GAPCONNECTABLE`, `AT+BAUDRATE`, `AT+UARTFLOW`, `AT+GATTCHARRAW` | not used |

Also new: HID, MIDI and Eddystone support, and NVM read/write.

---

## 3. The witness — sniffer setup

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

Plugin installed into the **personal** extcap directory, no sudo:

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

**The interface is named after the serial device path, not `nrf_sniffer_ble`.** It is
host-specific, so `witness.py` discovers it at runtime.

Live capture, confirming the whole chain works:

```
$ tshark -i /dev/tty.usbmodem21401 -a duration:15 -w smoke.pcapng
Capturing on 'nRF Sniffer for Bluetooth LE: /dev/tty.usbmodem21401'
2 packets captured

$ tshark -r smoke.pcapng
    1   0.000000 <REDACTED-NEIGHBOUR> → Broadcast    LE LL 50 ADV_IND
    2   0.000640 <REDACTED-NEIGHBOUR> → Broadcast    LE LL 50 ADV_IND
```

Real frames off the air. The count is low because the bait was not advertising yet and the
default mode is "All advertising devices" on a quiet band.

---

## 4. Why not the Wireshark extcap

`tshark` does not proxy the extcap protocol, so the options have to be read from the shim
binary directly:

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

"Follow LE address" is `control 1, value 7` — an **extcap control-pipe message**, driven
interactively by the Wireshark GUI over a pair of FIFOs. Driving that from `tshark` would
mean implementing the control protocol by hand.

`nrfutil ble-sniffer sniff` exposes it directly instead:

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

`--follow` plus `--output-pcap-file` is exactly what the witness needs, with no control
pipes and no FIFO plumbing.

---

## 5. Upgrading the bait firmware

The board ships with 0.6.2 from April 2015. Updating to 0.9.0 is worth it — it is what
gives you `AT+BLEGETPEERADDR`, `AT+MODESWITCHEN`, and an advertising timeout that can be
set to "never".

**It must be done over the air from the phone app; there is no host-side path.** Adafruit's
guide confirms this, and the Bluefruit LE Friend has no other supported route.

**The Android build of Bluefruit Connect crashed repeatedly during DFU. The iPad build of
the same app completed it first try.** If Android crashes, try iOS before suspecting the
device or the image.

Afterwards, re-run `tools/at_probe.py` and regenerate the fixtures — the recorded
transcripts and the version assertions in `tests/test_parse.py` describe whichever
firmware produced them. BD_ADDR and the device name both survive the upgrade unchanged.

If an upgrade fails and leaves the board unresponsive, the stock images are in
[Adafruit_BluefruitLE_Firmware](https://github.com/adafruit/Adafruit_BluefruitLE_Firmware)
and the guide's [downloads page](https://learn.adafruit.com/introducing-adafruit-ble-bluetooth-low-energy-friend/downloads)
covers recovery. Worth knowing before you start, not after.

---

## 6. Kernel panic when flashing the dongle

**The host kernel-panicked during DFU.** Recorded because it is a real result that affects
anyone reproducing this.

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

A null-pointer dereference **inside Apple's own USB CDC-ACM driver**, triggered by
`nrfutil-device` during DFU — most likely the dongle detaching and re-enumerating
mid-transfer with the CDC port still open.

- The flash **succeeded anyway**; the dongle came back as `nRF Sniffer for Bluetooth LE`.
- It is a macOS driver bug, not an nrfutil misconfiguration. No flag avoids it.
- Ordinary capture has never panicked across many runs. Only the DFU path did.
- Concurrent AT probing of the Bluefruit, on the separate CP210x/`AppleUSBSerial` path,
  was unaffected and completed cleanly 72 seconds before the panic.

Save your work before flashing. It is a one-time step.

---

## 7. Still unverified

- Whether the pcap is flushed incrementally enough to read while capture is running. The
  design does not depend on it — conversion happens afterwards, and `--convert` can
  re-derive at any time.
- Whether a BLE peer writing `+++` can reach the AT parser on 0.6.2 (§1). Moot in practice
  now that 0.9.0 is installed.
- Whether the sniffer drops packets under load on this USB topology; both devices sit
  behind hubs.
- Whether `AT+EVENTENABLE`/`AT+EVENTSTATUS` could replace polling. Not tried; polling works
  and is simpler.
