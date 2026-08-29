# Installation

Full setup for both radios. If you only want to try the parsers and the report against
the capture bundled with the repo, you do not need any of this — see
[Quick start](../README.md#install).

Every step ends with a check. If a check fails, stop there: the next step will not work,
and [Troubleshooting](../README.md#limitations) covers the common causes.

## 0. The repo

```bash
git clone https://github.com/atahan99/BlueSentinel.git
cd BlueSentinel
python3 -m pip install -r requirements.txt
python3 -m pytest tests/ -q          # 33 tests, no hardware needed
```

If the tests pass, the code is sound and everything below is hardware setup.

## 1. Install tshark

```bash
brew install --cask wireshark      # macOS
sudo apt install tshark            # Debian/Ubuntu
```

## 2. Plug in the Bluefruit, slide the switch to `CMD`

```bash
python3 tools/at_probe.py --commands ATI
```

You should see your firmware version. No output at all means the switch is on `UART` —
by far the most common cause of "my device is dead".

## 3. Install nrfutil

```bash
PLAT=aarch64-apple-darwin          # or x86_64-apple-darwin, x86_64-unknown-linux-gnu
mkdir -p ~/.local/bin
curl -L "https://files.nordicsemi.com/artifactory/swtools/external/nrfutil/executables/$PLAT/nrfutil" -o ~/.local/bin/nrfutil
chmod +x ~/.local/bin/nrfutil
export PATH="$HOME/.local/bin:$PATH"
nrfutil install ble-sniffer
```

## 4. Flash the dongle

Insert it **while holding the side button**, until the red LED pulses. That is DFU mode.

```bash
nrfutil device list                 # note the serial number
nrfutil device program \
  --firmware ~/.nrfutil/share/nrfutil-ble-sniffer/firmware/sniffer_nrf52840dongle_nrf52840_4.1.1.zip \
  --serial-number <serial>
```

> **Save your work first.** On macOS 26.6 / Apple Silicon this step kernel-panicked our
> machine — a null-pointer dereference inside Apple's own `com.apple.driver.usb.cdc`
> driver during DFU. The flash succeeded anyway and ordinary capture has never panicked
> since, but it is a macOS driver bug no flag avoids. Details in
> [hardware-notes.md](hardware-notes.md) §6.

After flashing **the LED goes dark — that is correct.** The pulsing LED belongs to the
bootloader, which is no longer running.

## 5. Install the Wireshark plugin

```bash
mkdir -p ~/.local/lib/wireshark/extcap
nrfutil ble-sniffer bootstrap --extcap-dir ~/.local/lib/wireshark/extcap
tshark -D | grep -i nrf             # should list the sniffer
```

## 6. Permissions and drivers

| OS | Note |
|---|---|
| Linux | `cp210x` is in-kernel. Add yourself to `dialout`: `sudo usermod -aG dialout $USER`, then log out and back in. |
| macOS | May need the [Silicon Labs VCP driver](https://www.silabs.com/developer-tools/usb-to-uart-bridge-vcp-drivers) on older versions. Recent macOS includes it. |

The sniffer interface is named after the **serial device path**, not `nrf_sniffer_ble`.
It is host-specific, which is why the code discovers it at runtime.

## 7. Check it with a phone

You need a GATT client to generate traffic. The **system Bluetooth settings screen will
not work** — it lists pairable accessories, and an unpaired BLE-only peripheral never
appears there no matter how correctly it is advertising.

**[nRF Connect](https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp)**
(Nordic) is the better tool: scanner tab, filter by name, and it exposes the whole GATT
table so you can write arbitrary bytes to any characteristic.

**[Bluefruit Connect](https://play.google.com/store/apps/details?id=com.adafruit.bluefruit.le.connect.v4)**
(Adafruit) also works. Connect, then open *Info* to walk the GATT table and generate a
burst of ATT reads.

Both are available for iOS too.

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| `at_probe.py` prints nothing | Slide switch is on `UART`. Move it to `CMD`. |
| `No CP210x port found` | Try another cable — many USB cables are charge-only. On Linux, check the `dialout` group. |
| `No sniffer interface found` | Dongle not flashed, or the plugin went to the wrong directory. Compare against `tshark -G folders`. |
| Dongle has no LED | Correct after flashing. The pulsing LED is the bootloader's. |
| Phone cannot see the bait | Use nRF Connect, not the system Bluetooth menu. |
| Sees it but will not connect | Something else is already connected — the bait takes one at a time. |
| Radio will not open on a second run | An orphaned sniffer holds the port: `pkill -f nrfutil`. |
| `report.py` says "No incidents" | Nothing connected. The scanner list still shows who looked. |
