# Moto Buds 2 Fusion support (experimental, Windows + Linux)

## Why the original only worked with one pair of buds

The daemon (`backend/moto_control.py`) had the author's own earbuds' MAC address hard-coded as the
default, and Electron always started it without `--mac`. It was not a protocol limitation, so any
other earbuds (any model) failed to connect.

## What this branch changes

- **Auto-detects the earbuds.** Linux: `bluetoothctl` (prefers a *connected* device that advertises
  the Moto RFCOMM UUID or has a Moto name). Windows: the PnP Bluetooth device list via PowerShell,
  matched by Bluetooth name (Windows does not tell us whether the device is currently connected).
  Override with `--mac` or the `MOTO_BUDS_MAC` environment variable.
- **RFCOMM channel fallback:** tries channel 16 first, then scans channels 1-30 using only the
  read-only opcode `0x0000`.
- Linux: the daemon trusts the detected device itself. The UI now shows the real Bluetooth name.
- The **LDAC-specific Hi-Res toggle** is hidden for the Moto Buds 2 family (they advertise LHDC).
- `backend/probe_fusion.py`: read-only protocol probe. `backend/test_discovery.py`: unit tests.

## Run the probe (earbuds paired in your OS Bluetooth settings)

Windows (uses the Python bundled with this repo, nothing to install), from the repo root:

    backend\win-python\python.exe backend\probe_fusion.py

Linux:

    python3 backend/probe_fusion.py

If auto-detect picks nothing or the wrong device, pass the MAC explicitly. On Windows, the MAC is the
12 hex digits after `DEV_` in the instance ID printed by:

    Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName,InstanceId

    backend\win-python\python.exe backend\probe_fusion.py --mac AA:BB:CC:DD:EE:FF

It writes `fusion_probe_report.txt/.json` in the current folder. The MAC is masked and the Fast Pair
account key (opcode `0x0010`) is redacted. Skim it for serial numbers before posting it publicly.

## Reading the result

| Probe output | Meaning | Next step |
|---|---|---|
| `[2]` channel found, opcodes answered | Same protocol family | Test the matching UI controls |
| `[2]` channel differs from 16 | Same protocol, different port | Already handled by the scan |
| `[2]` no channel answers | Different protocol or BLE GATT only | Capture the official app (Android HCI snoop log) and compare framing with `PROTOCOL.md` |
| An opcode is **silent** | Feature absent or re-mapped | Hide it for this model in `profileFor()` (`src/store/useDeviceStore.ts`) |

`[1]` (service UUID check) only runs on Linux; on Windows it is skipped and `[2]` is the real test.

Write opcodes (ANC set, EQ write, gestures, ...) are intentionally **not** probed. Try them from the UI
only after the matching read opcode answered.
