#!/usr/bin/env python3
"""Read-only protocol probe for Motorola earbuds (written for the Moto Buds 2 Fusion).

What it answers, in order:
  1. Does the device advertise the Moto RFCOMM service UUID?            (same protocol family?)
  2. Which RFCOMM channel speaks the HEAD/TAIL framed protocol?          (is it still 16?)
  3. Which READ opcodes from PROTOCOL.md does the device answer, and with what payload?

It never sends a write/set opcode. The three handshake opcodes are the same ones the app
itself sends on connect. Run it with the earbuds already connected in your OS Bluetooth settings:

    python3 backend/probe_fusion.py                 # auto-detects the device
    python3 backend/probe_fusion.py --mac AA:BB:..  # or name it explicitly

It writes <out>.txt and <out>.json (default: fusion_probe_report.*) in the current directory.
The MAC is masked in the report, and the Fast Pair account-key response (opcode 0x0010) is
redacted. The report can still contain firmware/hardware strings and possibly serial numbers
(opcode 0x0000), so skim it before posting it publicly.
"""
import argparse
import binascii
import json
import os
import re
import socket
import struct
import sys
import time

# The bundled Windows Python (python311._pth) does not add the script's folder to sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from moto_control import (
    HEAD, TAIL, MOTO_SPP_UUID, RFCOMM_PORT,
    build_packet, discover_device, scan_rfcomm_channels, _bluetoothctl,
)

# (opcode, request payload, label). All are reads or the app's own connect handshake.
HANDSHAKE = [
    (0x0000, b"", "profile version / firmware info"),
    (0x000B, b"\xfc\xff\x05\x00", "list support info and configs"),
    (0x0010, b"", "read account key"),
]
READS = [
    (0x0001, b"", "get support features"),
    (0x0003, b"", "get device name"),
    (0x0004, b"", "get hardware info"),
    (0x0005, b"", "get battery level"),
    (0x0100, b"", "get gesture toggle configs"),
    (0x0200, b"", "read ANC mode"),
    (0x0300, b"", "read EQ state"),
    (0x0301, b"", "enumerate EQ presets"),
    (0x0305, b"", "read custom EQ"),
    (0x030C, b"", "read Hi-Res mode"),
    (0x030E, b"", "read game mode"),
    (0x0313, b"", "read volume boost"),
    (0x0402, b"", "read in-ear detection"),
]
REDACT_PAYLOAD_OPCODES = {0x0010}  # Fast Pair account key: never write it to a report
ANC_MODES = {0: "off", 1: "anc", 2: "transparency"}


def parse_frames(buf: bytes):
    """Split a byte stream into HEAD..TAIL frames and verify each CRC32."""
    frames, i = [], 0
    while i + 22 <= len(buf):
        if buf[i:i + 4] != HEAD:
            i += 1
            continue
        plen = buf[i + 10] | (buf[i + 11] << 8)
        end = i + 14 + plen + 4 + 4
        if end > len(buf):
            break
        body = buf[i:i + 14 + plen]
        crc_rx = struct.unpack("<I", buf[i + 14 + plen:i + 14 + plen + 4])[0]
        frames.append({
            "opcode": (buf[i + 6] << 8) | buf[i + 7],
            "type": buf[i + 8],
            "result": buf[i + 9],
            "seq": buf[i + 12] | (buf[i + 13] << 8),
            "payload": bytes(buf[i + 14:i + 14 + plen]),
            "crc_ok": (binascii.crc32(body) & 0xFFFFFFFF) == crc_rx,
            "tail_ok": buf[end - 4:end] == TAIL,
        })
        i = end
    return frames


def decode_hint(opcode: int, payload: bytes) -> str:
    if opcode == 0x0000:
        strings = re.findall(rb"[\x20-\x7e]{4,}", payload)
        text = [s.decode() for s in strings]
        model = next((m.group(0) for s in text if (m := re.search(r"XT\d{4}-\d", s))), None)
        return f"strings={text}" + (f"  model_id={model}" if model else "")
    if opcode in (0x0005, 0x0009) and len(payload) >= 3:
        def one(b): return f"{b & 0x7F}%{'+chg/in-case' if b & 0x80 else ''}"
        return f"L={one(payload[0])} R={one(payload[1])} case={one(payload[2])}"
    if opcode in (0x0200, 0x0204) and len(payload) >= 2:
        return f"mode={ANC_MODES.get(payload[0], payload[0])} sub_mode={payload[1]}"
    if opcode in (0x030C, 0x0311) and payload:
        return f"hires_payload={payload.hex()} (LDAC-specific in the original app)"
    if opcode in (0x030E, 0x0312) and payload:
        return f"game_mode_payload={payload.hex()} (0x19=on 0x1A=off in notifications)"
    if opcode == 0x0402 and payload:
        return f"in_ear_detection={'on' if payload[0] == 1 else 'off'}"
    return ""


def mask_mac(text: str, mac: str, enabled: bool) -> str:
    if not enabled:
        return text
    masked = "XX:XX:XX:XX:XX:" + mac[-2:]
    return re.sub(re.escape(mac), masked, text, flags=re.IGNORECASE)


def open_socket(mac: str, port: int, timeout=3.0):
    if mac == "127.0.0.1":  # mock server used by the repo's tests
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.settimeout(timeout)
    s.connect((mac, port))
    return s


def collect(sock, window=1.2, quiet=0.45) -> bytes:
    """Read everything the device sends for up to `window` seconds, stopping after `quiet` idle seconds."""
    data, start, last = bytearray(), time.time(), None
    while time.time() - start < window:
        sock.settimeout(0.15)
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            last = time.time()
        except socket.timeout:
            if last is not None and time.time() - last >= quiet:
                break
    return bytes(data)


def main():
    ap = argparse.ArgumentParser(description="Read-only Moto earbuds protocol probe")
    ap.add_argument("--mac", help="earbuds MAC (default: auto-detect; 127.0.0.1 = repo mock server)")
    ap.add_argument("--port", type=int, default=RFCOMM_PORT, help="RFCOMM channel to try first (default 16)")
    ap.add_argument("--out", default="fusion_probe_report", help="output file prefix")
    ap.add_argument("--no-mask-mac", action="store_true", help="do not mask the MAC address in the report")
    args = ap.parse_args()
    mask = not args.no_mask_mac

    lines, report = [], {"steps": {}, "opcodes": []}

    def say(msg=""):
        lines.append(msg)
        print(msg)

    name = None
    if args.mac:
        mac = args.mac.upper() if args.mac != "127.0.0.1" else args.mac
    else:
        found = discover_device()
        if not found:
            print("No Moto earbuds found. Connect them in your OS Bluetooth settings first, or pass --mac.")
            return 2
        mac, name = found["mac"], found["name"]

    say("== Moto earbuds read-only probe ==")
    say(f"device      : {name or '(unnamed)'}  {mask_mac(mac, mac, mask)}")

    # Step 1: service UUIDs
    info = _bluetoothctl("info", mac) if mac != "127.0.0.1" else ""
    has_uuid = MOTO_SPP_UUID in info.lower()
    report["steps"]["advertises_moto_uuid"] = has_uuid
    for ln in info.splitlines():
        if re.match(r"\s*(Name|Alias|Class|Modalias|UUID):", ln):
            say("  bt> " + mask_mac(ln.strip(), mac, mask))
    if not info and mac != "127.0.0.1":
        has_uuid = None
        report["steps"]["advertises_moto_uuid"] = None
        say("[1] service UUID check skipped (needs bluetoothctl, i.e. Linux/BlueZ); step [2] is the real test.")
    else:
        say(f"[1] advertises Moto RFCOMM UUID ({MOTO_SPP_UUID[:8]}...): {'YES' if has_uuid else 'NO / not shown'}")

    # Step 2: channel
    port, sock = args.port, None
    try:
        sock = open_socket(mac, port)
        say(f"[2] RFCOMM channel {port}: connected")
    except Exception as e:
        say(f"[2] RFCOMM channel {port}: failed ({e}); scanning channels 1-30...")
        ch = scan_rfcomm_channels(mac) if mac != "127.0.0.1" else None
        if ch is None:
            say("    no channel answered the HEAD/TAIL protocol -> different protocol or transport (BLE GATT?).")
            say("    Next step: capture the official app with an Android HCI snoop log and compare framing.")
            report["steps"]["channel"] = None
            _write(args.out, lines, report)
            return 1
        port = ch
        sock = open_socket(mac, port)
        say(f"    protocol answers on channel {ch}  <-- differs from default {RFCOMM_PORT}" if ch != RFCOMM_PORT
            else f"    protocol answers on channel {ch}")
    report["steps"]["channel"] = port

    # Step 3: opcodes
    say("[3] opcode probe (reads + the app's own connect handshake):")
    seen_any = False
    try:
        for opcode, payload, label in HANDSHAKE + READS:
            sock.send(build_packet(opcode, payload))
            raw = collect(sock)
            frames = parse_frames(raw)
            entry = {"opcode": f"0x{opcode:04X}", "label": label, "replied": bool(frames), "frames": []}
            if not frames:
                say(f"  0x{opcode:04X} {label:<34} no reply")
            for f in frames:
                seen_any = True
                redacted = f["opcode"] in REDACT_PAYLOAD_OPCODES
                shown = f"<redacted {len(f['payload'])} bytes>" if redacted else f["payload"].hex()
                hint = "" if redacted else decode_hint(f["opcode"], f["payload"])
                ok = "" if (f["crc_ok"] and f["tail_ok"]) else "  [BAD CRC/TAIL]"
                say(f"  0x{opcode:04X} {label:<34} -> op=0x{f['opcode']:04X} type={f['type']} "
                    f"result={f['result']} payload={shown}{ok}")
                if hint:
                    say(f"         {mask_mac(hint, mac, mask)}")
                entry["frames"].append({
                    "opcode": f"0x{f['opcode']:04X}", "type": f["type"], "result": f["result"],
                    "payload_hex": shown, "crc_ok": f["crc_ok"], "tail_ok": f["tail_ok"], "hint": hint,
                })
            report["opcodes"].append(entry)
    finally:
        sock.close()

    answered = [e["opcode"] for e in report["opcodes"] if e["replied"]]
    silent = [e["opcode"] for e in report["opcodes"] if not e["replied"]]
    say("")
    say(f"answered : {', '.join(answered) or '-'}")
    say(f"silent   : {', '.join(silent) or '-'}")
    say("Silent opcodes are features to hide or re-map in the app for this model.")
    report["summary"] = {"answered": answered, "silent": silent, "any_framed_reply": seen_any}
    _write(args.out, lines, report)
    return 0 if seen_any else 1


def _write(prefix, lines, report):
    with open(prefix + ".txt", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(prefix + ".json", "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nreport written to {prefix}.txt and {prefix}.json")


if __name__ == "__main__":
    sys.exit(main())
