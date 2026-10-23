"""Unit tests for device auto-discovery and packet framing (no Bluetooth hardware needed)."""
import binascii
import os
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import moto_control as mc

DEVICES = """Device 11:22:33:44:55:66 Some Speaker
Device AA:BB:CC:DD:EE:FF moto buds 2 Fusion
Device 54:84:50:92:78:AE moto buds
"""

INFO = {
    "11:22:33:44:55:66": "Name: Some Speaker\n\tConnected: yes\n",
    "AA:BB:CC:DD:EE:FF": "Name: moto buds 2 Fusion\n\tUUID: Vendor specific (fc9d9fe0-4899-11ee-be56-0242ac120002)\n\tConnected: yes\n",
    "54:84:50:92:78:AE": "Name: moto buds\n\tConnected: no\n",
}


class DiscoveryTests(unittest.TestCase):
    def test_parse_device_list(self):
        self.assertEqual(
            mc.parse_device_list(DEVICES),
            [("11:22:33:44:55:66", "Some Speaker"), ("AA:BB:CC:DD:EE:FF", "moto buds 2 Fusion"),
             ("54:84:50:92:78:AE", "moto buds")],
        )

    def test_non_moto_scores_zero(self):
        self.assertEqual(mc.score_device("Some Speaker", INFO["11:22:33:44:55:66"]), 0)

    def test_connected_uuid_device_beats_disconnected_name_match(self):
        fusion = mc.score_device("moto buds 2 Fusion", INFO["AA:BB:CC:DD:EE:FF"])
        old = mc.score_device("moto buds", INFO["54:84:50:92:78:AE"])
        self.assertGreater(fusion, old)

    def test_discover_picks_connected_fusion_not_authors_mac(self):
        with mock.patch.dict(os.environ, {}, clear=False), \
             mock.patch.object(mc, "_bluetoothctl", side_effect=lambda *a, **k: DEVICES if a[0] == "devices" else INFO[a[1]]):
            os.environ.pop("MOTO_BUDS_MAC", None)
            self.assertEqual(mc.discover_device(), {"mac": "AA:BB:CC:DD:EE:FF", "name": "moto buds 2 Fusion"})

    def test_discover_none_when_no_moto_device(self):
        with mock.patch.object(mc, "_bluetoothctl", side_effect=lambda *a, **k: "Device 11:22:33:44:55:66 Some Speaker\n" if a[0] == "devices" else INFO["11:22:33:44:55:66"]):
            os.environ.pop("MOTO_BUDS_MAC", None)
            self.assertIsNone(mc.discover_device())

    def test_env_override(self):
        with mock.patch.dict(os.environ, {"MOTO_BUDS_MAC": "aa:bb:cc:dd:ee:00"}):
            self.assertEqual(mc.discover_device()["mac"], "AA:BB:CC:DD:EE:00")


PNP_JSON = r"""[
  {"FriendlyName": "Intel(R) Wireless Bluetooth(R)", "InstanceId": "USB\\VID_8087&PID_0033\\5&1A2B"},
  {"FriendlyName": "moto buds 2 Fusion", "InstanceId": "BTHENUM\\DEV_AABBCCDDEEFF\\7&2F1E&0&BLUETOOTHDEVICE_AABBCCDDEEFF"},
  {"FriendlyName": "moto buds 2 Fusion", "InstanceId": "BTHENUM\\DEV_AABBCCDDEEFF\\7&2F1E&0&DUPLICATE"},
  {"FriendlyName": "Some Speaker", "InstanceId": "BTHENUM\\DEV_112233445566\\7&9&0&BLUETOOTHDEVICE_112233445566"}
]"""


class WindowsDiscoveryTests(unittest.TestCase):
    def test_parse_pnp_devices_extracts_mac_and_dedupes(self):
        self.assertEqual(
            mc.parse_pnp_devices(PNP_JSON),
            [("AA:BB:CC:DD:EE:FF", "moto buds 2 Fusion"), ("11:22:33:44:55:66", "Some Speaker")],
        )

    def test_single_device_comes_back_as_object_not_list(self):
        one = '{"FriendlyName": "moto buds", "InstanceId": "BTHENUM\\\\DEV_AABBCCDDEEFF\\\\x"}'
        self.assertEqual(mc.parse_pnp_devices(one), [("AA:BB:CC:DD:EE:FF", "moto buds")])

    def test_garbage_and_empty_output(self):
        self.assertEqual(mc.parse_pnp_devices(""), [])
        self.assertEqual(mc.parse_pnp_devices("not json"), [])

    def test_discover_on_windows_picks_moto_by_name(self):
        devices = mc.parse_pnp_devices(PNP_JSON)
        with mock.patch.object(mc.sys, "platform", "win32"), \
             mock.patch.object(mc, "_windows_devices", return_value=devices):
            os.environ.pop("MOTO_BUDS_MAC", None)
            self.assertEqual(mc.discover_device(), {"mac": "AA:BB:CC:DD:EE:FF", "name": "moto buds 2 Fusion"})

    def test_discover_on_windows_none_found(self):
        with mock.patch.object(mc.sys, "platform", "win32"), \
             mock.patch.object(mc, "_windows_devices", return_value=[("11:22:33:44:55:66", "Some Speaker")]):
            os.environ.pop("MOTO_BUDS_MAC", None)
            self.assertIsNone(mc.discover_device())


class FramingTests(unittest.TestCase):
    def test_frame_layout_and_crc(self):
        pkt = mc.build_packet(0x0201, bytes([1, 1]))
        self.assertEqual(pkt[:4], b"HEAD")
        self.assertEqual(int.from_bytes(pkt[4:6], "little"), 8 + 2)   # total length
        self.assertEqual(int.from_bytes(pkt[6:8], "big"), 0x0201)     # opcode
        self.assertEqual((pkt[8], pkt[9]), (128, 0))                  # type, result
        self.assertEqual(int.from_bytes(pkt[10:12], "little"), 2)     # payload length
        self.assertEqual(pkt[14:16], bytes([1, 1]))                   # payload
        crc = struct.unpack("<I", pkt[16:20])[0]
        self.assertEqual(crc, binascii.crc32(pkt[:16]) & 0xFFFFFFFF)  # CRC over HEAD..payload
        self.assertEqual(pkt[20:], b"TAIL")

    def test_probe_parser_roundtrip(self):
        import probe_fusion as pf
        raw = mc.build_packet(0x0009, bytes([0x64, 0x5A, 0xD0]), ptype=32) + mc.build_packet(0x0204, bytes([2, 0]), ptype=32)
        frames = pf.parse_frames(raw)
        self.assertEqual([f["opcode"] for f in frames], [0x0009, 0x0204])
        self.assertTrue(all(f["crc_ok"] and f["tail_ok"] for f in frames))
        self.assertIn("case=80%+chg/in-case", pf.decode_hint(0x0009, frames[0]["payload"]))
        self.assertIn("transparency", pf.decode_hint(0x0204, frames[1]["payload"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
