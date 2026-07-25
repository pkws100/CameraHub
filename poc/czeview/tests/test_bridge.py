from __future__ import annotations

import json
import unittest

import bridge


class FakeClient:
    def __init__(self, iot):
        self.iot = iot

    def get_device_config(self, _serial):
        return {"code": 100001, "action": "get", "name": "iot", "iot": self.iot}


class BridgeTests(unittest.TestCase):
    def test_detects_ptz2_before_legacy_ptz(self):
        device = {"serial_number": "redacted"}
        self.assertEqual(bridge.detect_ptz_mode(FakeClient({"807": None, "841": None}), device), "ptz2")
        self.assertEqual(bridge.detect_ptz_mode(FakeClient({"807": None}), device), "ptz")
        self.assertIsNone(bridge.detect_ptz_mode(FakeClient({}), device))

    def test_horizontal_ptz_commands_are_bounded(self):
        code, value = bridge.ptz_parameters("ptz2", "left")
        self.assertEqual(code, "841")
        self.assertEqual(json.loads(value), {"ps": -80, "ts": 0, "zs": 0})
        self.assertEqual(bridge.ptz_parameters("ptz2", None), ("842", "{}"))
        with self.assertRaises(ValueError):
            bridge.ptz_parameters("ptz2", "up")

    def test_legacy_ptz_codes_remain_supported(self):
        self.assertEqual(bridge.ptz_parameters("ptz", None), ("808", "{}"))
        code, value = bridge.ptz_parameters("ptz", "right")
        self.assertEqual(code, "807")
        self.assertEqual(json.loads(value)["ps"], 80)


if __name__ == "__main__":
    unittest.main()
