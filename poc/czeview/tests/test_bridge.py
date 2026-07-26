from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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

    def test_inventory_timestamp_does_not_replace_auth_revision(self):
        with bridge.runtime_lock:
            bridge.enabled_account_ids.add("account")
            bridge.account_versions["account"] = "7"
        try:
            self.assertTrue(bridge.account_current("account", "7"))
            self.assertFalse(bridge.account_current("account", "8"))
        finally:
            with bridge.runtime_lock:
                bridge.enabled_account_ids.discard("account")
                bridge.account_versions.pop("account", None)

    def test_legacy_session_is_reused_for_imported_account(self):
        original_session_path = bridge.SESSION_PATH
        with tempfile.TemporaryDirectory() as directory:
            bridge.SESSION_PATH = Path(directory) / "session.json"
            bridge.SESSION_PATH.write_text(
                json.dumps({"userToken": "test-token", "loginTime": 1}),
                encoding="utf-8",
            )
            try:
                bridge.migrate_legacy_session("account-id")
                migrated = json.loads(
                    (Path(directory) / "accounts" / "account-id.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(migrated["userToken"], "test-token")
            finally:
                bridge.SESSION_PATH = original_session_path

    def test_session_diagnostic_never_returns_token_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            path.write_text(
                json.dumps({"userToken": "must-not-leak", "loginTime": 1}),
                encoding="utf-8",
            )
            state, age = bridge.session_cache_diagnostic(path)
            self.assertEqual(state, "expired")
            self.assertIsInstance(age, float)

    def test_session_reset_requires_auth_error_or_three_failures(self):
        temporary = bridge.CloudEdgeError("temporary")
        authentication = bridge.AuthenticationError("invalid")
        ready = bridge.SESSION_RESET_COOLDOWN
        self.assertFalse(bridge.session_reset_needed(temporary, 1, ready))
        self.assertFalse(bridge.session_reset_needed(temporary, 2, ready))
        self.assertTrue(bridge.session_reset_needed(temporary, 3, ready))
        self.assertTrue(bridge.session_reset_needed(authentication, 1, ready))
        self.assertFalse(
            bridge.session_reset_needed(authentication, 1, ready - 1)
        )


if __name__ == "__main__":
    unittest.main()
