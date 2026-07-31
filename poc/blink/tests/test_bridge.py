from __future__ import annotations

import asyncio
import base64
import datetime as dt
import importlib
import os
import ssl
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


TEMP = tempfile.TemporaryDirectory(prefix="blink-bridge-test-")
TOKEN_PATH = Path(TEMP.name) / "token"
TOKEN_PATH.write_text(base64.urlsafe_b64encode(b"b" * 32).decode(), encoding="utf-8")
os.environ["BLINK_ADAPTER_TOKEN_PATH"] = str(TOKEN_PATH)
os.environ["BACKEND_INTERNAL"] = "http://127.0.0.1:9"
os.environ["MEDIAMTX_API"] = "http://127.0.0.1:9"

bridge_module = importlib.import_module("bridge")


class FakeResponse:
    def __init__(self, data: bytes, status: int = 200):
        self.status = status
        self.content_length = len(data)
        self.content = self
        self._data = data
        self.closed = False

    async def iter_chunked(self, _size):
        yield self._data

    def close(self):
        self.closed = True

    def release(self):
        self.closed = True


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bridge = bridge_module.Bridge()

    async def asyncTearDown(self):
        await self.bridge.close()

    async def test_service_token_is_normalized_like_backend(self):
        self.assertEqual(
            bridge_module.ADAPTER_TOKEN,
            base64.urlsafe_b64encode(b"b" * 32).decode().rstrip("="),
        )

    async def test_passive_refresh_never_downloads_media_or_uploads_local_clips(self):
        camera = types.SimpleNamespace(
            recent_clips=[
                {
                    "time": (dt.datetime.now() - dt.timedelta(minutes=5)).isoformat(),
                    "clip": "https://example.invalid/local_storage/clip",
                },
                {
                    "time": (dt.datetime.now() - dt.timedelta(hours=2)).isoformat(),
                    "clip": "https://example.invalid/expired",
                },
            ]
        )
        self.assertIsNone(await bridge_module.passive_get_media(camera))
        await bridge_module.passive_expire_recent_clips(camera)
        self.assertEqual(len(camera.recent_clips), 1)

    async def test_inventory_is_metadata_only_and_maps_backend_ids(self):
        camera = types.SimpleNamespace(
            network_id=21,
            camera_id=7,
            name="Einfahrt",
            product_type="catalina",
            camera_type="camera",
            thumbnail="https://rest.example/thumbnail.jpg",
            battery="ok",
            status="online",
            sync=types.SimpleNamespace(name="Sync Module"),
        )
        blink = types.SimpleNamespace(cameras={"Einfahrt": camera})
        session = bridge_module.AccountSession(
            account_id="account-1",
            revision=1,
            client=AsyncMock(),
            blink=blink,
        )
        observed = {}

        async def backend_json(method, path, payload=None):
            observed.update(method=method, path=path, payload=payload)
            return {"devices": [{"externalId": "21:7", "deviceId": "device-1"}]}

        self.bridge.backend_json = backend_json
        await self.bridge.publish_inventory(session)
        self.assertEqual(observed["method"], "POST")
        device = observed["payload"]["devices"][0]
        self.assertTrue(device["capabilities"]["explicitLiveOnly"])
        self.assertEqual(device["capabilities"]["liveMaxSeconds"], 300)
        self.assertEqual(device["streamSupport"], "candidate")
        self.assertIs(session.devices["device-1"], camera)

    async def test_thumbnail_requires_explicit_call_and_valid_jpeg(self):
        camera = types.SimpleNamespace(
            get_thumbnail=AsyncMock(
                return_value=FakeResponse(b"\xff\xd8cached-thumbnail\xff\xd9")
            )
        )
        session = types.SimpleNamespace(
            devices={"device-1": camera},
            client=AsyncMock(),
            operation_lock=asyncio.Lock(),
        )
        self.bridge.accounts = {"account-1": session}
        data = await self.bridge.thumbnail("device-1")
        self.assertTrue(data.startswith(b"\xff\xd8"))
        camera.get_thumbnail.assert_awaited_once()

    async def test_verified_livestream_tls_keeps_certificate_validation(self):
        writer = types.SimpleNamespace(
            write=unittest.mock.Mock(),
            drain=AsyncMock(),
        )
        live = types.SimpleNamespace(
            target=types.SimpleNamespace(hostname="example.invalid", port=443),
            get_auth_header=lambda: b"auth",
        )
        open_connection = AsyncMock(return_value=("reader", writer))
        with patch.object(asyncio, "open_connection", open_connection):
            await bridge_module.verified_live_auth(live)
        kwargs = open_connection.await_args.kwargs
        self.assertEqual(kwargs["server_hostname"], "example.invalid")
        self.assertEqual(kwargs["ssl"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs["ssl"].check_hostname)

    async def test_media_limit_rejects_oversized_response_before_read(self):
        response = FakeResponse(b"x" * 20)
        with self.assertRaises(bridge_module.web.HTTPRequestEntityTooLarge):
            await self.bridge.response_bytes(response, 10)
        self.assertTrue(response.closed)

    async def test_failed_live_start_is_attempted_once_per_contiguous_lease(self):
        lease = {
            "cameraId": "camera-1",
            "deviceId": "device-1",
            "accountId": "account-1",
            "path": "blink-camera-1-low",
            "active": True,
        }
        payloads = [
            {"cameras": [lease]},
            {"cameras": [lease]},
            {"cameras": []},
            {"cameras": [lease]},
        ]

        async def backend_json(*_args, **_kwargs):
            return payloads.pop(0)

        self.bridge.backend_json = backend_json
        self.bridge.start_live = AsyncMock(side_effect=RuntimeError("test failure"))
        bridge_module.HEALTH_PATH = Path(TEMP.name) / "health"
        sleeps = 0

        async def controlled_sleep(_seconds):
            nonlocal sleeps
            sleeps += 1
            if sleeps >= 4:
                raise asyncio.CancelledError

        with patch.object(asyncio, "sleep", controlled_sleep):
            with self.assertRaises(asyncio.CancelledError):
                await self.bridge.lease_loop()
        self.assertEqual(self.bridge.start_live.await_count, 2)


if __name__ == "__main__":
    unittest.main()
