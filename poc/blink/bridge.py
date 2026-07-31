"""Battery-safe Blink cloud adapter for Camera Hub.

The adapter keeps Blink credentials and tokens in Camera Hub's encrypted database.
It performs metadata refreshes no faster than once per minute. Media and live-view
requests are only executed in response to an authenticated Camera Hub request or
an active interactive lease.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import aiohttp
from aiohttp import web
from blinkpy.auth import Auth, BlinkTwoFARequiredError
from blinkpy.blinkpy import Blink
from blinkpy.camera import BlinkCamera
from blinkpy.livestream import BlinkLiveStream

BACKEND_INTERNAL = os.environ.get("BACKEND_INTERNAL", "http://web:8090").rstrip("/")
MEDIAMTX_API = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997").rstrip("/")
MEDIAMTX_PUBLISH = os.environ.get("MEDIAMTX_PUBLISH", "rtsp://mediamtx:8554").rstrip(
    "/"
)
TOKEN_PATH = Path(
    os.environ.get("BLINK_ADAPTER_TOKEN_PATH", "/run/secrets/blink_adapter_token")
)
HEALTH_PATH = Path(os.environ.get("BLINK_HEALTH_PATH", "/run/bridge-health/state"))
POLL_SECONDS = max(2, int(os.environ.get("BLINK_LEASE_POLL_SECONDS", "2")))
REFRESH_SECONDS = max(60, int(os.environ.get("BLINK_REFRESH_SECONDS", "60")))
LIVE_MAX_SECONDS = 5 * 60
THUMBNAIL_MAX_BYTES = 4 * 1024 * 1024
CLIP_MAX_BYTES = 128 * 1024 * 1024
SAFE_PATH = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s blink-bridge %(message)s",
)
LOG = logging.getLogger("blink-bridge")


def read_secret() -> str:
    encoded = TOKEN_PATH.read_text(encoding="utf-8").strip()
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))[:32]
    except ValueError as error:
        raise RuntimeError("blink adapter token is invalid") from error
    if len(raw) < 32:
        raise RuntimeError("blink adapter token is missing or too short")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ADAPTER_TOKEN = read_secret()


async def passive_get_media(_camera: BlinkCamera, media_type: str = "image"):
    """Prevent BlinkPy metadata refresh from downloading image/video bodies."""
    del media_type
    return None


async def passive_expire_recent_clips(
    camera: BlinkCamera, delta: dt.timedelta = dt.timedelta(hours=1)
):
    """Prune cached metadata without asking a Sync Module to upload a clip."""
    cutoff = (dt.datetime.now() - delta).timestamp()
    camera.recent_clips = [
        clip
        for clip in camera.recent_clips
        if dt.datetime.fromisoformat(clip["time"]).timestamp() > cutoff
    ]


async def verified_live_auth(live: BlinkLiveStream):
    """BlinkPy 0.25.9 disables TLS validation here; keep normal validation."""
    context = ssl.create_default_context()
    live.target_reader, live.target_writer = await asyncio.open_connection(
        live.target.hostname,
        live.target.port,
        ssl=context,
        server_hostname=live.target.hostname,
    )
    live.target_writer.write(live.get_auth_header())
    await live.target_writer.drain()


# These patches intentionally affect only this isolated adapter process.
BlinkCamera.get_media = passive_get_media
BlinkCamera.expire_recent_clips = passive_expire_recent_clips
BlinkLiveStream.auth = verified_live_auth


@dataclass
class AccountSession:
    account_id: str
    revision: int
    client: aiohttp.ClientSession
    blink: Blink
    pending_2fa: bool = False
    last_refresh: float = 0
    devices: dict[str, BlinkCamera] = field(default_factory=dict)
    external_ids: dict[str, str] = field(default_factory=dict)
    clip_urls: dict[tuple[str, str], str] = field(default_factory=dict)
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class LiveSession:
    device_id: str
    account_id: str
    camera_id: str
    path: str
    started: float
    live: BlinkLiveStream
    feed_task: asyncio.Task
    ffmpeg: asyncio.subprocess.Process


class Bridge:
    def __init__(self) -> None:
        timeout = aiohttp.ClientTimeout(total=30, connect=8)
        self.http = aiohttp.ClientSession(timeout=timeout, raise_for_status=False)
        self.accounts: dict[str, AccountSession] = {}
        self.live: dict[str, LiveSession] = {}
        self.lease_attempted: set[str] = set()
        self.lock = asyncio.Lock()

    @property
    def backend_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {ADAPTER_TOKEN}",
            "Content-Type": "application/json",
        }

    async def backend_json(
        self, method: str, path: str, payload: dict | None = None
    ) -> dict:
        async with self.http.request(
            method,
            f"{BACKEND_INTERNAL}{path}",
            headers=self.backend_headers,
            json=payload,
        ) as response:
            data = await response.json(content_type=None)
            if response.status >= 400:
                raise RuntimeError(
                    str(data.get("detail") or f"backend-{response.status}")
                )
            return data

    async def account_record(self, account_id: str) -> dict:
        data = await self.backend_json("GET", "/internal/v1/providers/blink/accounts")
        for account in data.get("accounts", []):
            if account.get("id") == account_id:
                return account
        raise web.HTTPNotFound(text=json.dumps({"error": "blink-account-not-found"}))

    async def report_auth(
        self,
        account_id: str,
        status: str,
        *,
        error: str | None = None,
        auth_data: dict | None = None,
    ) -> None:
        payload: dict[str, Any] = {"status": status, "errorCode": error}
        if auth_data is not None:
            payload["authData"] = {
                key: value
                for key, value in auth_data.items()
                if key
                in {
                    "username",
                    "password",
                    "token",
                    "refresh_token",
                    "expires_in",
                    "expiration_date",
                    "host",
                    "region_id",
                    "client_id",
                    "account_id",
                    "user_id",
                    "hardware_id",
                }
            }
        await self.backend_json(
            "POST",
            f"/internal/v1/providers/blink/accounts/{quote(account_id, safe='')}/auth-state",
            payload,
        )

    async def close_account(self, account_id: str) -> None:
        for device_id, live in list(self.live.items()):
            if live.account_id == account_id:
                await self.stop_live(device_id)
        current = self.accounts.pop(account_id, None)
        if current:
            await current.client.close()

    async def login(self, account_id: str, reconnect: bool = False) -> dict:
        async with self.lock:
            record = await self.account_record(account_id)
            current = self.accounts.get(account_id)
            if (
                current
                and current.revision == int(record["authRevision"])
                and not reconnect
                and not current.pending_2fa
            ):
                return {"state": "active"}
            await self.close_account(account_id)
            credentials = dict(record.get("credentials") or {})
            client = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=45, connect=10)
            )
            blink = Blink(refresh_rate=REFRESH_SECONDS, session=client)
            blink.auth = Auth(credentials, no_prompt=True, session=client)
            session = AccountSession(
                account_id=account_id,
                revision=int(record["authRevision"]),
                client=client,
                blink=blink,
            )
            blink.auth.callback = lambda: asyncio.create_task(
                self.report_auth(
                    account_id,
                    "active",
                    auth_data=blink.auth.login_attributes,
                )
            )
            self.accounts[account_id] = session
            try:
                async with session.operation_lock:
                    started = await blink.start()
                    if not started:
                        raise RuntimeError("blink-login-failed")
            except BlinkTwoFARequiredError:
                session.pending_2fa = True
                await self.report_auth(
                    account_id, "pending", error="blink-verification-required"
                )
                return {"state": "verification-required"}
            except Exception:
                LOG.exception("Blink login failed for account %s", account_id)
                await self.report_auth(account_id, "error", error="blink-login-failed")
                await self.close_account(account_id)
                return {"state": "error", "errorCode": "blink-login-failed"}
            await self.after_login(session)
            return {"state": "active"}

    async def verify(self, account_id: str, code: str) -> dict:
        async with self.lock:
            session = self.accounts.get(account_id)
            if not session or not session.pending_2fa:
                raise web.HTTPConflict(
                    text=json.dumps({"error": "blink-verification-session-missing"})
                )
            try:
                async with session.operation_lock:
                    success = await session.blink.send_2fa_code(code)
                    if not success:
                        raise RuntimeError("blink-verification-failed")
            except Exception:
                LOG.warning("Blink verification failed for account %s", account_id)
                await self.report_auth(
                    account_id, "pending", error="blink-verification-failed"
                )
                return {
                    "state": "verification-required",
                    "errorCode": "blink-verification-failed",
                }
            session.pending_2fa = False
            await self.after_login(session)
            return {"state": "active"}

    async def after_login(self, session: AccountSession) -> None:
        session.last_refresh = time.monotonic()
        await self.report_auth(
            session.account_id,
            "active",
            auth_data=session.blink.auth.login_attributes,
        )
        await self.publish_inventory(session)

    @staticmethod
    def camera_external_id(camera: BlinkCamera) -> str:
        return f"{camera.network_id}:{camera.camera_id}"

    async def publish_inventory(self, session: AccountSession) -> None:
        devices = []
        cameras_by_external: dict[str, BlinkCamera] = {}
        for name, camera in session.blink.cameras.items():
            external = self.camera_external_id(camera)
            cameras_by_external[external] = camera
            sync = getattr(camera, "sync", None)
            thumbnail = bool(getattr(camera, "thumbnail", None))
            devices.append(
                {
                    "externalId": external,
                    "homeId": str(getattr(camera, "network_id", "") or ""),
                    "name": str(getattr(camera, "name", None) or name),
                    "model": str(
                        getattr(camera, "product_type", None)
                        or getattr(camera, "camera_type", None)
                        or camera.__class__.__name__
                    ),
                    "manufacturer": "Blink",
                    "capabilities": {
                        "cachedThumbnail": thumbnail,
                        "clips": True,
                        "liveCandidate": True,
                        "explicitLiveOnly": True,
                        "liveMaxSeconds": LIVE_MAX_SECONDS,
                        "syncModule": str(getattr(sync, "name", "") or ""),
                        "battery": getattr(camera, "battery", None),
                        "online": getattr(camera, "status", None),
                    },
                    "streamSupport": "candidate",
                }
            )
        result = await self.backend_json(
            "POST",
            "/internal/v1/providers/blink/inventory",
            {
                "accountId": session.account_id,
                "status": "active",
                "devices": devices,
            },
        )
        session.devices.clear()
        session.external_ids.clear()
        for mapping in result.get("devices", []):
            camera = cameras_by_external.get(mapping.get("externalId"))
            if camera:
                session.devices[mapping["deviceId"]] = camera
                session.external_ids[mapping["deviceId"]] = mapping["externalId"]

    def find_device(self, device_id: str) -> tuple[AccountSession, BlinkCamera]:
        for session in self.accounts.values():
            camera = session.devices.get(device_id)
            if camera:
                return session, camera
        raise web.HTTPNotFound(text=json.dumps({"error": "blink-device-not-found"}))

    async def refresh_account(self, account_id: str, force: bool = False) -> dict:
        session = self.accounts.get(account_id)
        if not session:
            result = await self.login(account_id)
            if result["state"] != "active":
                return result
            session = self.accounts[account_id]
        if session.pending_2fa:
            return {"state": "verification-required"}
        elapsed = time.monotonic() - session.last_refresh
        if not force and elapsed < REFRESH_SECONDS:
            return {"state": "active", "throttled": True}
        try:
            async with session.operation_lock:
                refreshed = await session.blink.refresh(force=False)
                session.last_refresh = time.monotonic()
                await self.report_auth(
                    account_id,
                    "active",
                    auth_data=session.blink.auth.login_attributes,
                )
                await self.publish_inventory(session)
            return {"state": "active", "refreshed": bool(refreshed)}
        except Exception:
            LOG.exception("Blink metadata refresh failed for account %s", account_id)
            await self.report_auth(
                account_id, "reauth-required", error="blink-refresh-failed"
            )
            return {"state": "reauth-required", "errorCode": "blink-refresh-failed"}

    @staticmethod
    async def response_bytes(
        response: aiohttp.ClientResponse | None, maximum: int
    ) -> bytes:
        if response is None or response.status != 200:
            raise web.HTTPBadGateway(
                text=json.dumps({"error": "blink-media-unavailable"})
            )
        if response.content_length and response.content_length > maximum:
            response.close()
            raise web.HTTPRequestEntityTooLarge(
                max_size=maximum, actual_size=response.content_length
            )
        chunks, total = [], 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > maximum:
                response.close()
                raise web.HTTPRequestEntityTooLarge(max_size=maximum, actual_size=total)
            chunks.append(chunk)
        response.release()
        return b"".join(chunks)

    async def thumbnail(self, device_id: str) -> bytes:
        session, camera = self.find_device(device_id)
        async with session.operation_lock:
            data = await self.response_bytes(
                await camera.get_thumbnail(), THUMBNAIL_MAX_BYTES
            )
        if not data.startswith(b"\xff\xd8"):
            raise web.HTTPBadGateway(
                text=json.dumps({"error": "blink-thumbnail-invalid"})
            )
        return data

    def clips(self, device_id: str) -> list[dict]:
        session, camera = self.find_device(device_id)
        result = []
        for clip in list(camera.recent_clips)[-50:][::-1]:
            url = str(clip.get("clip") or "")
            if not url.startswith("https://"):
                continue
            token = hashlib.sha256(f"{device_id}\0{url}".encode("utf-8")).hexdigest()[
                :32
            ]
            session.clip_urls[(device_id, token)] = url
            result.append(
                {
                    "id": token,
                    "createdAt": clip.get("time"),
                    "cameraName": camera.name,
                }
            )
        return result

    async def clip(self, device_id: str, token: str) -> bytes:
        session, camera = self.find_device(device_id)
        url = session.clip_urls.get((device_id, token))
        if not url:
            self.clips(device_id)
            url = session.clip_urls.get((device_id, token))
        if not url:
            raise web.HTTPNotFound(text=json.dumps({"error": "blink-clip-not-found"}))
        async with session.operation_lock:
            data = await self.response_bytes(
                await camera.get_video_clip(url), CLIP_MAX_BYTES
            )
        if len(data) < 12 or b"ftyp" not in data[:32]:
            raise web.HTTPBadGateway(text=json.dumps({"error": "blink-clip-invalid"}))
        return data

    async def ensure_mediamtx_path(self, path: str) -> None:
        if not SAFE_PATH.fullmatch(path):
            raise RuntimeError("blink-path-invalid")
        url = f"{MEDIAMTX_API}/v3/config/paths/add/{quote(path, safe='')}"
        async with self.http.post(
            url,
            json={"source": "publisher", "record": False},
        ) as response:
            if response.status in {200, 204}:
                return
            if response.status != 400:
                raise RuntimeError(f"mediamtx-path-{response.status}")
        async with self.http.get(
            f"{MEDIAMTX_API}/v3/config/paths/get/{quote(path, safe='')}"
        ) as response:
            configured = await response.json(content_type=None)
            if response.status != 200 or configured.get("source") != "publisher":
                raise RuntimeError("mediamtx-path-in-use")

    async def start_live(self, lease: dict) -> None:
        device_id = lease["deviceId"]
        if device_id in self.live:
            return
        session, camera = self.find_device(device_id)
        if any(item.account_id == session.account_id for item in self.live.values()):
            return
        path = str(lease["path"])
        await self.ensure_mediamtx_path(path)
        async with session.operation_lock:
            live = await camera.init_livestream()
        await live.start("127.0.0.1", 0)
        feed_task = asyncio.create_task(live.feed())
        ffmpeg = await asyncio.create_subprocess_exec(
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "warning",
            "-f",
            "mpegts",
            "-i",
            live.url,
            "-map",
            "0:v:0",
            "-an",
            "-c:v",
            "copy",
            "-f",
            "rtsp",
            "-rtsp_transport",
            "tcp",
            f"{MEDIAMTX_PUBLISH}/{path}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self.live[device_id] = LiveSession(
            device_id=device_id,
            account_id=session.account_id,
            camera_id=str(lease["cameraId"]),
            path=path,
            started=time.monotonic(),
            live=live,
            feed_task=feed_task,
            ffmpeg=ffmpeg,
        )
        LOG.info("Started explicit Blink live session for device %s", device_id)

    async def stop_live(self, device_id: str) -> None:
        current = self.live.pop(device_id, None)
        if not current:
            return
        current.live.stop()
        current.feed_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await current.feed_task
        if current.ffmpeg.returncode is None:
            current.ffmpeg.terminate()
            try:
                await asyncio.wait_for(current.ffmpeg.wait(), 5)
            except asyncio.TimeoutError:
                current.ffmpeg.kill()
                await current.ffmpeg.wait()
        LOG.info("Stopped Blink live session for device %s", device_id)

    async def lease_loop(self) -> None:
        while True:
            try:
                payload = await self.backend_json(
                    "GET", "/internal/v1/providers/blink/leases"
                )
                leases = {
                    item["deviceId"]: item
                    for item in payload.get("cameras", [])
                    if item.get("active")
                }
                self.lease_attempted.intersection_update(leases)
                for device_id, current in list(self.live.items()):
                    if (
                        device_id not in leases
                        or time.monotonic() - current.started >= LIVE_MAX_SECONDS
                        or current.ffmpeg.returncode is not None
                        or current.feed_task.done()
                    ):
                        await self.stop_live(device_id)
                for device_id, lease in leases.items():
                    if (
                        device_id not in self.live
                        and device_id not in self.lease_attempted
                    ):
                        # Exactly one cloud wake attempt per contiguous lease period.
                        # A new user click after releasing the lease permits a new try.
                        self.lease_attempted.add(device_id)
                        try:
                            await self.start_live(lease)
                        except Exception:
                            LOG.exception(
                                "Could not start Blink live session for device %s",
                                device_id,
                            )
                HEALTH_PATH.parent.mkdir(parents=True, exist_ok=True)
                HEALTH_PATH.write_text(str(int(time.time())), encoding="ascii")
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("Blink lease poll failed")
            await asyncio.sleep(POLL_SECONDS)

    async def account_loop(self) -> None:
        while True:
            try:
                records = await self.backend_json(
                    "GET", "/internal/v1/providers/blink/accounts"
                )
                enabled = {item["id"]: item for item in records.get("accounts", [])}
                for account_id in list(self.accounts):
                    session = self.accounts[account_id]
                    record = enabled.get(account_id)
                    if not record or int(record["authRevision"]) != session.revision:
                        await self.close_account(account_id)
                for account_id, record in enabled.items():
                    if record.get("status") == "pending":
                        continue
                    if account_id not in self.accounts:
                        await self.login(account_id)
                    elif not self.accounts[account_id].pending_2fa:
                        await self.refresh_account(account_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("Blink account refresh loop failed")
            await asyncio.sleep(REFRESH_SECONDS)

    async def close(self) -> None:
        for device_id in list(self.live):
            await self.stop_live(device_id)
        for account_id in list(self.accounts):
            await self.close_account(account_id)
        await self.http.close()


BRIDGE: Bridge | None = None


@web.middleware
async def authenticated(request: web.Request, handler):
    expected = f"Bearer {ADAPTER_TOKEN}"
    if not hmac.compare_digest(request.headers.get("Authorization", ""), expected):
        raise web.HTTPUnauthorized(
            text=json.dumps({"error": "blink-adapter-auth-required"}),
            content_type="application/json",
        )
    return await handler(request)


def bridge(request: web.Request) -> Bridge:
    return request.app["bridge"]


async def login_handler(request: web.Request) -> web.Response:
    result = await bridge(request).login(request.match_info["account_id"])
    return web.json_response(result)


async def reconnect_handler(request: web.Request) -> web.Response:
    result = await bridge(request).login(
        request.match_info["account_id"], reconnect=True
    )
    return web.json_response(result)


async def verify_handler(request: web.Request) -> web.Response:
    body = await request.json()
    code = str(body.get("code") or "")
    if not re.fullmatch(r"[A-Za-z0-9]{4,12}", code):
        raise web.HTTPUnprocessableEntity(
            text=json.dumps({"error": "blink-verification-code-invalid"})
        )
    result = await bridge(request).verify(request.match_info["account_id"], code)
    return web.json_response(result)


async def refresh_handler(request: web.Request) -> web.Response:
    result = await bridge(request).refresh_account(request.match_info["account_id"])
    return web.json_response(result)


async def thumbnail_handler(request: web.Request) -> web.Response:
    data = await bridge(request).thumbnail(request.match_info["device_id"])
    return web.Response(
        body=data,
        content_type="image/jpeg",
        headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
    )


async def clips_handler(request: web.Request) -> web.Response:
    return web.json_response(
        {"clips": bridge(request).clips(request.match_info["device_id"])}
    )


async def clip_handler(request: web.Request) -> web.Response:
    data = await bridge(request).clip(
        request.match_info["device_id"], request.match_info["clip_id"]
    )
    return web.Response(
        body=data,
        content_type="video/mp4",
        headers={"Cache-Control": "no-store, private", "Accept-Ranges": "none"},
    )


async def start_app() -> web.Application:
    global BRIDGE
    BRIDGE = Bridge()
    app = web.Application(middlewares=[authenticated], client_max_size=32 * 1024)
    app["bridge"] = BRIDGE
    app.add_routes(
        [
            web.post("/internal/v1/accounts/{account_id}/login", login_handler),
            web.post("/internal/v1/accounts/{account_id}/reconnect", reconnect_handler),
            web.post("/internal/v1/accounts/{account_id}/verify", verify_handler),
            web.post("/internal/v1/accounts/{account_id}/refresh", refresh_handler),
            web.get("/internal/v1/devices/{device_id}/thumbnail", thumbnail_handler),
            web.get("/internal/v1/devices/{device_id}/clips", clips_handler),
            web.get("/internal/v1/devices/{device_id}/clips/{clip_id}", clip_handler),
        ]
    )
    app["tasks"] = [
        asyncio.create_task(BRIDGE.lease_loop()),
        asyncio.create_task(BRIDGE.account_loop()),
    ]
    app.on_cleanup.append(cleanup)
    return app


async def cleanup(app: web.Application) -> None:
    for task in app.get("tasks", []):
        task.cancel()
    for task in app.get("tasks", []):
        with contextlib.suppress(asyncio.CancelledError):
            await task
    await app["bridge"].close()


if __name__ == "__main__":
    web.run_app(start_app(), host="0.0.0.0", port=8788, print=None)
