from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import signal
import subprocess
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cryptography.utils import CryptographyDeprecationWarning
from cloudedge import CloudEdgeClient
from cloudedge.exceptions import CloudEdgeError


logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

BACKEND = os.environ.get("BACKEND_INTERNAL", "http://web:8090").rstrip("/")
MEDIAMTX_API = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997").rstrip("/")
PUBLISH_URL = os.environ.get("MEDIAMTX_PUBLISH_URL", "rtsp://mediamtx:8554/czeview-low")
CREDENTIALS_PATH = Path(os.environ.get("CZEVIEW_CREDENTIALS_PATH", "/run/secrets/czeview_credentials"))
TOKEN_PATH = Path(os.environ.get("INTERNAL_TOKEN_PATH", "/run/secrets/zmodo_internal_token"))
SESSION_PATH = Path(os.environ.get("CZEVIEW_SESSION_PATH", "/data/session.json"))
HEALTH_PATH = Path("/run/bridge-health/state")
CAMERA_ID = os.environ.get("CZEVIEW_CAMERA_ID", "czeview")
STREAM_PATH = os.environ.get("CZEVIEW_STREAM_PATH", "czeview-low")
CONTROL_PORT = int(os.environ.get("CZEVIEW_CONTROL_PORT", "8787"))
POLL_SECONDS = 2.0

stop_event = threading.Event()
active_event = threading.Event()
client_lock = threading.RLock()
control_state: dict[str, Any] = {"client": None, "device": None, "ptz_mode": None}
control_server: ThreadingHTTPServer | None = None


def log(state: str, **fields: Any) -> None:
    safe = " ".join(f"{key}={value}" for key, value in fields.items())
    print(f"czeview_bridge={state}" + (f" {safe}" if safe else ""), flush=True)


def load_credentials(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8-sig").strip()
    if raw.startswith("{"):
        values = {str(key): str(value) for key, value in json.loads(raw).items()}
    else:
        values = {}
        for source_line in raw.splitlines():
            line = source_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    required = (
        "CZEVIEW_USEREMAIL",
        "CZEVIEW_PASSWORD",
        "CZEVIEW_COUNTRY_CODE",
        "CZEVIEW_PHONE_CODE",
    )
    if any(not values.get(key) for key in required):
        raise RuntimeError("incomplete-czeview-credentials")
    values.setdefault("CZEVIEW_SOURCE_APP", "141")
    return values


def internal_token() -> str:
    encoded = TOKEN_PATH.read_text(encoding="utf-8").strip()
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))[:32]
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def request_json(path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{BACKEND}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {internal_token()}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def select_device(devices: list[dict[str, Any]], configured_serial: str) -> dict[str, Any]:
    if configured_serial:
        matches = [item for item in devices if str(item.get("serial_number") or "") == configured_serial]
        if len(matches) != 1:
            raise RuntimeError("configured-device-not-found")
        return matches[0]
    if len(devices) != 1:
        raise RuntimeError("device-selection-required")
    return devices[0]


def register_camera(
    device: dict[str, Any],
    credentials: dict[str, str],
    ptz_mode: str | None,
) -> None:
    camera_name = credentials.get("CZEVIEW_CAMERA_NAME") or "CZEview Kamera"
    type_id = str(device.get("type_id") or "unbekannt")
    request_json(
        f"/internal/v1/external-cameras/{CAMERA_ID}",
        "PUT",
        {
            "name": camera_name,
            "path": STREAM_PATH,
            "sourceLabel": "CZEview P2P · bei Bedarf",
            "codec": "h264",
            "manufacturer": "CZEview (Plattformmarke)",
            "model": f"API-Gerätetyp {type_id}",
            "detailQuality": "2304 × 1296 · H.264 (verifiziert)",
            "width": 2304,
            "height": 1296,
            "controlUrl": f"http://czeview-bridge:{CONTROL_PORT}" if ptz_mode else None,
            "ptzAxes": ["x"] if ptz_mode else [],
        },
    )


def detect_ptz_mode(client: CloudEdgeClient, device: dict[str, Any]) -> str | None:
    try:
        with client_lock:
            response = client.get_device_config(str(device["serial_number"]))
    except (CloudEdgeError, OSError, ValueError):
        return None
    if not isinstance(response, dict):
        return None
    iot = response.get("iot")
    if not isinstance(iot, dict):
        result = response.get("result")
        iot = result.get("iot") if isinstance(result, dict) else {}
    if "841" in iot:
        return "ptz2"
    if "807" in iot:
        return "ptz"
    return None


def ptz_parameters(ptz_mode: str, direction: str | None) -> tuple[str, str]:
    if ptz_mode not in {"ptz", "ptz2"}:
        raise ValueError("ptz-not-supported")
    if direction is None:
        return ("842" if ptz_mode == "ptz2" else "808"), "{}"
    vectors = {
        "left": {"ps": -80, "ts": 0, "zs": 0},
        "right": {"ps": 80, "ts": 0, "zs": 0},
    }
    if direction not in vectors:
        raise ValueError("ptz-direction-not-supported")
    return (
        "841" if ptz_mode == "ptz2" else "807",
        json.dumps(vectors[direction], separators=(",", ":")),
    )


def control_ptz(direction: str | None) -> None:
    with client_lock:
        client = control_state["client"]
        device = control_state["device"]
        ptz_mode = control_state["ptz_mode"]
        if not client or not device or not ptz_mode:
            raise RuntimeError("ptz-not-ready")
        code, value = ptz_parameters(ptz_mode, direction)
        client.set_device_config(
            str(device["serial_number"]),
            {code: value},
            auto_wake=direction is not None,
            device_id=device.get("device_id"),
        )


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "PKWS-CZEview-Bridge"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        expected = f"Bearer {internal_token()}"
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            self.send_json(401, {"ok": False, "error": "internal-auth-required"})
            return
        prefix = f"/v1/cameras/{quote(CAMERA_ID, safe='')}/ptz/"
        if not self.path.startswith(prefix):
            self.send_json(404, {"ok": False, "error": "not-found"})
            return
        action = self.path[len(prefix):]
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self.send_json(400, {"ok": False, "error": "invalid-content-length"})
            return
        if length < 0:
            self.send_json(400, {"ok": False, "error": "invalid-content-length"})
            return
        if length > 1024:
            self.send_json(413, {"ok": False, "error": "request-too-large"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("invalid-json-object")
            if action not in {"start", "stop"}:
                raise ValueError("unsupported-action")
            direction = str(body.get("direction") or "") if action == "start" else None
            control_ptz(direction)
        except (CloudEdgeError, OSError, RuntimeError, ValueError):
            self.send_json(409, {"ok": False, "error": "ptz-command-rejected"})
            return
        self.send_json(200, {"ok": True})


def start_control_server() -> None:
    global control_server
    if control_server:
        return
    control_server = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), ControlHandler)
    threading.Thread(target=control_server.serve_forever, daemon=True).start()


def ensure_mediamtx_path() -> None:
    payload = json.dumps({"source": "publisher", "record": False}).encode()
    request = Request(
        f"{MEDIAMTX_API}/v3/config/paths/add/{quote(STREAM_PATH, safe='')}",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=5):
            return
    except HTTPError as error:
        if error.code != 400:
            raise
    verify = Request(f"{MEDIAMTX_API}/v3/config/paths/get/{quote(STREAM_PATH, safe='')}")
    with urlopen(verify, timeout=5) as response:
        configured = json.load(response)
    if configured.get("source") != "publisher":
        raise RuntimeError("mediamtx-path-in-use")


class FfmpegPublisher:
    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.frames = 0
        self.bytes = 0

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        self.stop()
        self.frames = 0
        self.bytes = 0
        self.process = subprocess.Popen(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-fflags",
                "+genpts",
                "-probesize",
                "32",
                "-analyzeduration",
                "0",
                "-re",
                "-f",
                "h264",
                "-framerate",
                "30",
                "-i",
                "pipe:0",
                "-an",
                "-vf",
                "fps=15",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-g",
                "8",
                "-keyint_min",
                "8",
                "-sc_threshold",
                "0",
                "-b:v",
                "2500k",
                "-maxrate",
                "3000k",
                "-bufsize",
                "5000k",
                "-f",
                "rtsp",
                "-rtsp_transport",
                "tcp",
                PUBLISH_URL,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def write(self, data: bytes) -> None:
        if not self.process or self.process.poll() is not None or not self.process.stdin:
            raise BrokenPipeError("publisher-not-running")
        if self.frames == 0 and not data.startswith((b"\x00\x00\x00\x01", b"\x00\x00\x01")):
            raise ValueError("video-is-not-annex-b")
        self.process.stdin.write(data)
        self.process.stdin.flush()
        self.frames += 1
        self.bytes += len(data)

    def stop(self) -> None:
        process, self.process = self.process, None
        if not process:
            return
        if process.stdin:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def lease_poller() -> None:
    previous: bool | None = None
    while not stop_event.is_set():
        try:
            state = request_json(f"/internal/v1/external-cameras/{CAMERA_ID}/lease")
            active = bool(state.get("active"))
            if active:
                active_event.set()
            else:
                active_event.clear()
            if active != previous:
                log("requested" if active else "idle")
                previous = active
        except (OSError, ValueError, HTTPError, URLError):
            log("control_unavailable")
        stop_event.wait(POLL_SECONDS)


def make_client(credentials: dict[str, str]) -> CloudEdgeClient:
    client = CloudEdgeClient(
        credentials["CZEVIEW_USEREMAIL"],
        credentials["CZEVIEW_PASSWORD"],
        credentials["CZEVIEW_COUNTRY_CODE"],
        credentials["CZEVIEW_PHONE_CODE"],
        debug=False,
        session_cache_file=str(SESSION_PATH),
        enable_network_ping=False,
        source_app=credentials["CZEVIEW_SOURCE_APP"],
    )
    client.authenticate()
    return client


def serve(client: CloudEdgeClient, device: dict[str, Any]) -> None:
    publisher = FfmpegPublisher()
    empty_sessions = 0
    try:
        while not stop_event.is_set():
            if not active_event.wait(1):
                publisher.stop()
                continue
            # MediaMTX paths created through its API are runtime state. Reassert the
            # publisher path before every battery-camera session so a MediaMTX
            # restart does not strand an otherwise healthy bridge.
            ensure_mediamtx_path()
            publisher.start()
            holder: dict[str, Any] = {}

            def on_video(data: bytes) -> None:
                streamer = holder.get("streamer")
                if stop_event.is_set() or not active_event.is_set():
                    if streamer:
                        streamer.request_stop()
                    return
                try:
                    publisher.write(data)
                except (BrokenPipeError, OSError, ValueError):
                    if streamer:
                        streamer.request_stop()

            streamer = client.create_streamer(
                device,
                on_video=on_video,
                remote=False,
                video_id=0,
                manage_stream_switch=True,
            )
            holder["streamer"] = streamer
            frame_count, byte_count = streamer.run_session()
            if frame_count:
                empty_sessions = 0
                log("stream_window_complete", frames=frame_count, bytes=byte_count)
            else:
                empty_sessions += 1
                log("stream_retry", attempt=empty_sessions)
                stop_event.wait(min(10, 2 * empty_sessions))
            if not active_event.is_set():
                publisher.stop()
            if empty_sessions >= 3:
                client.get_all_devices()
                empty_sessions = 0
    finally:
        publisher.stop()


def shutdown(*_args: Any) -> None:
    stop_event.set()
    active_event.set()
    if control_server:
        control_server.shutdown()


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    credentials = load_credentials(CREDENTIALS_PATH)
    SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    poller_started = False
    last_cache_reset = -600.0
    while not stop_event.is_set():
        try:
            client = make_client(credentials)
            devices = client.get_all_devices()
            device = select_device(devices, credentials.get("CZEVIEW_DEVICE_SERIAL", ""))
            ptz_mode = detect_ptz_mode(client, device)
            with client_lock:
                control_state.update(client=client, device=device, ptz_mode=ptz_mode)
            ensure_mediamtx_path()
            register_camera(device, credentials, ptz_mode)
            start_control_server()
            HEALTH_PATH.write_text(str(int(time.time())), encoding="ascii")
            log("authenticated", devices=len(devices), ptz="horizontal" if ptz_mode else "none")
            if not poller_started:
                threading.Thread(target=lease_poller, daemon=True).start()
                poller_started = True
            serve(client, device)
            return
        except CloudEdgeError as error:
            log("degraded", reason=type(error).__name__)
            if time.monotonic() - last_cache_reset >= 600:
                SESSION_PATH.unlink(missing_ok=True)
                last_cache_reset = time.monotonic()
            stop_event.wait(30)
        except (OSError, ValueError, RuntimeError, HTTPError, URLError) as error:
            log("degraded", reason=type(error).__name__)
            stop_event.wait(30)


if __name__ == "__main__":
    main()
