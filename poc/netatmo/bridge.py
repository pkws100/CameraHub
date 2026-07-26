from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


BACKEND = os.environ.get("BACKEND_INTERNAL", "http://web:8090").rstrip("/")
MEDIAMTX_API = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997").rstrip("/")
TOKEN_PATH = Path(os.environ.get("NETATMO_ADAPTER_TOKEN_PATH", "/run/secrets/netatmo_adapter_token"))
HEALTH_PATH = Path("/run/bridge-health/state")
POLL_SECONDS = 2.0
stop_event = threading.Event()


def adapter_token() -> str:
    encoded = TOKEN_PATH.read_text(encoding="utf-8").strip()
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))[:32]
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def request_streams() -> list[dict[str, Any]]:
    request = Request(
        f"{BACKEND}/internal/v1/providers/netatmo/streams",
        headers={"Authorization": f"Bearer {adapter_token()}", "Accept": "application/json"},
    )
    with urlopen(request, timeout=20) as response:
        return json.load(response).get("cameras", [])


def ensure_path(path: str) -> None:
    payload = json.dumps({"source": "publisher", "record": False}).encode()
    request = Request(
        f"{MEDIAMTX_API}/v3/config/paths/add/{quote(path, safe='')}",
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
    with urlopen(
        Request(f"{MEDIAMTX_API}/v3/config/paths/get/{quote(path, safe='')}"),
        timeout=5,
    ) as response:
        if json.load(response).get("source") != "publisher":
            raise RuntimeError("mediamtx-path-in-use")


class StreamProcess:
    def __init__(self, camera: dict[str, Any]) -> None:
        self.camera = camera
        self.process: subprocess.Popen[bytes] | None = None
        self.candidate_index = 0

    def start(self) -> None:
        candidates = self.camera.get("streamCandidates") or []
        if not candidates:
            return
        self.stop()
        ensure_path(str(self.camera["path"]))
        source = str(candidates[self.candidate_index % len(candidates)])
        self.candidate_index += 1
        self.process = subprocess.Popen(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-rw_timeout",
                "15000000",
                "-i",
                source,
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-tune",
                "zerolatency",
                "-g",
                "30",
                "-keyint_min",
                "30",
                "-sc_threshold",
                "0",
                "-f",
                "rtsp",
                "-rtsp_transport",
                "tcp",
                f"rtsp://mediamtx:8554/{self.camera['path']}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def update(self, camera: dict[str, Any]) -> None:
        changed = (
            camera.get("path") != self.camera.get("path")
            or camera.get("streamCandidates") != self.camera.get("streamCandidates")
        )
        self.camera = camera
        if changed:
            self.start()
        elif not self.process or self.process.poll() is not None:
            self.start()

    def stop(self) -> None:
        process, self.process = self.process, None
        if not process or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def shutdown(*_args: Any) -> None:
    stop_event.set()


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    streams: dict[str, StreamProcess] = {}
    while not stop_event.is_set():
        try:
            desired = {
                str(camera["cameraId"]): camera
                for camera in request_streams()
                if camera.get("active") and camera.get("streamCandidates")
            }
            for camera_id in list(streams):
                if camera_id not in desired:
                    streams.pop(camera_id).stop()
            for camera_id, camera in desired.items():
                if camera_id not in streams:
                    streams[camera_id] = StreamProcess(camera)
                    streams[camera_id].start()
                else:
                    streams[camera_id].update(camera)
            HEALTH_PATH.write_text(str(int(time.time())), encoding="ascii")
        except (OSError, ValueError, RuntimeError, HTTPError, URLError):
            pass
        stop_event.wait(POLL_SECONDS)
    for stream in streams.values():
        stream.stop()


if __name__ == "__main__":
    main()
