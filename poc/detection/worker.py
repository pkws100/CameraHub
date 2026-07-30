from __future__ import annotations

import base64
import json
import os
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import cv2
import numpy as np

from detector import MotionEngine


BACKEND = os.environ.get("BACKEND_INTERNAL", "http://web:8090").rstrip("/")
TOKEN_PATH = Path(
    os.environ.get("DETECTION_ADAPTER_TOKEN_PATH", "/run/secrets/detection_adapter_token")
)
HEALTH_PATH = Path("/run/detection-health/worker")
POLL_SECONDS = float(os.environ.get("DETECTION_POLL_SECONDS", "5"))
stop_event = threading.Event()


def log(event: str, **fields: Any) -> None:
    safe = " ".join(f"{key}={value}" for key, value in fields.items())
    print(f"detection_worker={event}" + (f" {safe}" if safe else ""), flush=True)


def load_token() -> str:
    raw = TOKEN_PATH.read_text(encoding="utf-8").strip()
    decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(decoded) < 32:
        raise RuntimeError("detection-adapter-token-too-short")
    return base64.urlsafe_b64encode(decoded[:32]).decode().rstrip("=")


class BackendClient:
    def __init__(self) -> None:
        self.token = load_token()
        self.pending: queue.Queue[tuple[dict[str, Any], bytes | None]] = queue.Queue(maxsize=1000)
        self.last_error: str | None = None

    def request(
        self, path: str, *, method: str = "GET", payload: dict | None = None,
        body: bytes | None = None, content_type: str = "application/json",
    ) -> dict:
        data = body
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode()
        request = Request(
            f"{BACKEND}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                **({"Content-Type": content_type} if data is not None else {}),
            },
        )
        try:
            with urlopen(request, timeout=8) as response:
                self.last_error = None
                return json.load(response)
        except HTTPError as error:
            self.last_error = f"backend-http-{error.code}"
            raise RuntimeError(self.last_error) from error
        except (URLError, TimeoutError, ValueError, OSError) as error:
            self.last_error = "backend-unavailable"
            raise RuntimeError(self.last_error) from error

    def post_event(self, payload: dict[str, Any], snapshot: bytes | None = None) -> None:
        try:
            self._send_event(payload, snapshot)
        except RuntimeError:
            log(
                "event_retry",
                camera=payload.get("cameraId", "unknown"),
                zone=payload.get("zoneId", "unknown"),
                state=payload.get("state", "unknown"),
                error=self.last_error or "backend-error",
            )
            try:
                self.pending.put_nowait((payload, snapshot))
            except queue.Full:
                pass

    def _send_event(self, payload: dict[str, Any], snapshot: bytes | None) -> None:
        result = self.request(
            "/internal/v1/detection/events", method="POST", payload=payload
        )
        if snapshot and result.get("snapshotRequested"):
            self.request(
                f"/internal/v1/detection/events/{result['eventId']}/snapshot",
                method="POST", body=snapshot, content_type="image/jpeg",
            )

    def flush(self) -> None:
        for _ in range(min(100, self.pending.qsize())):
            payload, snapshot = self.pending.get_nowait()
            try:
                self._send_event(payload, snapshot)
            except RuntimeError:
                self.pending.put_nowait((payload, snapshot))
                break


class CameraWorker(threading.Thread):
    def __init__(self, camera: dict[str, Any], config: dict[str, Any], client: BackendClient):
        super().__init__(name=f"detection-{camera['id']}", daemon=True)
        self.camera = camera
        self.client = client
        self.width = int(config.get("width", 640))
        self.height = int(config.get("height", 360))
        self.engine = MotionEngine(
            camera,
            width=self.width,
            height=self.height,
            warmup_seconds=float(config.get("warmupSeconds", 10)),
            scene_change_ratio=float(config.get("sceneChangeRatio", 0.60)),
        )
        self.local_stop = threading.Event()
        self.process: subprocess.Popen | None = None
        self.last_frame_at = 0.0
        self.processing_delay_ms = 0
        self.started_at = time.monotonic()

    def stop(self) -> None:
        self.local_stop.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()

    def send_actions(self, actions: list[dict[str, Any]], frame: np.ndarray | None = None) -> None:
        snapshot: bytes | None = None
        for action in actions:
            log(
                "motion",
                camera=self.camera["id"],
                zone=action["zoneId"],
                state=action["state"],
            )
            payload = {
                **action,
                "cameraId": self.camera["id"],
                "occurredAt": None,
            }
            if action["state"] == "started" and frame is not None:
                zone = next(
                    (item for item in self.camera["zones"] if item["id"] == action["zoneId"]),
                    None,
                )
                if zone and zone.get("snapshotEnabled"):
                    ok, encoded = cv2.imencode(
                        ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 75]
                    )
                    if ok and len(encoded) <= 256 * 1024:
                        snapshot = encoded.tobytes()
            self.client.post_event(payload, snapshot)

    def ffmpeg_command(self) -> list[str]:
        return [
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
            "-rtsp_transport", "tcp", "-timeout", "10000000",
            "-i", self.camera["rtspUrl"], "-an", "-sn", "-dn",
            "-vf", f"fps=3,scale={self.width}:{self.height},format=gray",
            "-pix_fmt", "gray", "-f", "rawvideo", "pipe:1",
        ]

    def run(self) -> None:
        delays = (1, 5, 15, 30)
        failures = 0
        frame_bytes = self.width * self.height
        while not stop_event.is_set() and not self.local_stop.is_set():
            try:
                self.process = subprocess.Popen(
                    self.ffmpeg_command(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=frame_bytes * 2,
                )
                log("stream_connected", camera=self.camera["id"])
                assert self.process.stdout is not None
                while not stop_event.is_set() and not self.local_stop.is_set():
                    raw = self.process.stdout.read(frame_bytes)
                    if len(raw) != frame_bytes:
                        break
                    failures = 0
                    self.last_frame_at = time.monotonic()
                    frame = np.frombuffer(raw, dtype=np.uint8).reshape(
                        (self.height, self.width)
                    )
                    started = time.monotonic()
                    self.send_actions(self.engine.process(frame), frame)
                    self.processing_delay_ms = max(
                        0, round((time.monotonic() - started) * 1000)
                    )
            except (OSError, ValueError):
                self.client.last_error = f"camera-stream-unavailable:{self.camera['id']}"
            finally:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                self.process = None
            if stop_event.is_set() or self.local_stop.is_set():
                break
            delay = delays[min(failures, len(delays) - 1)]
            failures += 1
            log("stream_retry", camera=self.camera["id"], delay=delay)
            self.local_stop.wait(delay)
        self.send_actions(self.engine.end_all())


def same_camera(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def cgroup_metrics(previous_cpu: tuple[int, float] | None) -> tuple[float | None, int | None, tuple[int, float] | None]:
    try:
        cpu_line = next(
            line for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines()
            if line.startswith("usage_usec ")
        )
        usage = int(cpu_line.split()[1])
        sampled_at = time.monotonic()
        cpu = None
        if previous_cpu:
            cpu = max(
                0.0,
                (usage - previous_cpu[0]) / 1_000_000 / max(0.001, sampled_at - previous_cpu[1]) * 100,
            )
        memory = int(Path("/sys/fs/cgroup/memory.current").read_text().strip())
        return cpu, memory, (usage, sampled_at)
    except (OSError, StopIteration, ValueError):
        return None, None, previous_cpu


def main() -> None:
    client = BackendClient()
    workers: dict[str, CameraWorker] = {}
    configs: dict[str, dict[str, Any]] = {}
    previous_cpu: tuple[int, float] | None = None
    while not stop_event.is_set():
        try:
            config = client.request("/internal/v1/detection/config")
            desired = {camera["id"]: camera for camera in config.get("cameras", [])}
            for camera_id in set(workers) - set(desired):
                workers.pop(camera_id).stop()
                configs.pop(camera_id, None)
            for camera_id, camera in desired.items():
                if (
                    camera_id in configs
                    and same_camera(configs[camera_id], camera)
                    and workers[camera_id].is_alive()
                ):
                    continue
                if camera_id in workers:
                    workers.pop(camera_id).stop()
                worker = CameraWorker(camera, config, client)
                workers[camera_id] = worker
                configs[camera_id] = camera
                worker.start()
            client.flush()
            delays = [worker.processing_delay_ms for worker in workers.values()]
            cpu_percent, memory_bytes, previous_cpu = cgroup_metrics(previous_cpu)
            missing_frames = [
                worker for worker in workers.values() if not worker.last_frame_at
            ]
            if not config.get("enabled"):
                state = "paused"
            elif any(worker.engine.learning for worker in workers.values()):
                state = "learning"
            elif missing_frames:
                state = (
                    "degraded"
                    if any(time.monotonic() - worker.started_at > 10 for worker in missing_frames)
                    else "starting"
                )
            else:
                state = "active" if len(workers) == len(desired) else "degraded"
            client.request(
                "/internal/v1/detection/status",
                method="POST",
                payload={
                    "state": state,
                    "activeCameras": len(workers),
                    "processingDelayMs": max(delays, default=0),
                    "cpuPercent": cpu_percent,
                    "memoryBytes": memory_bytes,
                    "lastError": client.last_error,
                },
            )
            HEALTH_PATH.write_text(
                json.dumps({"state": state, "at": int(time.time())}), encoding="utf-8"
            )
        except Exception as error:
            client.last_error = type(error).__name__
        stop_event.wait(POLL_SECONDS)
    for worker in workers.values():
        worker.stop()
    for worker in workers.values():
        worker.join(timeout=10)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    main()
