from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

BACKEND = os.environ.get("BACKEND_INTERNAL", "http://web:8090")
MEDIAMTX = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997")
TOKEN_PATH = Path(os.environ.get("INTERNAL_TOKEN_PATH", "/run/secrets/zmodo_internal_token"))
SECRET_DIR = Path("/run/relay-secrets")
HEALTH_FILE = Path("/run/relay-health/manager")
running = True
processes: dict[str, dict] = {}
retry_state: dict[str, dict] = {}


def internal_token() -> str:
    raw = base64.urlsafe_b64decode(TOKEN_PATH.read_text().strip() + "===")[:32]
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def request_json(url: str, method: str = "GET", payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=body, method=method, headers={"Authorization": f"Bearer {internal_token()}", "Content-Type": "application/json"})
    with urlopen(req, timeout=5) as response:
        return json.load(response) if response.length != 0 else {}


def mediamtx_path(name: str, port: int) -> None:
    payload = {"source": f"udp+mpegts://0.0.0.0:{port}", "record": False}
    encoded = quote(name, safe="")
    try:
        request_json(f"{MEDIAMTX}/v3/config/paths/add/{encoded}", "POST", payload)
        return
    except HTTPError as error:
        if error.code != 400:
            raise
    try:
        request_json(f"{MEDIAMTX}/v3/config/paths/patch/{encoded}", "PATCH", payload)
        return
    except HTTPError as error:
        if error.code not in (400, 404, 405):
            raise
    # MediaMTX 1.19 besitzt in einigen Builds keinen PATCH-Endpunkt. Beim
    # kontrollierten Wechsel eines bereits statisch definierten neutralen
    # Pfads wird deshalb nur dessen Laufzeitkonfiguration ersetzt.
    delete_mediamtx_path(name)
    request_json(f"{MEDIAMTX}/v3/config/paths/add/{encoded}", "POST", payload)


def delete_mediamtx_path(name: str) -> None:
    try:
        request_json(f"{MEDIAMTX}/v3/config/paths/delete/{quote(name, safe='')}", "DELETE")
    except HTTPError as error:
        if error.code != 404:
            raise


def stop_source(source_id: str, delete_path: bool = False) -> None:
    item = processes.pop(source_id, None)
    if not item:
        return
    process = item["process"]
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=3)
    item["playlist"].unlink(missing_ok=True)
    if delete_path:
        delete_mediamtx_path(item["path"])
    print(f"relay={source_id} state=stopped", flush=True)


def start_source(item: dict, port: int) -> None:
    state = retry_state.setdefault(item["id"], {"attempt": 0, "next": 0})
    if state["next"] > time.time():
        return
    mediamtx_path(item["path"], port)
    playlist = SECRET_DIR / f"{item['id']}.m3u"
    playlist.write_text("#EXTM3U\n" + item["sourceUri"] + "\n", encoding="utf-8")
    playlist.chmod(0o600)
    output = f"#std{{access=udp,mux=ts,dst=mediamtx:{port}}}"
    if item["codec"] in {"h265", "mjpeg"}:
        output = f"#transcode{{vcodec=h264,vb=1800,fps=15,scale=1,acodec=none}}:std{{access=udp,mux=ts,dst=mediamtx:{port}}}"
    command = ["cvlc", "-I", "dummy", "--no-one-instance", "--rtsp-tcp"]
    if not item.get("audio"):
        command += ["--no-audio", "--no-sout-audio"]
    command += ["--sout", output, "--sout-keep", "--play-and-exit", str(playlist)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes[item["id"]] = {"process": process, "playlist": playlist, "path": item["path"], "signature": (item["path"], item["sourceUri"], item["codec"], bool(item.get("audio")), item.get("connectionId"), port), "port": port}
    print(f"relay={item['id']} state=started codec={item['codec']} audio={bool(item.get('audio'))} revision={item.get('connectionRevision')} secret=redacted", flush=True)


def assign_ports(source_ids) -> dict[str, int]:
    assigned: dict[str, int] = {}
    used: set[int] = set()
    for source_id in sorted(source_ids):
        candidate = 13000 + (int.from_bytes(hashlib.blake2s(source_id.encode(), digest_size=2).digest(), "big") % 1000)
        while candidate in used:
            candidate = 13000 + ((candidate - 12999) % 1000)
        assigned[source_id] = candidate
        used.add(candidate)
    return assigned


def reconcile(config: dict) -> None:
    desired = {item["id"]: item for item in config.get("cameras", []) if item.get("active")}
    assigned_ports = assign_ports(desired)
    for source_id in list(processes):
        current = processes[source_id]; process = current["process"]
        if process.poll() is not None:
            processes.pop(source_id); current["playlist"].unlink(missing_ok=True)
            state = retry_state.setdefault(source_id, {"attempt": 0, "next": 0}); state["attempt"] += 1
            delays = (2, 5, 15, 30); state["next"] = time.time() + delays[min(state["attempt"] - 1, 3)]
            print(f"relay={source_id} state=exited retry_scheduled=true", flush=True)
        elif source_id not in desired:
            stop_source(source_id, delete_path=True)
        elif current["signature"] != (desired[source_id]["path"], desired[source_id]["sourceUri"], desired[source_id]["codec"], bool(desired[source_id].get("audio")), desired[source_id].get("connectionId"), assigned_ports[source_id]):
            path_changed = current["path"] != desired[source_id]["path"]
            stop_source(source_id, delete_path=path_changed)
    for source_id in sorted(desired):
        if source_id not in processes:
            start_source(desired[source_id], assigned_ports[source_id])
    HEALTH_FILE.write_text(str(int(time.time())))


def shutdown(*_args) -> None:
    global running
    running = False


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while running:
        try:
            reconcile(request_json(f"{BACKEND}/internal/v1/relay-config"))
        except (OSError, ValueError, URLError, HTTPError, RuntimeError) as error:
            print(f"manager=degraded reason={type(error).__name__}", flush=True)
        for _ in range(10):
            if not running:
                break
            time.sleep(1)
    for source_id in list(processes):
        stop_source(source_id)
    HEALTH_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
