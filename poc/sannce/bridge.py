from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import re
import secrets
import signal
import socket
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import (
    HTTPDigestAuthHandler,
    HTTPPasswordMgrWithDefaultRealm,
    Request,
    build_opener,
    urlopen,
)
from zoneinfo import ZoneInfo


logging.disable(logging.CRITICAL)

PREFIX = "192.168.0.2"
COMMAND_MAGIC = b"\xf1\xf5\xea\xf5"
MEDIA_MAGIC = b"\xf1\xf5\xea\xf9"
FRAME_MAGIC = b"\x00\x00\x00\x02"
MAX_FRAME_BYTES = 8 * 1024 * 1024
SAFE_PATH = re.compile(r"[A-Za-z0-9_.~-]{1,128}")
MEDIAMTX_API = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997").rstrip("/")
MEDIAMTX_PUBLISH = os.environ.get("MEDIAMTX_PUBLISH", "rtsp://mediamtx:8554").rstrip("/")
CREDENTIALS_PATH = Path(os.environ.get("SANNCE_CREDENTIALS_PATH", "/run/secrets/sannce_credentials"))
INTERNAL_TOKEN_PATH = Path(os.environ.get("INTERNAL_TOKEN_PATH", "/run/secrets/zmodo_internal_token"))
INVENTORY_PORT = int(os.environ.get("SANNCE_INVENTORY_PORT", "8790"))
RECORDER_TIMEZONE = ZoneInfo(os.environ.get("CAMERA_HUB_TIMEZONE", "Europe/Berlin"))
HEALTH_PATH = Path("/run/bridge-health/state")
RECORDING_TOKEN_SECONDS = 15 * 60
PLAYBACK_MAX_SECONDS = 30 * 60

stop_event = threading.Event()
state_lock = threading.Lock()
last_frames: dict[str, float] = {}
detected_frames: dict[str, tuple[float, str]] = {}
recording_lock = threading.Lock()
recording_files: dict[str, tuple[float, "Recording"]] = {}
playback_slots = threading.BoundedSemaphore(2)


def log(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, separators=(",", ":"), ensure_ascii=True), flush=True)


@dataclass(frozen=True)
class Channel:
    physical: int
    stream_index: int
    path: str
    fps: int = 24


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    username: str
    password: str
    channel_count: int
    channels: tuple[Channel, ...]
    discover_channels: tuple[Channel, ...]


@dataclass(frozen=True)
class Recording:
    token: str
    channel: int
    kind: str
    start_at: str
    end_at: str
    filename: str


def load_config(path: Path = CREDENTIALS_PATH) -> Config:
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    channel_count = int(raw.get("channelCount", 8))
    channels = []
    for item in raw["channels"]:
        physical = int(item["channel"])
        stream = int(item.get("stream", 1))
        path_name = str(item["path"])
        if physical < 1 or physical > channel_count or stream not in {0, 1}:
            raise ValueError("invalid-channel")
        if not SAFE_PATH.fullmatch(path_name):
            raise ValueError("invalid-path")
        stream_index = channel_count * min(stream, 1) + physical - 1
        channels.append(Channel(physical, stream_index, path_name, int(item.get("fps", 24))))
    if not channels or len({item.path for item in channels}) != len(channels):
        raise ValueError("invalid-channel-inventory")
    configured = {item.physical for item in channels}
    discover_channels = []
    for physical in raw.get("discoverChannels", []):
        physical = int(physical)
        if physical < 1 or physical > channel_count or physical in configured:
            raise ValueError("invalid-discovery-channel")
        discover_channels.append(Channel(
            physical, channel_count + physical - 1, f"sannce-{physical}-low", 24,
        ))
    return Config(
        host=str(raw["host"]), port=int(raw.get("port", 3002)),
        username=str(raw["username"]), password=str(raw["password"]),
        channel_count=channel_count, channels=tuple(channels),
        discover_channels=tuple(discover_channels),
    )


class WebSocket:
    def __init__(self, host: str, port: int, timeout: float = 10) -> None:
        self.socket = socket.create_connection((host, port), timeout=timeout)
        self.socket.settimeout(timeout)
        self.send_lock = threading.Lock()
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\nOrigin: http://{host}\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self.socket.recv(4096))
            if len(response) > 16384:
                raise OSError("websocket-handshake-too-large")
        if b" 101 " not in bytes(response).split(b"\r\n", 1)[0]:
            raise OSError("websocket-handshake-rejected")

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass

    def _read(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise EOFError("websocket-closed")
            data.extend(chunk)
        return bytes(data)

    def send(self, payload: bytes, opcode: int = 2) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)
        header.extend(value ^ mask[index % 4] for index, value in enumerate(payload))
        with self.send_lock:
            self.socket.sendall(header)

    def receive(self) -> bytes:
        fragments = bytearray()
        while True:
            first, second = self._read(2)
            final, opcode, masked = bool(first & 0x80), first & 0x0F, bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if masked else None
            payload = self._read(length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 8:
                raise EOFError("websocket-close")
            if opcode == 9:
                self.send(payload, 10)
                continue
            if opcode not in {0, 2}:
                continue
            fragments.extend(payload)
            if final:
                return bytes(fragments)


def command_packet(text: str) -> bytes:
    payload = text.encode("utf-8")
    header = bytearray(20)
    struct.pack_into("<I", header, 0, 0xF5EAF5F1)
    struct.pack_into("<H", header, 6, 20 + len(payload))
    struct.pack_into("<H", header, 18, len(payload))
    return bytes(header) + payload


def parse_commands(data: bytes) -> Iterator[list[str]]:
    offset = 0
    while offset + 20 <= len(data):
        if data[offset : offset + 4] != COMMAND_MAGIC:
            offset += 1
            continue
        total = struct.unpack_from("<H", data, offset + 6)[0]
        if total < 20 or offset + total > len(data):
            return
        payload = data[offset + 20 : offset + total]
        for raw in payload.split(b"\n\n\n"):
            if raw.strip():
                yield raw.decode("latin1").split("\t")
        offset += total


def media_payloads(data: bytes) -> Iterator[bytes]:
    offset = 0
    while offset + 28 <= len(data):
        if data[offset : offset + 4] != MEDIA_MAGIC:
            offset += 1
            continue
        total = struct.unpack_from("<H", data, offset + 14)[0]
        if total < 28 or offset + total > len(data):
            return
        yield data[offset + 28 : offset + total]
        offset += total


class MediaParser:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> Iterator[bytes]:
        self.buffer.extend(data)
        while len(self.buffer) >= 28:
            if self.buffer[:4] != MEDIA_MAGIC:
                marker = self.buffer.find(MEDIA_MAGIC, 1)
                if marker < 0:
                    del self.buffer[:-3]
                    return
                del self.buffer[:marker]
            if len(self.buffer) < 28:
                return
            total = struct.unpack_from("<H", self.buffer, 14)[0]
            if total < 28:
                del self.buffer[0]
                continue
            if len(self.buffer) < total:
                return
            yield bytes(self.buffer[28:total])
            del self.buffer[:total]


class FrameParser:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> Iterator[bytes]:
        self.buffer.extend(data)
        while len(self.buffer) >= 8:
            if self.buffer[:4] != FRAME_MAGIC:
                marker = self.buffer.find(FRAME_MAGIC, 1)
                if marker < 0:
                    del self.buffer[:-3]
                    return
                del self.buffer[:marker]
            if len(self.buffer) < 8:
                return
            total = struct.unpack_from("<I", self.buffer, 4)[0]
            if total < 32 or total > MAX_FRAME_BYTES:
                del self.buffer[0]
                continue
            if len(self.buffer) < total:
                return
            encoded = struct.unpack_from("<I", self.buffer, 20)[0]
            if 0 < encoded <= total - 32:
                yield bytes(self.buffer[32 : 32 + encoded])
            del self.buffer[:total]


def has_h264_sps(frame: bytes) -> bool:
    return b"\x00\x00\x00\x01\x67" in frame or b"\x00\x00\x01\x67" in frame


def detected_codec(frame: bytes) -> str | None:
    if has_h264_sps(frame):
        return "h264"
    for marker in (b"\x00\x00\x00\x01", b"\x00\x00\x01"):
        offset = 0
        while True:
            position = frame.find(marker, offset)
            if position < 0:
                break
            nal = position + len(marker)
            if nal < len(frame) and ((frame[nal] >> 1) & 0x3F) in {32, 33, 34}:
                return "h265"
            offset = nal + 1
    return None


def authenticate(config: Config) -> tuple[WebSocket, str]:
    websocket = WebSocket(config.host, config.port)
    username = base64.b64encode(config.username.encode()).decode()
    password = base64.b64encode(config.password.encode()).decode()
    websocket.send(command_packet(
        f"{PREFIX}\tIP\tUSER\tLOGON\t{username}\t{password}\t\t3\tUTF-8\t805306367\t1\n\n\n"
    ))
    command_id = ""
    authenticated = False
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and not authenticated:
        for fields in parse_commands(websocket.receive()):
            core = fields[2:] if len(fields) > 2 and fields[1] in {"IP", "PROXY"} else fields
            if len(core) > 6 and core[:4] == ["INNER", "USER", "LOGONFAILED", "3"]:
                nonce = base64.b64decode(core[6])[:8].decode("latin1")
                user_digest = base64.b64encode(
                    hashlib.md5((config.username + nonce).encode("latin1")).digest()
                ).decode()
                pass_digest = base64.b64encode(
                    hashlib.md5((config.password + nonce).encode("latin1")).digest()
                ).decode()
                websocket.send(command_packet(
                    f"{PREFIX}\tIP\tUSER\tLOGON\t{user_digest}\t{pass_digest}"
                    "\t\t3\tUTF-8\t0\t1\n\n\n"
                ))
            elif len(core) > 2 and core[:2] == ["INNER", "CMDID"]:
                command_id = core[2]
            elif len(core) > 2 and core[:3] == ["INNER", "LOGON", "FINISHED"]:
                authenticated = True
    if not authenticated or not command_id:
        websocket.close()
        raise OSError("sannce-authentication-failed")
    return websocket, command_id


def maintain_command_socket(websocket: WebSocket, finished: threading.Event) -> None:
    """Drain control traffic so WebSocket pings keep the authenticated session alive."""
    while not stop_event.is_set() and not finished.is_set():
        try:
            websocket.receive()
        except TimeoutError:
            continue
        except (EOFError, OSError):
            finished.set()
            return


def ensure_mediamtx_path(path: str) -> None:
    payload = json.dumps({"source": "publisher", "record": False}).encode()
    request = Request(
        f"{MEDIAMTX_API}/v3/config/paths/add/{quote(path, safe='')}", data=payload,
        method="POST", headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=5):
            return
    except HTTPError as error:
        if error.code != 400:
            raise
    with urlopen(f"{MEDIAMTX_API}/v3/config/paths/get/{quote(path, safe='')}", timeout=5) as response:
        configured = json.load(response)
    if configured.get("source") != "publisher":
        raise RuntimeError("mediamtx-path-in-use")


class Publisher:
    def __init__(self, channel: Channel) -> None:
        self.channel = channel
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        ensure_mediamtx_path(self.channel.path)
        self.process = subprocess.Popen(
            [
                "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "warning",
                "-fflags", "+genpts", "-r", str(self.channel.fps), "-f", "h264",
                "-i", "pipe:0", "-an", "-c:v", "copy", "-f", "rtsp",
                "-rtsp_transport", "tcp", f"{MEDIAMTX_PUBLISH}/{self.channel.path}",
            ], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def write(self, frame: bytes) -> None:
        if not self.process or self.process.poll() is not None or not self.process.stdin:
            raise BrokenPipeError("publisher-not-running")
        self.process.stdin.write(frame)
        self.process.stdin.flush()

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
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def channel_session(config: Config, channel: Channel) -> None:
    command_socket: WebSocket | None = None
    data_socket: WebSocket | None = None
    publisher = Publisher(channel)
    command_finished = threading.Event()
    command_worker: threading.Thread | None = None
    try:
        command_socket, command_id = authenticate(config)
        command_worker = threading.Thread(
            target=maintain_command_socket, args=(command_socket, command_finished), daemon=True,
        )
        command_worker.start()
        data_socket = WebSocket(config.host, config.port)
        data_socket.send(command_packet(
            f"{PREFIX}\tIP\tINNER\tCONNECT\t{channel.stream_index}\t1\t{command_id}"
            "\t\t0\t\t\t\t\n\n\n"
        ))
        media_parser = MediaParser()
        parser = FrameParser()
        publisher_started = False
        forced = False
        heartbeat = time.monotonic()
        while not stop_event.is_set():
            if command_finished.is_set():
                raise EOFError("sannce-command-session-ended")
            message = data_socket.receive()
            for payload in media_parser.feed(message):
                if not forced:
                    command_socket.send(command_packet(
                        f"{PREFIX}\tIP\tCMD\tFORCE_IFRAME\t{channel.stream_index}\t0\n\n\n"
                    ))
                    forced = True
                for frame in parser.feed(payload):
                    codec = detected_codec(frame)
                    if codec:
                        with state_lock:
                            detected_frames[channel.path] = (time.monotonic(), codec)
                    if not publisher_started:
                        if not has_h264_sps(frame):
                            continue
                        publisher.start()
                        publisher_started = True
                        log("stream_started", channel=channel.physical, path=channel.path)
                    publisher.write(frame)
                    with state_lock:
                        last_frames[channel.path] = time.monotonic()
            if time.monotonic() - heartbeat >= 5:
                command_socket.send(command_packet(""))
                heartbeat = time.monotonic()
    finally:
        command_finished.set()
        publisher.stop()
        if data_socket:
            data_socket.close()
        if command_socket:
            command_socket.close()
        if command_worker:
            command_worker.join(timeout=1)


def channel_worker(config: Config, channel: Channel, retry_seconds: int = 3) -> None:
    while not stop_event.is_set():
        try:
            channel_session(config, channel)
        except (BrokenPipeError, EOFError, OSError, RuntimeError, ValueError, HTTPError) as error:
            log("stream_retry", channel=channel.physical, reason=type(error).__name__)
        with state_lock:
            last_frames.pop(channel.path, None)
        stop_event.wait(retry_seconds)


def recorder_opener(config: Config):
    password_manager = HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(
        None, f"http://{config.host}", config.username, config.password
    )
    return build_opener(HTTPDigestAuthHandler(password_manager))


def recorder_post_xml(config: Config, path: str, root: ET.Element) -> ET.Element:
    request = Request(
        f"http://{config.host}{path}",
        data=ET.tostring(root, encoding="utf-8", xml_declaration=True),
        method="POST",
        headers={"Content-Type": "application/xml", "Accept": "application/xml"},
    )
    with recorder_opener(config).open(request, timeout=15) as response:
        data = response.read(2 * 1024 * 1024)
    return ET.fromstring(data)


def local_recorder_time(value: str) -> datetime:
    clean = value.strip().removesuffix("Z")
    parsed = datetime.fromisoformat(clean)
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed.replace(tzinfo=RECORDER_TIMEZONE)


def utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def search_recordings(
    config: Config,
    channel: int,
    start_local: datetime,
    end_local: datetime,
    *,
    position: int = 1,
    maximum: int = 100,
) -> tuple[int, list[Recording]]:
    root = ET.Element("CMSearchDescription")
    span_list = ET.SubElement(root, "timeSpanList")
    span = ET.SubElement(span_list, "timeSpan")
    ET.SubElement(span, "startTime").text = start_local.strftime("%Y-%m-%dT%H:%M:%SZ")
    ET.SubElement(span, "endTime").text = end_local.strftime("%Y-%m-%dT%H:%M:%SZ")
    content = ET.SubElement(root, "contentTypeList")
    ET.SubElement(content, "contentType").text = "video"
    record_types = ET.SubElement(root, "RecTypeList")
    ET.SubElement(record_types, "recType").text = "ALL"
    detail_types = ET.SubElement(root, "vcaDetailTypeList")
    ET.SubElement(detail_types, "vcaDetailType").text = "ALL"
    ET.SubElement(root, "maxResults").text = str(maximum)
    ET.SubElement(root, "searchResultPostion").text = str(position)
    ET.SubElement(root, "channelID").text = str(channel - 1)
    ET.SubElement(root, "streamType").text = "1"
    ET.SubElement(root, "queryType").text = "0"
    result = recorder_post_xml(config, "/ISAPI/ContentMgmt/search", root)
    total = int(result.findtext("numOfMatches", "0") or 0)
    records: list[Recording] = []
    for item in result.findall(".//matchElement"):
        filename = (item.findtext("fileName") or "").strip()
        start_text = (item.findtext(".//startTime") or "").strip()
        end_text = (item.findtext(".//endTime") or "").strip()
        reported_channel = int(item.findtext("chanNo", "-1") or -1) + 1
        if (
            reported_channel != channel
            or not filename
            or len(filename) > 128
            or any(character in filename for character in "\r\n\t")
            or not start_text
            or not end_text
        ):
            continue
        start_at = utc_iso(local_recorder_time(start_text))
        end_at = utc_iso(local_recorder_time(end_text))
        digest = hmac.new(
            config.password.encode("utf-8"),
            f"{channel}\0{filename}\0{start_at}\0{end_at}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:40]
        records.append(
            Recording(
                token=digest,
                channel=channel,
                kind=(item.findtext("type") or "recording")[:32],
                start_at=start_at,
                end_at=end_at,
                filename=filename,
            )
        )
    with recording_lock:
        expires = time.time() + RECORDING_TOKEN_SECONDS
        for record in records:
            recording_files[record.token] = (expires, record)
        for token, (expiry, _) in list(recording_files.items()):
            if expiry <= time.time():
                recording_files.pop(token, None)
    return total, records


def recordings_for_day(config: Config, channel: int, selected: date) -> list[Recording]:
    start = datetime.combine(selected, datetime.min.time())
    end = start + timedelta(days=1) - timedelta(seconds=1)
    position, results, page_size = 1, [], 500
    while len(results) < 2000:
        _, page = search_recordings(
            config, channel, start, end, position=position, maximum=page_size
        )
        if not page:
            break
        results.extend(page)
        position += len(page)
        if len(page) < page_size:
            break
    return results


def recording_availability(config: Config, channel: int) -> dict:
    now_local = datetime.now(RECORDER_TIMEZONE).replace(tzinfo=None)
    start_local = now_local - timedelta(days=5 * 366)
    position, page_size, maximum_records = 1, 1000, 20_000
    first: Recording | None = None
    last: Recording | None = None
    limited = False
    while position <= maximum_records:
        _, page = search_recordings(
            config, channel, start_local, now_local,
            position=position, maximum=page_size,
        )
        if not page:
            break
        first = first or page[0]
        last = page[-1]
        position += len(page)
        if len(page) < page_size:
            break
    else:
        limited = True
    if not first or not last:
        return {"availableFrom": None, "availableTo": None, "limited": False}
    return {
        "availableFrom": first.start_at,
        "availableTo": last.end_at,
        "limited": limited,
    }


def recording_from_token(token: str) -> Recording | None:
    with recording_lock:
        item = recording_files.get(token)
        if not item or item[0] <= time.time():
            recording_files.pop(token, None)
            return None
        return item[1]


def playback_process(
    config: Config, recording: Recording, offset_seconds: int = 0
) -> tuple[subprocess.Popen[bytes], threading.Event]:
    command_socket, command_id = authenticate(config)
    data_socket = WebSocket(config.host, config.port, timeout=15)
    finished = threading.Event()
    media_parser = MediaParser()
    parser = FrameParser()
    first_frames: list[bytes] = []
    try:
        data_socket.send(command_packet(
            f"{PREFIX}\tIP\tINNER\tCONNECT\t250\t1\t{command_id}\t{recording.filename}"
            "\t0\t-1\t1\t0\t1\t\t\t\t\t\t\t0\t\t\t\n\n\n"
        ))
        if offset_seconds:
            time.sleep(0.15)
            data_socket.send(command_packet(
                f"{PREFIX}\tIP\tINNER\tCONNECT\t250\t1\t{command_id}\t{recording.filename}"
                f"\t1\t{offset_seconds}\t1\t0\t1\n\n\n"
            ))
        first_frame_deadline = time.monotonic() + 15
        while time.monotonic() < first_frame_deadline and not first_frames:
            for payload in media_parser.feed(data_socket.receive()):
                first_frames.extend(parser.feed(payload))
        codec = next((detected_codec(frame) for frame in first_frames if detected_codec(frame)), None)
        if codec not in {"h264", "h265"}:
            raise OSError("recording-codec-unknown")
        input_format = "hevc" if codec == "h265" else "h264"
        process = subprocess.Popen(
            [
                "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                "-fflags", "+genpts", "-r", "24", "-threads", "1",
                "-f", input_format, "-i", "pipe:0",
                "-an", "-vf", "scale=1280:-2", "-c:v", "libx264", "-preset", "ultrafast",
                "-tune", "zerolatency", "-threads", "1", "-crf", "26",
                "-pix_fmt", "yuv420p", "-movflags",
                "frag_keyframe+empty_moov+default_base_moof", "-f", "mp4", "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        data_socket.close()
        command_socket.close()
        raise

    def produce() -> None:
        deadline = time.monotonic() + PLAYBACK_MAX_SECONDS
        try:
            for frame in first_frames:
                if process.stdin:
                    process.stdin.write(frame)
                    process.stdin.flush()
            while time.monotonic() < deadline and not finished.is_set():
                for payload in media_parser.feed(data_socket.receive()):
                    for frame in parser.feed(payload):
                        if process.stdin:
                            process.stdin.write(frame)
                            process.stdin.flush()
        except (BrokenPipeError, EOFError, OSError, TimeoutError):
            pass
        finally:
            finished.set()
            try:
                data_socket.send(command_packet(
                    f"{PREFIX}\tIP\tINNER\tDISCONNECT\t250\t1\t0\n\n\n"
                ))
            except (OSError, EOFError):
                pass
            data_socket.close()
            command_socket.close()
            if process.stdin:
                try:
                    process.stdin.close()
                except OSError:
                    pass

    threading.Thread(target=produce, daemon=True).start()
    return process, finished


def inventory_payload(config: Config) -> dict:
    now = time.monotonic()
    with state_lock:
        frames = dict(last_frames)
        detected = dict(detected_frames)
    channels = []
    for channel in config.channels + config.discover_channels:
        ready = channel.path in frames and now - frames[channel.path] < 20
        detected_at, codec = detected.get(channel.path, (0.0, "h264"))
        present = ready or now - detected_at < 20
        if channel in config.discover_channels and not present:
            continue
        channels.append({
            "channel": channel.physical,
            "path": channel.path,
            "ready": ready,
            "configured": channel in config.channels,
            "codec": codec,
            "width": 704,
            "height": 480,
            "fps": channel.fps,
        })
    return {
        "host": config.host,
        "manufacturer": "SANNCE",
        "model": "N98PBM",
        "channelCount": config.channel_count,
        "channels": channels,
    }


def start_inventory_server(config: Config) -> http.server.ThreadingHTTPServer:
    raw_token = INTERNAL_TOKEN_PATH.read_text(encoding="utf-8").strip()
    token_bytes = base64.urlsafe_b64decode(raw_token + "=" * (-len(raw_token) % 4))[:32]
    if len(token_bytes) < 32:
        raise ValueError("invalid-internal-token")
    token = base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")

    class InventoryHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            if hmac.compare_digest(supplied, f"Bearer {token}"):
                return True
            self.send_error(401)
            return False

        def json_response(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if not self.authorized():
                return
            parsed = urlparse(self.path)
            if parsed.path == "/internal/v1/inventory":
                self.json_response(inventory_payload(config))
                return
            if parsed.path == "/internal/v1/recordings/availability":
                try:
                    channel = int((parse_qs(parsed.query).get("channel") or [""])[0])
                    if channel < 1 or channel > config.channel_count:
                        raise ValueError
                    self.json_response(recording_availability(config, channel))
                except ValueError:
                    self.json_response({"error": "invalid-recording-query"}, 422)
                except (HTTPError, OSError, TimeoutError, ET.ParseError):
                    self.json_response({"error": "recorder-archive-unavailable"}, 503)
                return
            if parsed.path == "/internal/v1/recordings":
                try:
                    params = parse_qs(parsed.query)
                    channel = int((params.get("channel") or [""])[0])
                    selected = date.fromisoformat((params.get("date") or [""])[0])
                    if channel < 1 or channel > config.channel_count:
                        raise ValueError
                    records = recordings_for_day(config, channel, selected)
                    self.json_response({
                        "recordings": [
                            {
                                "id": item.token,
                                "startAt": item.start_at,
                                "endAt": item.end_at,
                                "kind": item.kind,
                                "playable": True,
                            }
                            for item in records
                        ]
                    })
                except ValueError:
                    self.json_response({"error": "invalid-recording-query"}, 422)
                except (HTTPError, OSError, TimeoutError, ET.ParseError):
                    self.json_response({"error": "recorder-archive-unavailable"}, 503)
                return
            media_match = re.fullmatch(
                r"/internal/v1/recordings/([a-f0-9]{40})/media", parsed.path
            )
            if media_match:
                recording = recording_from_token(media_match.group(1))
                if not recording:
                    self.send_error(404)
                    return
                if not playback_slots.acquire(blocking=False):
                    self.send_error(429)
                    return
                process = None
                finished = None
                try:
                    try:
                        offset_seconds = int((parse_qs(parsed.query).get("offset") or ["0"])[0])
                    except ValueError:
                        offset_seconds = -1
                    duration = max(
                        0,
                        int(
                            (
                                datetime.fromisoformat(recording.end_at.replace("Z", "+00:00"))
                                - datetime.fromisoformat(recording.start_at.replace("Z", "+00:00"))
                            ).total_seconds()
                        ),
                    )
                    if offset_seconds < 0 or (duration and offset_seconds >= duration):
                        self.send_error(422)
                        return
                    try:
                        process, finished = playback_process(config, recording, offset_seconds)
                    except (EOFError, OSError, TimeoutError):
                        self.send_error(502)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "video/mp4")
                    self.send_header("Cache-Control", "no-store, private")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    if not process.stdout:
                        raise OSError("playback-output-unavailable")
                    while not finished.is_set() or process.poll() is None:
                        chunk = process.stdout.read1(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    if finished:
                        finished.set()
                    if process and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    playback_slots.release()
                return
            else:
                self.send_error(404)
                return

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("0.0.0.0", INVENTORY_PORT), InventoryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def health_worker(channels: tuple[Channel, ...]) -> None:
    paths = {channel.path for channel in channels}
    while not stop_event.is_set():
        now = time.monotonic()
        with state_lock:
            healthy = paths == set(last_frames) and all(now - last_frames[path] < 20 for path in paths)
        if healthy:
            HEALTH_PATH.parent.mkdir(parents=True, exist_ok=True)
            HEALTH_PATH.write_text(str(int(time.time())), encoding="ascii")
        stop_event.wait(2)


def shutdown(*_args: object) -> None:
    stop_event.set()


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    config = load_config()
    inventory_server = start_inventory_server(config)
    log("configured", channels=len(config.channels), discovery=len(config.discover_channels))
    threading.Thread(target=health_worker, args=(config.channels,), daemon=True).start()
    workers = []
    for channel in config.channels:
        worker = threading.Thread(target=channel_worker, args=(config, channel), daemon=True)
        worker.start()
        workers.append(worker)
    for channel in config.discover_channels:
        worker = threading.Thread(
            target=channel_worker, args=(config, channel, 30), daemon=True,
        )
        worker.start()
        workers.append(worker)
    while not stop_event.wait(1):
        if not all(worker.is_alive() for worker in workers):
            raise RuntimeError("sannce-worker-stopped")
    inventory_server.shutdown()


if __name__ == "__main__":
    main()
