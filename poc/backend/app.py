from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Header, HTTPException, Request as FastAPIRequest, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from onvif_client import OnvifClient, OnvifError


WEB_ROOT = Path(os.environ.get("WEB_ROOT", "/web")).resolve()
DB_PATH = Path(os.environ.get("DATABASE_PATH", "/data/zmodo.db"))
SEED_PATH = Path(os.environ.get("CAMERA_CONFIG", "/config/cameras.json"))
SECRET_PATH = Path(os.environ.get("SECRET_KEY_PATH", "/run/secrets/zmodo_secret_key"))
INTERNAL_TOKEN_PATH = Path(os.environ.get("INTERNAL_TOKEN_PATH", "/run/secrets/zmodo_internal_token"))
CZEVIEW_ADAPTER_TOKEN_PATH = Path(os.environ.get("CZEVIEW_ADAPTER_TOKEN_PATH", "/run/secrets/czeview_adapter_token"))
NETATMO_ADAPTER_TOKEN_PATH = Path(os.environ.get("NETATMO_ADAPTER_TOKEN_PATH", "/run/secrets/netatmo_adapter_token"))
MEDIAMTX_API = os.environ.get("MEDIAMTX_API", "http://mediamtx:9997")
ALLOWED_NETWORK = ipaddress.ip_network(os.environ.get("DISCOVERY_NETWORK", "192.168.1.0/24"), strict=True)
MAX_CAMERAS = int(os.environ.get("MAX_CAMERAS", "32"))
SESSION_SECONDS = 8 * 60 * 60
ELEVATION_SECONDS = 10 * 60
SCAN_TTL_SECONDS = 15 * 60
SCAN_PORTS = (80, 443, 554, 2020, 8000, 8080, 8554, 8899, 10080, 10554)
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DB_LOCK = threading.RLock()
SCAN_LOCK = threading.Lock()
SCANS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LEASES: dict[str, dict[str, float]] = {}
PTZ_ATTEMPTS: dict[str, list[float]] = {}
CONNECTION_TESTS: dict[str, tuple[float, str, dict]] = {}
ACTIVATION_LOCK = threading.Lock()
PREVIEW_SEMAPHORE = threading.BoundedSemaphore(2)
PREVIEW_CACHE: dict[str, tuple[float, bytes]] = {}
DISCOVERY_PREVIEW_CACHE: dict[tuple[str, str], tuple[float, bytes]] = {}
REAUTH_ATTEMPTS: dict[str, list[float]] = {}
NETATMO_TOKEN_LOCKS: dict[str, threading.Lock] = {}
NETATMO_STREAM_CACHE: dict[str, tuple[float, list[str]]] = {}
CLOUD_PROBE_LEASES: dict[str, dict] = {}
HTTP_DIAGNOSTIC_ONLY = os.environ.get("HTTP_DIAGNOSTIC_ONLY") == "1"
ALLOW_INSECURE_LOOPBACK_MANAGEMENT = (
    os.environ.get("ALLOW_INSECURE_LOOPBACK_MANAGEMENT") == "1"
    or os.environ.get("ZMODO_TESTING") == "1"
)
ALLOW_INSECURE_PRIVATE_MANAGEMENT = os.environ.get("ALLOW_INSECURE_PRIVATE_MANAGEMENT") == "1"
PRIVATE_HTTP_NETWORKS = tuple(
    ipaddress.ip_network(value.strip(), strict=False)
    for value in os.environ.get("PRIVATE_HTTP_NETWORKS", "").split(",")
    if value.strip()
)
ALLOW_OWNER_SETUP = os.environ.get("ALLOW_OWNER_SETUP") == "1" or os.environ.get("ZMODO_TESTING") == "1"
TRUSTED_PROXY_NETWORKS = tuple(
    ipaddress.ip_network(value.strip(), strict=False)
    for value in os.environ.get("TRUSTED_PROXY_NETWORKS", "172.28.178.0/24").split(",")
    if value.strip()
)
STATIC_AUTHENTICATED_CAMERA_IDS = frozenset(
    value.strip()
    for value in os.environ.get("STATIC_AUTHENTICATED_CAMERA_IDS", "").split(",")
    if value.strip()
)
EXTERNAL_CONTROL_HOSTS = frozenset(
    value.strip().lower()
    for value in os.environ.get("EXTERNAL_CONTROL_HOSTS", "czeview-bridge").split(",")
    if value.strip()
)
DUMMY_PASSWORD_HASH = PH.hash("CameraHub-Dummy-Password-Not-An-Account")


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = build_opener(NoRedirectHandler())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def read_secret(path: Path, test_name: str) -> bytes:
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        try:
            value = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except ValueError as exc:
            raise RuntimeError(f"invalid secret: {test_name}") from exc
        if len(value) >= 32:
            return value[:32]
    if os.environ.get("ZMODO_TESTING") == "1":
        return hashlib.sha256(test_name.encode()).digest()
    raise RuntimeError(f"missing secret file: {test_name}")


AES_KEY = read_secret(SECRET_PATH, "camera-encryption")
INTERNAL_TOKEN = base64.urlsafe_b64encode(read_secret(INTERNAL_TOKEN_PATH, "internal-api")).decode().rstrip("=")


def read_optional_service_token(path: Path, test_name: str) -> str:
    if not path.exists() and os.environ.get("ZMODO_TESTING") != "1":
        return ""
    return base64.urlsafe_b64encode(read_secret(path, test_name)).decode().rstrip("=")


CZEVIEW_ADAPTER_TOKEN = read_optional_service_token(CZEVIEW_ADAPTER_TOKEN_PATH, "czeview-adapter")
NETATMO_ADAPTER_TOKEN = read_optional_service_token(NETATMO_ADAPTER_TOKEN_PATH, "netatmo-adapter")


def encrypt_text(value: str) -> str:
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(AES_KEY).encrypt(nonce, value.encode(), b"zmodo-camera-secret-v1")
    return base64.urlsafe_b64encode(nonce + encrypted).decode()


def decrypt_text(value: str | None) -> str:
    if not value:
        return ""
    raw = base64.urlsafe_b64decode(value)
    return AESGCM(AES_KEY).decrypt(raw[:12], raw[12:], b"zmodo-camera-secret-v1").decode()


def encrypt_json(value: dict) -> str:
    return encrypt_text(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def decrypt_json(value: str | None) -> dict:
    plain = decrypt_text(value)
    return json.loads(plain) if plain else {}


SCHEMA = """
CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, elevated_until INTEGER NOT NULL, created_at TEXT NOT NULL, user_id TEXT REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, username_ct TEXT, password_ct TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cameras(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, position INTEGER NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
 source_label TEXT NOT NULL, low_path TEXT NOT NULL UNIQUE, high_path TEXT NOT NULL,
 detail_quality TEXT, managed INTEGER NOT NULL DEFAULT 0, address TEXT, protocol TEXT,
 port INTEGER, low_source_path TEXT, high_source_path TEXT, codec TEXT NOT NULL DEFAULT 'h264',
 high_webrtc_compatible INTEGER NOT NULL DEFAULT 1,
 force_transcode INTEGER NOT NULL DEFAULT 0,
 manufacturer TEXT, model TEXT, snapshot_uri TEXT, credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
 on_demand INTEGER NOT NULL DEFAULT 0,
 external_control_url TEXT, external_capabilities_json TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS zones(
 id TEXT PRIMARY KEY, camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('alarm','ignore')), points_json TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, revision INTEGER NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS zones_camera_idx ON zones(camera_id);
CREATE TABLE IF NOT EXISTS audit_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id TEXT, action TEXT NOT NULL,
 target_type TEXT NOT NULL, target_id TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log(created_at);
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS camera_connections(
 id TEXT PRIMARY KEY, camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('draft','active','last-good','rolled-back')),
 address TEXT NOT NULL, stream_protocol TEXT NOT NULL, stream_port INTEGER NOT NULL,
 low_source_path TEXT NOT NULL, high_source_path TEXT NOT NULL, codec TEXT NOT NULL,
 onvif_scheme TEXT NOT NULL DEFAULT 'http', onvif_port INTEGER NOT NULL DEFAULT 80,
 onvif_path TEXT NOT NULL DEFAULT '/onvif/device_service',
 credential_mode TEXT NOT NULL DEFAULT 'none' CHECK(credential_mode IN ('none','shared','separate')),
 shared_credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
 onvif_credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
 stream_credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
 tested_at TEXT, test_status TEXT NOT NULL DEFAULT 'untested', test_result_json TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, activated_at TEXT,
 UNIQUE(camera_id,revision)
);
CREATE INDEX IF NOT EXISTS connections_camera_idx ON camera_connections(camera_id,revision);
CREATE TABLE IF NOT EXISTS camera_capabilities(
 camera_id TEXT PRIMARY KEY REFERENCES cameras(id) ON DELETE CASCADE,
 connection_id TEXT REFERENCES camera_connections(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL, payload_json TEXT NOT NULL, checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS camera_profiles(
 id TEXT PRIMARY KEY, camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 connection_id TEXT NOT NULL REFERENCES camera_connections(id) ON DELETE CASCADE,
 token TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
 codec TEXT, width INTEGER, height INTEGER, frame_rate REAL, bitrate INTEGER,
 audio_codec TEXT, stream_path TEXT, snapshot_path TEXT,
 UNIQUE(connection_id,token)
);
CREATE INDEX IF NOT EXISTS profiles_camera_idx ON camera_profiles(camera_id,connection_id);
CREATE TABLE IF NOT EXISTS cloud_provider_configs(
 provider TEXT PRIMARY KEY CHECK(provider IN ('netatmo')),
 client_id_ct TEXT NOT NULL, client_secret_ct TEXT NOT NULL, redirect_uri TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cloud_accounts(
 id TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK(provider IN ('czeview','netatmo')),
 label TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, auth_payload_ct TEXT NOT NULL,
 auth_revision INTEGER NOT NULL DEFAULT 1,
 scopes_json TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending',
 last_error_code TEXT, last_verified_at TEXT, legacy_source TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cloud_accounts_provider_idx ON cloud_accounts(provider,enabled);
CREATE TABLE IF NOT EXISTS cloud_devices(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
 external_id_hash TEXT NOT NULL, external_id_ct TEXT NOT NULL, home_id_ct TEXT,
 name TEXT NOT NULL, model TEXT, manufacturer TEXT,
 capabilities_json TEXT NOT NULL DEFAULT '{}', stream_support TEXT NOT NULL DEFAULT 'unknown',
 last_error_code TEXT, last_seen_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(account_id,external_id_hash)
);
CREATE INDEX IF NOT EXISTS cloud_devices_account_idx ON cloud_devices(account_id,last_seen_at);
CREATE TABLE IF NOT EXISTS oauth_states(
 state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK(provider IN ('netatmo')),
 actor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, label TEXT NOT NULL,
 account_id TEXT REFERENCES cloud_accounts(id) ON DELETE CASCADE,
 redirect_uri TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS display_profiles(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, name_key TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS display_profiles_user_name_idx
 ON display_profiles(user_id,name_key);
CREATE TABLE IF NOT EXISTS display_profile_cameras(
 profile_id TEXT NOT NULL REFERENCES display_profiles(id) ON DELETE CASCADE,
 camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 PRIMARY KEY(profile_id,camera_id),
 UNIQUE(profile_id,position)
);
CREATE INDEX IF NOT EXISTS display_profile_cameras_camera_idx
 ON display_profile_cameras(camera_id);
"""


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)
        session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)")}
        if "user_id" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN user_id TEXT")
        camera_columns = {row["name"] for row in conn.execute("PRAGMA table_info(cameras)")}
        if "on_demand" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN on_demand INTEGER NOT NULL DEFAULT 0")
        if "external_control_url" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN external_control_url TEXT")
        if "external_capabilities_json" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN external_capabilities_json TEXT")
        if "cloud_device_id" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN cloud_device_id TEXT REFERENCES cloud_devices(id) ON DELETE SET NULL")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS cameras_cloud_device_idx ON cameras(cloud_device_id) WHERE cloud_device_id IS NOT NULL")
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=4").fetchone() is None:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS cameras_cloud_device_idx ON cameras(cloud_device_id) WHERE cloud_device_id IS NOT NULL"
            )
            conn.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(4,?)",
                (now_iso(),),
            )
        oauth_columns = {row["name"] for row in conn.execute("PRAGMA table_info(oauth_states)")}
        if "account_id" not in oauth_columns:
            conn.execute(
                "ALTER TABLE oauth_states ADD COLUMN account_id TEXT REFERENCES cloud_accounts(id) ON DELETE CASCADE"
            )
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=5").fetchone() is None:
            conn.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(5,?)",
                (now_iso(),),
            )
        cloud_account_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(cloud_accounts)")
        }
        if "auth_revision" not in cloud_account_columns:
            conn.execute(
                "ALTER TABLE cloud_accounts ADD COLUMN auth_revision INTEGER NOT NULL DEFAULT 1"
            )
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=6").fetchone() is None:
            conn.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(6,?)",
                (now_iso(),),
            )
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=7").fetchone() is None:
            conn.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(7,?)",
                (now_iso(),),
            )
        if "active_connection_id" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN active_connection_id TEXT")
        if "last_good_connection_id" not in camera_columns:
            conn.execute("ALTER TABLE cameras ADD COLUMN last_good_connection_id TEXT")
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=3").fetchone() is None:
            if "high_webrtc_compatible" not in camera_columns:
                conn.execute("ALTER TABLE cameras ADD COLUMN high_webrtc_compatible INTEGER NOT NULL DEFAULT 1")
            if "force_transcode" not in camera_columns:
                conn.execute("ALTER TABLE cameras ADD COLUMN force_transcode INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(3,?)",
                (now_iso(),),
            )
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            legacy = conn.execute("SELECT * FROM owner WHERE id=1").fetchone()
            if legacy:
                stamp = now_iso()
                conn.execute(
                    """INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at)
                       VALUES('owner',?,?,?,?,1,?,?)""",
                    (legacy["username"], legacy["username"], legacy["password_hash"], "owner", legacy["created_at"], stamp),
                )
                conn.execute("UPDATE sessions SET user_id='owner' WHERE user_id IS NULL")
        count = conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0]
        if count == 0 and SEED_PATH.exists():
            seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
            stamp = now_iso()
            for position, item in enumerate(seed.get("cameras", [])):
                address = item.get("address")
                if address and ipaddress.ip_address(address) not in ALLOWED_NETWORK:
                    raise RuntimeError(f"seed camera outside discovery network: {item['id']}")
                protocol = item.get("protocol") if address else None
                port = item.get("port") if address else None
                low_source_path = item.get("lowSourcePath") if address else None
                high_source_path = item.get("highSourcePath", low_source_path) if address else None
                conn.execute(
                    """INSERT INTO cameras(id,name,position,enabled,source_label,low_path,high_path,detail_quality,
                       managed,address,protocol,port,low_source_path,high_source_path,codec,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        item["id"], item["name"], position, int(item.get("enabled", True)),
                        item.get("source", "Direkt"), item["lowPath"], item.get("highPath", item["lowPath"]),
                        item.get("detailQuality"), int(item.get("managed", False)), address, protocol, port,
                        low_source_path, high_source_path, item.get("codec", "h264"), stamp, stamp,
                    ),
                )
        if conn.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone() is None:
            stamp = now_iso()
            cameras = conn.execute("SELECT * FROM cameras ORDER BY position").fetchall()
            for row in cameras:
                if conn.execute("SELECT 1 FROM camera_connections WHERE camera_id=?", (row["id"],)).fetchone():
                    continue
                if not row["address"]:
                    continue
                connection_id = str(uuid.uuid4())
                credential_mode = "shared" if row["credential_id"] else "none"
                conn.execute(
                    """INSERT INTO camera_connections(
                       id,camera_id,revision,state,address,stream_protocol,stream_port,low_source_path,high_source_path,codec,
                       onvif_scheme,onvif_port,onvif_path,credential_mode,shared_credential_id,test_status,
                       created_at,updated_at,activated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        connection_id, row["id"], 1, "active", row["address"],
                        row["protocol"] or "rtsp", row["port"] or 554, row["low_source_path"] or "/",
                        row["high_source_path"] or row["low_source_path"] or "/", row["codec"] or "h264",
                        "http", 80, "/onvif/device_service", credential_mode, row["credential_id"],
                        "legacy-active", stamp, stamp, stamp,
                    ),
                )
                conn.execute(
                    "UPDATE cameras SET active_connection_id=?,last_good_connection_id=? WHERE id=?",
                    (connection_id, connection_id, row["id"]),
                )
            conn.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)", (stamp,))
        interrupted = conn.execute(
            """SELECT c.id AS camera_id,c.active_connection_id,c.last_good_connection_id
               FROM cameras c JOIN camera_connections active ON active.id=c.active_connection_id
               WHERE active.test_status='untested' AND c.last_good_connection_id IS NOT NULL
               AND c.last_good_connection_id<>c.active_connection_id"""
        ).fetchall()
        for item in interrupted:
            fallback = conn.execute(
                """SELECT * FROM camera_connections WHERE id=? AND camera_id=?
                   AND test_status IN ('verified','legacy-active','stream-tested')""",
                (item["last_good_connection_id"], item["camera_id"]),
            ).fetchone()
            if not fallback:
                continue
            stamp = now_iso()
            conn.execute(
                "UPDATE camera_connections SET state='rolled-back',test_status='failed',updated_at=? WHERE id=?",
                (stamp, item["active_connection_id"]),
            )
            conn.execute("UPDATE camera_connections SET state='active',updated_at=? WHERE id=?", (stamp, fallback["id"]))
            conn.execute(
                """UPDATE cameras SET active_connection_id=?,address=?,protocol=?,port=?,low_source_path=?,
                   high_source_path=?,codec=?,high_webrtc_compatible=?,force_transcode=?,credential_id=?,updated_at=? WHERE id=?""",
                (
                    fallback["id"], fallback["address"], fallback["stream_protocol"], fallback["stream_port"],
                    fallback["low_source_path"], fallback["high_source_path"], fallback["codec"],
                    1, 0,
                    fallback["shared_credential_id"], stamp, item["camera_id"],
                ),
            )


initialize_database()
app = FastAPI(title="PKWS Multi Camera API", version="1.2.0", docs_url=None, redoc_url=None)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class SetupRequest(LoginRequest):
    pass


class ReauthRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    displayName: str = Field(min_length=1, max_length=80)
    role: Literal["owner", "admin", "viewer"]
    password: str = Field(min_length=8, max_length=256)


class UserPatch(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    displayName: str | None = Field(default=None, min_length=1, max_length=80)
    role: Literal["owner", "admin", "viewer"] | None = None
    enabled: bool | None = None


class UserPasswordReset(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class OwnPasswordChange(BaseModel):
    currentPassword: str = Field(min_length=8, max_length=256)
    newPassword: str = Field(min_length=8, max_length=256)


class Point(BaseModel):
    x: float = Field(ge=0, le=1)
    y: float = Field(ge=0, le=1)


class ZoneInput(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["alarm", "ignore"]
    points: list[Point] = Field(min_length=3, max_length=32)
    enabled: bool = True


class ZonesUpdate(BaseModel):
    revision: int = Field(ge=0)
    zones: list[ZoneInput] = Field(max_length=64)


class CameraCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str
    protocol: Literal["rtsp", "hls", "mjpeg", "snapshot"] = "rtsp"
    port: int = Field(ge=1, le=65535)
    lowSourcePath: str = Field(min_length=1, max_length=512)
    highSourcePath: str | None = Field(default=None, max_length=512)
    codec: Literal["h264", "h265", "mjpeg"] = "h264"
    username: str = Field(default="", max_length=128)
    password: str = Field(default="", max_length=256)
    onvifScheme: Literal["http", "https"] = "http"
    onvifPort: int = Field(ge=1, le=65535, default=80)
    onvifPath: str = Field(default="/onvif/device_service", min_length=1, max_length=256)
    manufacturer: str = Field(default="", max_length=128)
    model: str = Field(default="", max_length=128)

    @field_validator("address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if address not in ALLOWED_NETWORK:
            raise ValueError("address outside discovery network")
        return str(address)

    @field_validator("lowSourcePath", "highSourcePath")
    @classmethod
    def valid_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("/") or any(ch in value for ch in "\r\n@"):
            raise ValueError("invalid source path")
        return value

    @field_validator("onvifPath")
    @classmethod
    def valid_onvif_path(cls, value: str) -> str:
        if not value.startswith("/") or any(ch in value for ch in "\r\n@?#"):
            raise ValueError("invalid ONVIF path")
        return value


class DiscoveryProbeRequest(BaseModel):
    username: str = Field(default="", max_length=128)
    password: str = Field(default="", max_length=256)


class CameraPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None
    sourceLabel: str | None = Field(default=None, min_length=1, max_length=80)


class DisplayProfileInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    cameraIds: list[str] = Field(default_factory=list, max_length=MAX_CAMERAS)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("profile name must not be blank")
        return value


class ExternalCameraInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    sourceLabel: str = Field(min_length=1, max_length=80)
    codec: Literal["h264", "h265"] = "h264"
    manufacturer: str = Field(default="", max_length=128)
    model: str = Field(default="", max_length=128)
    detailQuality: str | None = Field(default=None, max_length=80)
    width: int | None = Field(default=None, ge=1, le=16384)
    height: int | None = Field(default=None, ge=1, le=16384)
    controlUrl: str | None = Field(default=None, max_length=256)
    ptzAxes: list[Literal["x", "y", "zoom"]] = Field(default_factory=list, max_length=3)

    @field_validator("controlUrl")
    @classmethod
    def valid_control_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("external control endpoint is not allowed") from exc
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.hostname.lower() not in EXTERNAL_CONTROL_HOSTS
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or port is None
        ):
            raise ValueError("external control endpoint is not allowed")
        return value.rstrip("/")


class ConnectionInput(BaseModel):
    address: str
    streamProtocol: Literal["rtsp", "hls", "mjpeg", "snapshot"] = "rtsp"
    streamPort: int = Field(ge=1, le=65535)
    lowSourcePath: str = Field(min_length=1, max_length=512)
    highSourcePath: str | None = Field(default=None, max_length=512)
    codec: Literal["h264", "h265", "mjpeg"] = "h264"
    onvifScheme: Literal["http", "https"] = "http"
    onvifPort: int = Field(ge=1, le=65535, default=80)
    onvifPath: str = Field(default="/onvif/device_service", min_length=1, max_length=256)
    credentialMode: Literal["none", "shared", "separate"] = "none"
    sharedUsername: str = Field(default="", max_length=128)
    sharedPassword: str = Field(default="", max_length=256)
    onvifUsername: str = Field(default="", max_length=128)
    onvifPassword: str = Field(default="", max_length=256)
    streamUsername: str = Field(default="", max_length=128)
    streamPassword: str = Field(default="", max_length=256)
    clearSharedCredentials: bool = False
    clearOnvifCredentials: bool = False
    clearStreamCredentials: bool = False
    baseRevision: int | None = Field(default=None, ge=1)

    @field_validator("address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if address not in ALLOWED_NETWORK:
            raise ValueError("address outside discovery network")
        return str(address)

    @field_validator("lowSourcePath", "highSourcePath", "onvifPath")
    @classmethod
    def valid_connection_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("/") or any(ch in value for ch in "\r\n@"):
            raise ValueError("invalid source path")
        return value


class CloudAccountPatch(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None


class CzeviewAccountCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    username: str = Field(min_length=1, max_length=160)
    email: str = Field(default="", max_length=254)
    password: str = Field(min_length=1, max_length=256)
    countryCode: str = Field(min_length=2, max_length=8)
    phoneCode: str = Field(min_length=1, max_length=8)
    sourceApp: str = Field(default="141", min_length=1, max_length=16)
    deviceSerial: str = Field(default="", max_length=256)
    cameraName: str = Field(default="", max_length=80)


class NetatmoProviderConfigInput(BaseModel):
    clientId: str = Field(min_length=1, max_length=256)
    clientSecret: str = Field(min_length=1, max_length=512)
    redirectUri: str = Field(min_length=1, max_length=1024)


class NetatmoAuthorizeInput(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    accountId: str | None = Field(default=None, min_length=1, max_length=64)


class CloudInventoryDevice(BaseModel):
    externalId: str = Field(min_length=1, max_length=512)
    homeId: str | None = Field(default=None, max_length=512)
    name: str = Field(min_length=1, max_length=160)
    model: str = Field(default="", max_length=128)
    manufacturer: str = Field(default="", max_length=128)
    capabilities: dict = Field(default_factory=dict)
    streamSupport: Literal["unknown", "unsupported", "candidate", "verified"] = "unknown"
    errorCode: str | None = Field(default=None, max_length=128)


class CloudInventoryUpdate(BaseModel):
    accountId: str
    status: Literal["pending", "active", "reauth-required", "error"] = "active"
    errorCode: str | None = Field(default=None, max_length=128)
    devices: list[CloudInventoryDevice] = Field(default_factory=list, max_length=128)


class CloudCameraImport(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)


class ConnectionActivation(BaseModel):
    revision: int = Field(ge=1)


class PTZMove(BaseModel):
    x: float = Field(ge=-0.65, le=0.65)
    y: float = Field(ge=-0.65, le=0.65)
    zoom: float = Field(ge=-0.65, le=0.65)
    profileToken: str = Field(min_length=1, max_length=128)


class PTZStop(BaseModel):
    profileToken: str = Field(min_length=1, max_length=128)


class OrderUpdate(BaseModel):
    cameraIds: list[str] = Field(min_length=1, max_length=MAX_CAMERAS)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def session_from_request(request: FastAPIRequest) -> sqlite3.Row:
    token = request.cookies.get("pkws_session")
    if not token:
        raise HTTPException(401, "authentication-required")
    with connect() as conn:
        row = conn.execute(
            """SELECT sessions.*,users.username,users.display_name,users.role,users.enabled
               FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token_hash=? AND sessions.expires_at>? AND users.enabled=1""",
            (hash_token(token), int(time.time())),
        ).fetchone()
    if not row:
        raise HTTPException(401, "session-expired")
    return row


def require_session(request: FastAPIRequest) -> sqlite3.Row:
    return session_from_request(request)


def require_csrf(request: FastAPIRequest, x_csrf_token: str = Header(default="")) -> sqlite3.Row:
    row = session_from_request(request)
    if not secrets.compare_digest(row["csrf"], x_csrf_token):
        raise HTTPException(403, "csrf-invalid")
    return row


def request_peer_ip(request: FastAPIRequest) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(request.client.host) if request.client else None
    except ValueError:
        return None


def request_from_trusted_proxy(request: FastAPIRequest) -> bool:
    peer = request_peer_ip(request)
    return bool(peer and any(peer in network for network in TRUSTED_PROXY_NETWORKS))


def request_is_secure(request: FastAPIRequest) -> bool:
    return request.url.scheme == "https" or (
        request_from_trusted_proxy(request)
        and request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() == "https"
    )


def request_allows_insecure_management(request: FastAPIRequest) -> bool:
    host = request.headers.get("host", "").split(":", 1)[0]
    if ALLOW_INSECURE_LOOPBACK_MANAGEMENT and host in {"127.0.0.1", "localhost"}:
        return True
    if not ALLOW_INSECURE_PRIVATE_MANAGEMENT:
        return False
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(host_ip in network for network in PRIVATE_HTTP_NETWORKS)


def effective_client_ip(request: FastAPIRequest) -> str:
    if request_from_trusted_proxy(request):
        candidate = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return str(request_peer_ip(request) or "unknown")


def require_elevated(request: FastAPIRequest, x_csrf_token: str = Header(default="")) -> sqlite3.Row:
    row = require_csrf(request, x_csrf_token)
    secure = request_is_secure(request)
    if not secure and not request_allows_insecure_management(request):
        raise HTTPException(426, "https-required-for-management")
    if row["elevated_until"] < int(time.time()):
        raise HTTPException(403, "reauth-required")
    return row


ROLE_LEVEL = {"viewer": 10, "admin": 20, "owner": 30}


def require_minimum_role(row: sqlite3.Row, minimum: str) -> sqlite3.Row:
    if ROLE_LEVEL.get(row["role"], 0) < ROLE_LEVEL[minimum]:
        raise HTTPException(403, "insufficient-role")
    return row


def require_admin(request: FastAPIRequest) -> sqlite3.Row:
    return require_minimum_role(session_from_request(request), "admin")


def require_admin_csrf(request: FastAPIRequest, x_csrf_token: str = Header(default="")) -> sqlite3.Row:
    return require_minimum_role(require_csrf(request, x_csrf_token), "admin")


def require_admin_elevated(request: FastAPIRequest, x_csrf_token: str = Header(default="")) -> sqlite3.Row:
    return require_minimum_role(require_elevated(request, x_csrf_token), "admin")


def require_owner(request: FastAPIRequest) -> sqlite3.Row:
    return require_minimum_role(session_from_request(request), "owner")


def require_owner_elevated(request: FastAPIRequest, x_csrf_token: str = Header(default="")) -> sqlite3.Row:
    return require_minimum_role(require_elevated(request, x_csrf_token), "owner")


def user_payload(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "username": row["username"], "displayName": row["display_name"],
        "role": row["role"], "enabled": bool(row["enabled"]), "createdAt": row["created_at"],
        "updatedAt": row["updated_at"], "lastLoginAt": row["last_login_at"],
    }


def session_user(row: sqlite3.Row) -> dict:
    return {"id": row["user_id"], "username": row["username"], "displayName": row["display_name"], "role": row["role"]}


def permissions_for(role: str) -> dict:
    return {
        "view": True,
        "manageCameras": ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL["admin"],
        "controlCameras": ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL["admin"],
        "manageZones": ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL["admin"],
        "discoverCameras": ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL["admin"],
        "manageUsers": role == "owner",
    }


NETATMO_AUTH_URL = "https://api.netatmo.com/oauth2/authorize"
NETATMO_TOKEN_URL = "https://api.netatmo.com/oauth2/token"
NETATMO_SCOPES = (
    "read_camera access_camera read_presence access_presence "
    "read_doorbell access_doorbell read_camerapro"
)


def cloud_account_payload(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "provider": row["provider"],
        "label": row["label"],
        "enabled": bool(row["enabled"]),
        "status": row["status"],
        "scopes": json.loads(row["scopes_json"] or "[]"),
        "lastErrorCode": row["last_error_code"],
        "lastVerifiedAt": row["last_verified_at"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def validate_netatmo_redirect_uri(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.path != "/api/cloud/oauth/netatmo/callback"
    ):
        raise HTTPException(422, "netatmo-redirect-uri-invalid")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
            permitted = address.is_loopback or any(address in network for network in PRIVATE_HTTP_NETWORKS)
        except ValueError:
            permitted = parsed.hostname.lower() == "localhost"
        if not permitted:
            raise HTTPException(422, "netatmo-http-redirect-must-be-private")
    return value


def form_request_json(url: str, values: dict[str, str], timeout: float = 10) -> dict:
    request = Request(
        url,
        data=urlencode(values).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as error:
        try:
            detail = json.loads(error.read().decode("utf-8", "replace"))
            code = str(detail.get("error") or detail.get("error_description") or "provider-request-failed")
        except Exception:
            code = "provider-request-failed"
        raise HTTPException(502, code) from error
    except (URLError, TimeoutError, ValueError) as error:
        raise HTTPException(502, "provider-unavailable") from error


def audit(conn: sqlite3.Connection, actor_id: str | None, action: str, target_type: str, target_id: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log(actor_user_id,action,target_type,target_id,created_at) VALUES(?,?,?,?,?)",
        (actor_id, action, target_type, target_id, now_iso()),
    )


def issue_session(response: Response, request: FastAPIRequest, user: sqlite3.Row) -> dict:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    now = int(time.time())
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
        conn.execute(
            "INSERT INTO sessions(token_hash,csrf,expires_at,elevated_until,created_at,user_id) VALUES(?,?,?,?,?,?)",
            (hash_token(token), csrf, now + SESSION_SECONDS, now + ELEVATION_SECONDS, now_iso(), user["id"]),
        )
    secure = request_is_secure(request)
    response.set_cookie("pkws_session", token, max_age=SESSION_SECONDS, httponly=True, secure=secure, samesite="strict", path="/")
    current = {"user_id": user["id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"]}
    return {
        "authenticated": True, "csrfToken": csrf, "elevatedUntil": now + ELEVATION_SECONDS,
        "user": session_user(current), "permissions": permissions_for(user["role"]),
    }


def public_camera(row: sqlite3.Row) -> dict:
    external_source = row["protocol"] == "external"
    with connect() as conn:
        capability_row = None if external_source else conn.execute(
            """SELECT cp.payload_json FROM camera_capabilities cp
               JOIN cameras c ON c.id=cp.camera_id
               WHERE cp.camera_id=? AND cp.connection_id=c.active_connection_id""",
            (row["id"],),
        ).fetchone()
        current = active_connection(conn, row["id"])
    capabilities = (
        json.loads(row["external_capabilities_json"])
        if external_source and row["external_capabilities_json"]
        else json.loads(capability_row["payload_json"])
        if capability_row
        else {}
    )
    active_stream_credentials = bool(
        current and (
            current["stream_credential_id"]
            or (current["credential_mode"] == "shared" and current["shared_credential_id"])
        )
    )
    uses_credentials = (
        active_stream_credentials
        if row["managed"]
        else external_source or row["id"] in STATIC_AUTHENTICATED_CAMERA_IDS
    )
    return {
        "id": row["id"], "name": row["name"], "lowPath": row["low_path"], "highPath": row["high_path"],
        "source": row["source_label"], "fallbackAvailable": False,
        "statusPath": f"/api/cameras/{row['id']}/status", "detailQuality": row["detail_quality"],
        "enabled": bool(row["enabled"]), "position": row["position"], "managed": bool(row["managed"]),
        "usesCredentials": uses_credentials, "externalSource": external_source,
        "onDemand": bool(row["on_demand"]),
        "highWebRTCCompatible": bool(row["high_webrtc_compatible"]),
        "compatibilityRelay": bool(row["force_transcode"]),
        "displayMode": "snapshot" if row["protocol"] == "snapshot" else "stream",
        "snapshotPath": f"/api/cameras/{row['id']}/snapshot" if row["protocol"] == "snapshot" else None,
        "features": {
            "audio": bool(
                capabilities.get("audio", {}).get("supported")
                and not row["force_transcode"]
            ),
            "ptz": bool(capabilities.get("ptz", {}).get("supported")),
            "ptzAxes": capabilities.get("ptz", {}).get("axes", []),
        },
    }


def admin_camera(row: sqlite3.Row, paths: dict[str, dict] | None = None, media_api_ok: bool | None = None) -> dict:
    result = public_camera(row)
    with connect() as conn:
        current = active_connection(conn, row["id"])
        draft = conn.execute(
            "SELECT * FROM camera_connections WHERE camera_id=? AND state='draft' ORDER BY revision DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
    active_flags = credential_flags(current) if current else {"mode": "none", "shared": False, "onvif": False, "stream": False}
    draft_flags = credential_flags(draft) if draft else {"mode": "none", "shared": False, "onvif": False, "stream": False}
    if paths is None or media_api_ok is None:
        paths, media_api_ok = media_paths()
    live_ready = bool(media_api_ok and paths.get(row["low_path"], {}).get("ready"))
    uses_active_revision = bool(row["managed"])
    external_source = row["protocol"] == "external"
    live_auth_configured = (
        bool(active_flags["stream"])
        if uses_active_revision
        else external_source or row["id"] in STATIC_AUTHENTICATED_CAMERA_IDS
    )
    credential_source = (
        "active-revision"
        if uses_active_revision
        else "external-secret"
        if external_source
        else "static-relay"
        if live_auth_configured
        else "none"
    )
    result.update({
        "address": row["address"], "protocol": row["protocol"], "port": row["port"], "codec": row["codec"],
        "manufacturer": row["manufacturer"], "model": row["model"],
        "hasCredentials": bool(active_flags["onvif"] or active_flags["stream"]),
        "activeCredentials": active_flags,
        "draftCredentials": draft_flags,
        "connectionState": current["test_status"] if current else "missing",
        "activeRevision": current["revision"] if current else None,
        "draftRevision": draft["revision"] if draft else None,
        "draftTestStatus": draft["test_status"] if draft else None,
        "relayMode": "dynamic" if row["managed"] else ("external-on-demand" if external_source else "static-rollback"),
        "liveAccess": {
            "ready": live_ready,
            "state": "live" if live_ready else ("media-server-offline" if not media_api_ok else "offline"),
            "usesActiveRevision": uses_active_revision,
            "credentialSource": credential_source,
            "authenticationConfigured": live_auth_configured,
            "authenticatedLive": bool(live_ready and live_auth_configured),
            "revision": current["revision"] if uses_active_revision and current else None,
        },
    })
    return result


def active_connection(conn: sqlite3.Connection, camera_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """SELECT cc.* FROM cameras c LEFT JOIN camera_connections cc ON cc.id=c.active_connection_id
           WHERE c.id=?""",
        (camera_id,),
    ).fetchone()


def connection_credentials(conn: sqlite3.Connection, row: sqlite3.Row, purpose: str) -> tuple[str, str]:
    credential_id = None
    if row["credential_mode"] == "shared":
        credential_id = row["shared_credential_id"]
    elif row["credential_mode"] == "separate":
        credential_id = row["onvif_credential_id"] if purpose == "onvif" else row["stream_credential_id"]
    if not credential_id:
        return "", ""
    credential = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    if not credential:
        return "", ""
    return decrypt_text(credential["username_ct"]), decrypt_text(credential["password_ct"])


def store_credential(conn: sqlite3.Connection, username: str, password: str) -> str | None:
    if not username and not password:
        return None
    credential_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO credentials VALUES(?,?,?,?)",
        (credential_id, encrypt_text(username), encrypt_text(password), now_iso()),
    )
    return credential_id


def inherited_credential(row: sqlite3.Row | None, purpose: str) -> str | None:
    if not row:
        return None
    if row["credential_mode"] == "shared":
        return row["shared_credential_id"]
    if row["credential_mode"] == "separate":
        return row["onvif_credential_id"] if purpose == "onvif" else row["stream_credential_id"]
    return None


def resolve_input_credentials(conn: sqlite3.Connection, body: ConnectionInput, prior: sqlite3.Row | None) -> tuple[str | None, str | None, str | None]:
    if body.credentialMode == "none":
        return None, None, None
    if body.credentialMode == "shared":
        credential_id = None if body.clearSharedCredentials else inherited_credential(prior, "stream")
        if body.sharedUsername or body.sharedPassword:
            credential_id = store_credential(conn, body.sharedUsername, body.sharedPassword)
        return credential_id, None, None
    onvif_id = None if body.clearOnvifCredentials else inherited_credential(prior, "onvif")
    stream_id = None if body.clearStreamCredentials else inherited_credential(prior, "stream")
    if body.onvifUsername or body.onvifPassword:
        onvif_id = store_credential(conn, body.onvifUsername, body.onvifPassword)
    if body.streamUsername or body.streamPassword:
        stream_id = store_credential(conn, body.streamUsername, body.streamPassword)
    return None, onvif_id, stream_id


def input_credential_pair(conn: sqlite3.Connection, body: ConnectionInput, prior: sqlite3.Row | None, purpose: str) -> tuple[str, str]:
    if body.credentialMode == "none":
        return "", ""
    if body.credentialMode == "shared":
        if body.sharedUsername or body.sharedPassword:
            return body.sharedUsername, body.sharedPassword
        credential_id = inherited_credential(prior, "stream")
    else:
        username = body.onvifUsername if purpose == "onvif" else body.streamUsername
        password = body.onvifPassword if purpose == "onvif" else body.streamPassword
        if username or password:
            return username, password
        credential_id = inherited_credential(prior, purpose)
    if not credential_id:
        return "", ""
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return (decrypt_text(row["username_ct"]), decrypt_text(row["password_ct"])) if row else ("", "")


def credential_flags(row: sqlite3.Row) -> dict:
    return {
        "mode": row["credential_mode"],
        "shared": bool(row["shared_credential_id"]),
        "onvif": bool(row["onvif_credential_id"] or (row["credential_mode"] == "shared" and row["shared_credential_id"])),
        "stream": bool(row["stream_credential_id"] or (row["credential_mode"] == "shared" and row["shared_credential_id"])),
    }


def connection_payload(row: sqlite3.Row, *, include_address: bool = True) -> dict:
    result = {
        "id": row["id"], "cameraId": row["camera_id"], "revision": row["revision"], "state": row["state"],
        "streamProtocol": row["stream_protocol"], "streamPort": row["stream_port"],
        "lowSourcePath": row["low_source_path"], "highSourcePath": row["high_source_path"],
        "codec": row["codec"], "onvifScheme": row["onvif_scheme"], "onvifPort": row["onvif_port"],
        "onvifPath": row["onvif_path"], "credentials": credential_flags(row),
        "testedAt": row["tested_at"], "testStatus": row["test_status"], "activatedAt": row["activated_at"],
    }
    if include_address:
        result["address"] = row["address"]
    return result


def base_connection(conn: sqlite3.Connection, camera_id: str, revision: int | None) -> sqlite3.Row | None:
    if revision is not None:
        row = conn.execute(
            "SELECT * FROM camera_connections WHERE camera_id=? AND revision=?",
            (camera_id, revision),
        ).fetchone()
        if not row:
            raise HTTPException(409, "base-connection-not-found")
        return row
    return active_connection(conn, camera_id)


def connection_input_digest(camera_id: str, body: ConnectionInput) -> str:
    canonical = body.model_dump_json(exclude_none=False)
    return hashlib.sha256(AES_KEY + camera_id.encode() + canonical.encode()).hexdigest()


def safe_onvif_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        return parsed.scheme in {"http", "https"} and address in ALLOWED_NETWORK and not parsed.username and not parsed.password
    except ValueError:
        return False


def onvif_client_for(conn: sqlite3.Connection, row: sqlite3.Row) -> OnvifClient:
    username, password = connection_credentials(conn, row, "onvif")
    device_url = f"{row['onvif_scheme']}://{row['address']}:{row['onvif_port']}{row['onvif_path']}"
    return OnvifClient(device_url, username, password, timeout=4, allowed_url=safe_onvif_url)


def source_uri_from_connection(conn: sqlite3.Connection, row: sqlite3.Row, high: bool = False) -> str:
    path = row["high_source_path"] if high else row["low_source_path"]
    username, password = connection_credentials(conn, row, "stream")
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
    scheme = "http" if row["stream_protocol"] in {"hls", "mjpeg", "snapshot"} else "rtsp"
    return f"{scheme}://{auth}{row['address']}:{row['stream_port']}{path}"


def connection_high_webrtc_compatible(row: sqlite3.Row, fallback: bool = True) -> bool:
    if row["high_source_path"] == row["low_source_path"]:
        return True
    try:
        result = json.loads(row["test_result_json"] or "{}")
        high = result.get("stream", {}).get("high", {})
        if high.get("ok"):
            return not int(high.get("hasBFrames") or 0)
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return fallback


def connection_requires_transcode(row: sqlite3.Row, fallback: bool = False) -> bool:
    try:
        result = json.loads(row["test_result_json"] or "{}")
        streams = result.get("stream", {})
        tested = [streams.get("low", {}), streams.get("high", {})]
        successful = [item for item in tested if item.get("ok")]
        if successful:
            return any(int(item.get("hasBFrames") or 0) > 0 for item in successful)
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return fallback


def media_paths() -> tuple[dict[str, dict], bool]:
    try:
        with urlopen(f"{MEDIAMTX_API}/v3/paths/list", timeout=2) as response:
            payload = json.load(response)
        return {item.get("name", ""): item for item in payload.get("items", [])}, True
    except Exception:
        return {}, False


def mediamtx_config_request(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{MEDIAMTX_API}{path}",
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response) if response.length not in (None, 0) else {}


def capture_rtsp_frame(path: str, timeout: int = 12) -> bytes:
    uri = f"rtsp://mediamtx:8554/{quote(path, safe='')}"
    command = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-rtsp_transport", "tcp",
        "-i", uri, "-frames:v", "1", "-an", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1",
    ]
    if not PREVIEW_SEMAPHORE.acquire(timeout=15):
        raise HTTPException(429, "preview-busy")
    try:
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(504, "preview-timeout") from exc
    finally:
        PREVIEW_SEMAPHORE.release()
    if result.returncode != 0 or not result.stdout.startswith(b"\xff\xd8"):
        raise HTTPException(502, "preview-frame-unavailable")
    return result.stdout


def transient_rtsp_preview(source_uri: str) -> bytes:
    """Resolve one frame without exposing or persisting the authenticated source URI."""
    path = "discovery-preview-" + secrets.token_urlsafe(12).replace("_", "").replace("-", "")
    encoded = quote(path, safe="")
    try:
        mediamtx_config_request(
            f"/v3/config/paths/add/{encoded}",
            "POST",
            {"source": source_uri, "sourceOnDemand": False, "rtspTransport": "tcp", "record": False},
        )
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                if mediamtx_config_request(f"/v3/paths/get/{encoded}").get("ready"):
                    return capture_rtsp_frame(path)
            except (HTTPError, OSError, ValueError):
                pass
            time.sleep(0.4)
        raise HTTPException(504, "preview-stream-timeout")
    except HTTPException:
        raise
    except (HTTPError, OSError, ValueError) as exc:
        raise HTTPException(502, "preview-stream-failed") from exc
    finally:
        try:
            mediamtx_config_request(f"/v3/config/paths/delete/{encoded}", "DELETE")
        except (HTTPError, OSError, ValueError):
            pass


def camera_status(row: sqlite3.Row, paths: dict[str, dict], api_ok: bool) -> dict:
    path = paths.get(row["low_path"], {})
    live = bool(path.get("ready"))
    return {
        "camera": row["id"], "state": "live" if live else ("media-server-offline" if not api_ok else "offline"),
        "source": row["source_label"], "lastFrameAt": now_iso() if live else None, "relayRunning": live,
        "webRTCOutputAvailable": live, "hlsOutputAvailable": live,
    }


@app.middleware("http")
async def security_headers(request: FastAPIRequest, call_next):
    if (
        HTTP_DIAGNOSTIC_ONLY
        and not request_allows_insecure_management(request)
        and not request_is_secure(request)
        and request.method not in {"GET", "HEAD", "OPTIONS"}
        and request.url.path.startswith("/api/")
    ):
        response = JSONResponse({"detail": "https-required-for-application"}, status_code=426)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    host = request.headers.get("host", "127.0.0.1").split(":", 1)[0]
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        host = "127.0.0.1"
    secure = request_is_secure(request)
    media_sources = "'self' blob:" if secure else f"'self' blob: http://{host}:8888"
    connect_sources = "'self'" if secure else f"'self' http://{host}:8889"
    frame_sources = "'self'" if secure else f"'self' http://{host}:8888"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
        f"media-src {media_sources}; connect-src {connect_sources}; frame-src {frame_sources}; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.url.path.startswith(("/api/", "/internal/")):
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/auth/state")
def auth_state(request: FastAPIRequest):
    with connect() as conn:
        setup = ALLOW_OWNER_SETUP and conn.execute("SELECT 1 FROM users").fetchone() is None
    try:
        row = session_from_request(request)
        return {
            "setupRequired": setup, "authenticated": True, "csrfToken": row["csrf"],
            "elevatedUntil": row["elevated_until"], "user": session_user(row),
            "permissions": permissions_for(row["role"]),
        }
    except HTTPException:
        return {"setupRequired": setup, "authenticated": False}


@app.post("/api/auth/setup")
def setup_owner(body: SetupRequest, request: FastAPIRequest, response: Response):
    if not ALLOW_OWNER_SETUP:
        raise HTTPException(403, "setup-disabled")
    host = request.headers.get("host", "").split(":", 1)[0]
    if host not in {"127.0.0.1", "localhost"}:
        raise HTTPException(403, "setup-loopback-only")
    with connect() as conn:
        if conn.execute("SELECT 1 FROM users").fetchone():
            raise HTTPException(409, "setup-complete")
        stamp = now_iso()
        password_hash = PH.hash(body.password)
        conn.execute("INSERT INTO owner VALUES(1,?,?,?)", (body.username, password_hash, stamp))
        conn.execute(
            """INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at)
               VALUES('owner',?,?,?,'owner',1,?,?)""",
            (body.username, body.username, password_hash, stamp, stamp),
        )
        user = conn.execute("SELECT * FROM users WHERE id='owner'").fetchone()
        audit(conn, user["id"], "user.setup", "user", user["id"])
    return issue_session(response, request, user)


@app.post("/api/auth/login")
def login(body: LoginRequest, request: FastAPIRequest, response: Response):
    remote = f"{effective_client_ip(request)}:{body.username.casefold()}"
    cutoff = time.time() - 300
    LOGIN_ATTEMPTS[remote] = [stamp for stamp in LOGIN_ATTEMPTS.get(remote, []) if stamp > cutoff]
    if len(LOGIN_ATTEMPTS[remote]) >= 5:
        raise HTTPException(429, "login-rate-limited")
    with connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND enabled=1", (body.username,)).fetchone()
    valid = False
    try:
        valid = PH.verify(user["password_hash"] if user else DUMMY_PASSWORD_HASH, body.password)
    except Exception:
        valid = False
    if not valid:
        LOGIN_ATTEMPTS[remote].append(time.time())
        raise HTTPException(401, "login-failed")
    LOGIN_ATTEMPTS.pop(remote, None)
    with connect() as conn:
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (now_iso(), user["id"]))
    return issue_session(response, request, user)


@app.post("/api/auth/reauth")
def reauth(body: ReauthRequest, request: FastAPIRequest, x_csrf_token: str = Header(default="")):
    row = require_csrf(request, x_csrf_token)
    attempt_key = f"{effective_client_ip(request)}:{row['user_id']}"
    cutoff = time.time() - 300
    REAUTH_ATTEMPTS[attempt_key] = [stamp for stamp in REAUTH_ATTEMPTS.get(attempt_key, []) if stamp > cutoff]
    if len(REAUTH_ATTEMPTS[attempt_key]) >= 5:
        raise HTTPException(429, "reauth-rate-limited")
    with connect() as conn:
        user = conn.execute("SELECT password_hash FROM users WHERE id=?", (row["user_id"],)).fetchone()
        try:
            valid = PH.verify(user["password_hash"], body.password)
        except Exception:
            valid = False
        if not valid:
            REAUTH_ATTEMPTS[attempt_key].append(time.time())
            raise HTTPException(401, "reauth-failed")
        REAUTH_ATTEMPTS.pop(attempt_key, None)
        elevated = int(time.time()) + ELEVATION_SECONDS
        conn.execute("UPDATE sessions SET elevated_until=? WHERE token_hash=?", (elevated, row["token_hash"]))
    return {"elevatedUntil": elevated}


@app.post("/api/auth/change-password")
def change_own_password(body: OwnPasswordChange, request: FastAPIRequest, x_csrf_token: str = Header(default="")):
    row = require_csrf(request, x_csrf_token)
    with connect() as conn:
        user = conn.execute("SELECT password_hash FROM users WHERE id=?", (row["user_id"],)).fetchone()
        try:
            valid = PH.verify(user["password_hash"], body.currentPassword)
        except Exception:
            valid = False
        if not valid:
            raise HTTPException(401, "current-password-invalid")
        conn.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (PH.hash(body.newPassword), now_iso(), row["user_id"]))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (row["user_id"], row["token_hash"]))
        if row["role"] == "owner":
            conn.execute("UPDATE owner SET password_hash=? WHERE id=1", (PH.hash(body.newPassword),))
        audit(conn, row["user_id"], "user.password.changed", "user", row["user_id"])
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(request: FastAPIRequest, response: Response, _: sqlite3.Row = Depends(require_csrf)):
    token = request.cookies.get("pkws_session", "")
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(token),))
    response.delete_cookie("pkws_session", path="/")
    return {"ok": True}


@app.get("/api/auth/authorize")
def authorize_media(_: sqlite3.Row = Depends(require_session)):
    return Response(status_code=204)


@app.get("/api/admin/users")
def list_users(_: sqlite3.Row = Depends(require_owner)):
    with connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, username COLLATE NOCASE").fetchall()
    return {"users": [user_payload(row) for row in rows]}


@app.post("/api/admin/users")
def create_user(body: UserCreate, actor: sqlite3.Row = Depends(require_owner_elevated)):
    user_id = str(uuid.uuid4())
    stamp = now_iso()
    try:
        with DB_LOCK, connect() as conn:
            conn.execute(
                """INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at)
                   VALUES(?,?,?,?,?,1,?,?)""",
                (user_id, body.username, body.displayName, PH.hash(body.password), body.role, stamp, stamp),
            )
            audit(conn, actor["user_id"], "user.created", "user", user_id)
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "username-already-exists")
    return user_payload(row)


@app.patch("/api/admin/users/{user_id}")
def update_user(user_id: str, body: UserPatch, actor: sqlite3.Row = Depends(require_owner_elevated)):
    with DB_LOCK, connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user-not-found")
        if user_id == actor["user_id"] and (
            (body.role is not None and body.role != target["role"]) or body.enabled is False or
            (body.username is not None and body.username.casefold() != target["username"].casefold())
        ):
            raise HTTPException(409, "cannot-change-own-access")
        next_role = body.role if body.role is not None else target["role"]
        next_enabled = int(body.enabled) if body.enabled is not None else target["enabled"]
        if target["role"] == "owner" and target["enabled"] and (next_role != "owner" or not next_enabled):
            owners = conn.execute("SELECT COUNT(*) FROM users WHERE role='owner' AND enabled=1").fetchone()[0]
            if owners <= 1:
                raise HTTPException(409, "last-owner-required")
        changes, values = [], []
        for field, column in (("username", "username"), ("displayName", "display_name"), ("role", "role"), ("enabled", "enabled")):
            value = getattr(body, field)
            if value is not None:
                changes.append(f"{column}=?")
                values.append(int(value) if isinstance(value, bool) else value)
        if not changes:
            raise HTTPException(400, "no-changes")
        values.extend([now_iso(), user_id])
        try:
            conn.execute(f"UPDATE users SET {','.join(changes)},updated_at=? WHERE id=?", values)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "username-already-exists")
        if not next_enabled or next_role != target["role"]:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(conn, actor["user_id"], "user.updated", "user", user_id)
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return user_payload(row)


@app.post("/api/admin/users/{user_id}/password")
def reset_user_password(user_id: str, body: UserPasswordReset, actor: sqlite3.Row = Depends(require_owner_elevated)):
    with DB_LOCK, connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user-not-found")
        new_hash = PH.hash(body.password)
        conn.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (new_hash, now_iso(), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, actor["token_hash"] if user_id == actor["user_id"] else ""))
        if target["role"] == "owner" and target["id"] == "owner":
            conn.execute("UPDATE owner SET password_hash=? WHERE id=1", (new_hash,))
        audit(conn, actor["user_id"], "user.password.reset", "user", user_id)
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def remove_user(user_id: str, actor: sqlite3.Row = Depends(require_owner_elevated)):
    if user_id == actor["user_id"]:
        raise HTTPException(409, "cannot-delete-self")
    with DB_LOCK, connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "user-not-found")
        if target["role"] == "owner" and target["enabled"]:
            owners = conn.execute("SELECT COUNT(*) FROM users WHERE role='owner' AND enabled=1").fetchone()[0]
            if owners <= 1:
                raise HTTPException(409, "last-owner-required")
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        audit(conn, actor["user_id"], "user.deleted", "user", user_id)
    return Response(status_code=204)


@app.get("/api/admin/cloud/providers")
def list_cloud_providers(_: sqlite3.Row = Depends(require_owner)):
    with connect() as conn:
        netatmo = conn.execute(
            "SELECT provider,redirect_uri,created_at,updated_at FROM cloud_provider_configs WHERE provider='netatmo'"
        ).fetchone()
    return {
        "providers": [
            {
                "id": "czeview",
                "configured": True,
                "authentication": "credentials",
            },
            {
                "id": "netatmo",
                "configured": bool(netatmo),
                "authentication": "oauth2",
                "redirectUri": netatmo["redirect_uri"] if netatmo else None,
                "updatedAt": netatmo["updated_at"] if netatmo else None,
            },
        ]
    }


@app.put("/api/admin/cloud/providers/netatmo")
def configure_netatmo_provider(
    body: NetatmoProviderConfigInput,
    actor: sqlite3.Row = Depends(require_owner_elevated),
):
    redirect_uri = validate_netatmo_redirect_uri(body.redirectUri)
    stamp = now_iso()
    with DB_LOCK, connect() as conn:
        conn.execute(
            """INSERT INTO cloud_provider_configs(
               provider,client_id_ct,client_secret_ct,redirect_uri,created_at,updated_at)
               VALUES('netatmo',?,?,?,?,?)
               ON CONFLICT(provider) DO UPDATE SET client_id_ct=excluded.client_id_ct,
               client_secret_ct=excluded.client_secret_ct,redirect_uri=excluded.redirect_uri,
               updated_at=excluded.updated_at""",
            (encrypt_text(body.clientId), encrypt_text(body.clientSecret), redirect_uri, stamp, stamp),
        )
        audit(conn, actor["user_id"], "cloud.provider.configured", "cloud-provider", "netatmo")
    return {"id": "netatmo", "configured": True, "redirectUri": redirect_uri, "updatedAt": stamp}


@app.get("/api/admin/cloud/accounts")
def list_cloud_accounts(_: sqlite3.Row = Depends(require_owner)):
    with connect() as conn:
        rows = conn.execute(
            """SELECT a.*,(SELECT COUNT(*) FROM cloud_devices d WHERE d.account_id=a.id) AS device_count
               FROM cloud_accounts a ORDER BY a.provider,a.label COLLATE NOCASE"""
        ).fetchall()
    accounts = []
    for row in rows:
        item = cloud_account_payload(row)
        item["deviceCount"] = row["device_count"]
        accounts.append(item)
    return {"accounts": accounts}


@app.post("/api/admin/cloud/accounts/czeview")
def create_czeview_account(
    body: CzeviewAccountCreate,
    actor: sqlite3.Row = Depends(require_owner_elevated),
):
    account_id, stamp = str(uuid.uuid4()), now_iso()
    auth = {
        "username": body.username,
        "email": body.email,
        "login": body.email or body.username,
        "password": body.password,
        "countryCode": body.countryCode,
        "phoneCode": body.phoneCode,
        "sourceApp": body.sourceApp,
        "deviceSerial": body.deviceSerial,
        "cameraName": body.cameraName,
    }
    with DB_LOCK, connect() as conn:
        conn.execute(
            """INSERT INTO cloud_accounts(
               id,provider,label,enabled,auth_payload_ct,scopes_json,status,created_at,updated_at)
               VALUES(?,'czeview',?,1,?,'[]','pending',?,?)""",
            (account_id, body.label, encrypt_json(auth), stamp, stamp),
        )
        audit(conn, actor["user_id"], "cloud.account.created", "cloud-account", account_id)
        row = conn.execute("SELECT * FROM cloud_accounts WHERE id=?", (account_id,)).fetchone()
    return cloud_account_payload(row)


@app.put("/api/admin/cloud/accounts/{account_id}/czeview")
def replace_czeview_account_credentials(
    account_id: str,
    body: CzeviewAccountCreate,
    actor: sqlite3.Row = Depends(require_owner_elevated),
):
    auth = {
        "username": body.username,
        "email": body.email,
        "login": body.email or body.username,
        "password": body.password,
        "countryCode": body.countryCode,
        "phoneCode": body.phoneCode,
        "sourceApp": body.sourceApp,
        "deviceSerial": body.deviceSerial,
        "cameraName": body.cameraName,
    }
    with DB_LOCK, connect() as conn:
        row = conn.execute(
            "SELECT * FROM cloud_accounts WHERE id=? AND provider='czeview'",
            (account_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "czeview-account-not-found")
        conn.execute(
            """UPDATE cloud_accounts SET label=?,auth_payload_ct=?,auth_revision=auth_revision+1,
               enabled=1,status='pending',
               last_error_code=NULL,last_verified_at=NULL,updated_at=? WHERE id=?""",
            (body.label, encrypt_json(auth), now_iso(), account_id),
        )
        audit(conn, actor["user_id"], "cloud.account.credentials.replaced", "cloud-account", account_id)
        row = conn.execute("SELECT * FROM cloud_accounts WHERE id=?", (account_id,)).fetchone()
    return cloud_account_payload(row)


@app.post("/api/admin/cloud/accounts/netatmo/authorize")
def authorize_netatmo_account(
    body: NetatmoAuthorizeInput,
    actor: sqlite3.Row = Depends(require_owner_elevated),
):
    with DB_LOCK, connect() as conn:
        config = conn.execute("SELECT * FROM cloud_provider_configs WHERE provider='netatmo'").fetchone()
        if not config:
            raise HTTPException(409, "netatmo-provider-not-configured")
        if body.accountId:
            account = conn.execute(
                "SELECT * FROM cloud_accounts WHERE id=? AND provider='netatmo'",
                (body.accountId,),
            ).fetchone()
            if not account:
                raise HTTPException(404, "netatmo-account-not-found")
        state = secrets.token_urlsafe(32)
        conn.execute("DELETE FROM oauth_states WHERE expires_at<=?", (int(time.time()),))
        conn.execute(
            """INSERT INTO oauth_states(
               state_hash,provider,actor_user_id,label,account_id,redirect_uri,expires_at,created_at)
               VALUES(?,'netatmo',?,?,?,?,?,?)""",
            (
                hash_token(state),
                actor["user_id"],
                body.label,
                body.accountId,
                config["redirect_uri"],
                int(time.time()) + 600,
                now_iso(),
            ),
        )
        client_id = decrypt_text(config["client_id_ct"])
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": config["redirect_uri"],
            "scope": NETATMO_SCOPES,
            "state": state,
        }
    )
    return {"authorizationUrl": f"{NETATMO_AUTH_URL}?{query}", "expiresIn": 600}


@app.get("/api/cloud/oauth/netatmo/callback")
def netatmo_oauth_callback(state: str = "", code: str = "", error: str = ""):
    if error:
        return RedirectResponse(url=f"/#discover?netatmo={quote(error, safe='')}", status_code=303)
    if not state or not code:
        raise HTTPException(400, "oauth-callback-incomplete")
    with DB_LOCK, connect() as conn:
        stored = conn.execute(
            """SELECT s.*,p.client_id_ct,p.client_secret_ct
               FROM oauth_states s JOIN cloud_provider_configs p ON p.provider=s.provider
               WHERE s.state_hash=? AND s.provider='netatmo'""",
            (hash_token(state),),
        ).fetchone()
        if not stored or stored["expires_at"] < int(time.time()):
            if stored:
                conn.execute("DELETE FROM oauth_states WHERE state_hash=?", (hash_token(state),))
            raise HTTPException(400, "oauth-state-invalid")
        conn.execute("DELETE FROM oauth_states WHERE state_hash=?", (hash_token(state),))
    token = form_request_json(
        NETATMO_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": decrypt_text(stored["client_id_ct"]),
            "client_secret": decrypt_text(stored["client_secret_ct"]),
            "code": code,
            "redirect_uri": stored["redirect_uri"],
        },
    )
    if not token.get("access_token") or not token.get("refresh_token"):
        raise HTTPException(502, "netatmo-token-response-invalid")
    account_id, stamp = stored["account_id"] or str(uuid.uuid4()), now_iso()
    expires_at = int(time.time()) + max(60, int(token.get("expires_in") or 10800))
    auth = {
        "accessToken": token["access_token"],
        "refreshToken": token["refresh_token"],
        "expiresAt": expires_at,
    }
    scopes = str(token.get("scope") or NETATMO_SCOPES).split()
    with DB_LOCK, connect() as conn:
        if stored["account_id"]:
            updated = conn.execute(
                """UPDATE cloud_accounts SET label=?,enabled=1,auth_payload_ct=?,scopes_json=?,
                   status='active',last_error_code=NULL,last_verified_at=?,updated_at=?
                   WHERE id=? AND provider='netatmo'""",
                (
                    stored["label"],
                    encrypt_json(auth),
                    json.dumps(scopes),
                    stamp,
                    stamp,
                    account_id,
                ),
            )
            if updated.rowcount != 1:
                raise HTTPException(409, "netatmo-account-reconnect-failed")
            action = "cloud.account.reconnected"
        else:
            conn.execute(
                """INSERT INTO cloud_accounts(
                   id,provider,label,enabled,auth_payload_ct,scopes_json,status,last_verified_at,created_at,updated_at)
                   VALUES(?,'netatmo',?,1,?,?, 'active',?,?,?)""",
                (account_id, stored["label"], encrypt_json(auth), json.dumps(scopes), stamp, stamp, stamp),
            )
            action = "cloud.account.created"
        audit(conn, stored["actor_user_id"], action, "cloud-account", account_id)
    return RedirectResponse(url="/#discover?netatmo=connected", status_code=303)


@app.patch("/api/admin/cloud/accounts/{account_id}")
def update_cloud_account(
    account_id: str,
    body: CloudAccountPatch,
    actor: sqlite3.Row = Depends(require_owner_elevated),
):
    changes, values = [], []
    if body.label is not None:
        changes.append("label=?")
        values.append(body.label)
    if body.enabled is not None:
        changes.append("enabled=?")
        values.append(int(body.enabled))
    if not changes:
        raise HTTPException(400, "no-changes")
    with DB_LOCK, connect() as conn:
        if not conn.execute("SELECT 1 FROM cloud_accounts WHERE id=?", (account_id,)).fetchone():
            raise HTTPException(404, "cloud-account-not-found")
        values.extend([now_iso(), account_id])
        conn.execute(f"UPDATE cloud_accounts SET {','.join(changes)},updated_at=? WHERE id=?", values)
        audit(conn, actor["user_id"], "cloud.account.updated", "cloud-account", account_id)
        row = conn.execute("SELECT * FROM cloud_accounts WHERE id=?", (account_id,)).fetchone()
    return cloud_account_payload(row)


@app.delete("/api/admin/cloud/accounts/{account_id}")
def delete_cloud_account(account_id: str, actor: sqlite3.Row = Depends(require_owner_elevated)):
    with DB_LOCK, connect() as conn:
        row = conn.execute("SELECT * FROM cloud_accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise HTTPException(404, "cloud-account-not-found")
        linked = conn.execute(
            """SELECT COUNT(*) FROM cameras c JOIN cloud_devices d ON d.id=c.cloud_device_id
               WHERE d.account_id=?""",
            (account_id,),
        ).fetchone()[0]
        if linked:
            raise HTTPException(409, "cloud-account-has-linked-cameras")
        conn.execute("DELETE FROM cloud_accounts WHERE id=?", (account_id,))
        audit(conn, actor["user_id"], "cloud.account.deleted", "cloud-account", account_id)
    return Response(status_code=204)


def display_profile_payload(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    camera_ids = [
        item["camera_id"]
        for item in conn.execute(
            "SELECT camera_id FROM display_profile_cameras WHERE profile_id=? ORDER BY position",
            (row["id"],),
        )
    ]
    return {
        "id": row["id"],
        "name": row["name"],
        "cameraIds": camera_ids,
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def validate_display_profile_cameras(conn: sqlite3.Connection, camera_ids: list[str]) -> None:
    if len(set(camera_ids)) != len(camera_ids):
        raise HTTPException(400, "duplicate-camera-id")
    if not camera_ids:
        return
    placeholders = ",".join("?" for _ in camera_ids)
    existing = {
        row["id"]
        for row in conn.execute(
            f"SELECT id FROM cameras WHERE id IN ({placeholders})",
            camera_ids,
        )
    }
    if existing != set(camera_ids):
        raise HTTPException(400, "invalid-camera-selection")


def replace_display_profile_cameras(
    conn: sqlite3.Connection, profile_id: str, camera_ids: list[str]
) -> None:
    conn.execute("DELETE FROM display_profile_cameras WHERE profile_id=?", (profile_id,))
    conn.executemany(
        "INSERT INTO display_profile_cameras(profile_id,camera_id,position) VALUES(?,?,?)",
        [(profile_id, camera_id, position) for position, camera_id in enumerate(camera_ids)],
    )


@app.get("/api/display-profiles")
def list_display_profiles(current: sqlite3.Row = Depends(require_session)):
    with connect() as conn:
        profiles = conn.execute(
            "SELECT * FROM display_profiles WHERE user_id=? ORDER BY name COLLATE NOCASE,id",
            (current["user_id"],),
        ).fetchall()
        cameras = conn.execute(
            "SELECT id,name,enabled,position FROM cameras ORDER BY position"
        ).fetchall()
        payloads = [display_profile_payload(conn, row) for row in profiles]
    return {
        "profiles": payloads,
        "cameraOptions": [
            {
                "id": row["id"],
                "name": row["name"],
                "enabled": bool(row["enabled"]),
                "position": row["position"],
            }
            for row in cameras
        ],
    }


@app.post("/api/display-profiles", status_code=201)
def create_display_profile(
    body: DisplayProfileInput, current: sqlite3.Row = Depends(require_csrf)
):
    profile_id, stamp = str(uuid.uuid4()), now_iso()
    try:
        with DB_LOCK, connect() as conn:
            validate_display_profile_cameras(conn, body.cameraIds)
            conn.execute(
                """INSERT INTO display_profiles(id,user_id,name,name_key,created_at,updated_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    current["user_id"],
                    body.name,
                    body.name.casefold(),
                    stamp,
                    stamp,
                ),
            )
            replace_display_profile_cameras(conn, profile_id, body.cameraIds)
            row = conn.execute(
                "SELECT * FROM display_profiles WHERE id=?", (profile_id,)
            ).fetchone()
            result = display_profile_payload(conn, row)
    except sqlite3.IntegrityError as exc:
        if "display_profiles.user_id, display_profiles.name_key" in str(exc):
            raise HTTPException(409, "display-profile-name-exists") from exc
        raise
    return result


@app.put("/api/display-profiles/{profile_id}")
def update_display_profile(
    profile_id: str,
    body: DisplayProfileInput,
    current: sqlite3.Row = Depends(require_csrf),
):
    try:
        with DB_LOCK, connect() as conn:
            row = conn.execute(
                "SELECT * FROM display_profiles WHERE id=? AND user_id=?",
                (profile_id, current["user_id"]),
            ).fetchone()
            if not row:
                raise HTTPException(404, "display-profile-not-found")
            validate_display_profile_cameras(conn, body.cameraIds)
            conn.execute(
                "UPDATE display_profiles SET name=?,name_key=?,updated_at=? WHERE id=?",
                (body.name, body.name.casefold(), now_iso(), profile_id),
            )
            replace_display_profile_cameras(conn, profile_id, body.cameraIds)
            row = conn.execute(
                "SELECT * FROM display_profiles WHERE id=?", (profile_id,)
            ).fetchone()
            result = display_profile_payload(conn, row)
    except sqlite3.IntegrityError as exc:
        if "display_profiles.user_id, display_profiles.name_key" in str(exc):
            raise HTTPException(409, "display-profile-name-exists") from exc
        raise
    return result


@app.delete("/api/display-profiles/{profile_id}")
def delete_display_profile(
    profile_id: str, current: sqlite3.Row = Depends(require_csrf)
):
    with DB_LOCK, connect() as conn:
        cursor = conn.execute(
            "DELETE FROM display_profiles WHERE id=? AND user_id=?",
            (profile_id, current["user_id"]),
        )
        if cursor.rowcount == 0:
            raise HTTPException(404, "display-profile-not-found")
    return Response(status_code=204)


@app.get("/api/cameras")
def list_cameras(
    profileId: str | None = None, current: sqlite3.Row = Depends(require_session)
):
    with connect() as conn:
        if profileId:
            profile = conn.execute(
                "SELECT 1 FROM display_profiles WHERE id=? AND user_id=?",
                (profileId, current["user_id"]),
            ).fetchone()
            if not profile:
                raise HTTPException(404, "display-profile-not-found")
            rows = conn.execute(
                """SELECT c.* FROM display_profile_cameras dpc
                   JOIN cameras c ON c.id=dpc.camera_id
                   WHERE dpc.profile_id=? AND c.enabled=1
                   ORDER BY dpc.position""",
                (profileId,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cameras WHERE enabled=1 ORDER BY position"
            ).fetchall()
    return {"cameras": [public_camera(row) for row in rows]}


@app.get("/api/admin/cameras")
def list_admin_cameras(_: sqlite3.Row = Depends(require_admin)):
    with connect() as conn:
        rows = conn.execute("SELECT * FROM cameras ORDER BY position").fetchall()
    paths, media_api_ok = media_paths()
    return {"cameras": [admin_camera(row, paths, media_api_ok) for row in rows]}


@app.get("/api/health")
def health(_: sqlite3.Row = Depends(require_session)):
    paths, ok = media_paths()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM cameras WHERE enabled=1 ORDER BY position").fetchall()
    return JSONResponse({"mediaMTX": "online" if ok else "offline", "cameras": [camera_status(row, paths, ok) for row in rows]}, status_code=200 if ok else 503)


@app.get("/healthz")
def healthz():
    paths, ok = media_paths()
    with connect() as conn:
        expected_paths = {
            row["low_path"]
            for row in conn.execute(
                """SELECT low_path FROM cameras
                   WHERE enabled=1 AND protocol!='snapshot' AND on_demand=0
                     AND (managed=0 OR codec='h264')"""
            )
        }
    expected = len(expected_paths)
    ready = sum(1 for name in expected_paths if paths.get(name, {}).get("ready"))
    status = "ok" if ok and ready >= expected else "starting"
    return JSONResponse({"status": status, "mediaServer": "online" if ok else "offline", "sourcesReady": ready, "sourcesExpected": expected}, status_code=200 if ok else 503)


@app.get("/api/cameras/{camera_id}/status")
def one_status(camera_id: str, _: sqlite3.Row = Depends(require_session)):
    with connect() as conn:
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
    if not row:
        raise HTTPException(404, "camera-not-found")
    paths, ok = media_paths()
    return camera_status(row, paths, ok)


def netatmo_access_token(account_id: str) -> str:
    lock = NETATMO_TOKEN_LOCKS.setdefault(account_id, threading.Lock())
    with lock:
        with connect() as conn:
            row = conn.execute(
                """SELECT a.*,p.client_id_ct,p.client_secret_ct FROM cloud_accounts a
                   JOIN cloud_provider_configs p ON p.provider=a.provider
                   WHERE a.id=? AND a.provider='netatmo' AND a.enabled=1""",
                (account_id,),
            ).fetchone()
        if not row:
            raise HTTPException(404, "netatmo-account-not-found")
        auth = decrypt_json(row["auth_payload_ct"])
        if auth.get("accessToken") and int(auth.get("expiresAt") or 0) > int(time.time()) + 90:
            return str(auth["accessToken"])
        try:
            token = form_request_json(
                NETATMO_TOKEN_URL,
                {
                    "grant_type": "refresh_token",
                    "refresh_token": str(auth.get("refreshToken") or ""),
                    "client_id": decrypt_text(row["client_id_ct"]),
                    "client_secret": decrypt_text(row["client_secret_ct"]),
                },
            )
        except HTTPException as exc:
            with DB_LOCK, connect() as conn:
                conn.execute(
                    """UPDATE cloud_accounts SET status='reauth-required',last_error_code=?,
                       updated_at=? WHERE id=?""",
                    (str(exc.detail)[:128], now_iso(), account_id),
                )
            raise
        if not token.get("access_token"):
            raise HTTPException(502, "netatmo-refresh-response-invalid")
        auth["accessToken"] = token["access_token"]
        auth["refreshToken"] = token.get("refresh_token") or auth.get("refreshToken")
        auth["expiresAt"] = int(time.time()) + max(60, int(token.get("expires_in") or 10800))
        with DB_LOCK, connect() as conn:
            conn.execute(
                """UPDATE cloud_accounts SET auth_payload_ct=?,status='active',last_error_code=NULL,
                   last_verified_at=?,updated_at=? WHERE id=?""",
                (encrypt_json(auth), now_iso(), now_iso(), account_id),
            )
        return str(auth["accessToken"])


def netatmo_api_json(account_id: str, path: str, params: dict[str, str] | None = None) -> dict:
    query = f"?{urlencode(params)}" if params else ""
    request = Request(
        f"https://api.netatmo.com/api/{path}{query}",
        headers={
            "Authorization": f"Bearer {netatmo_access_token(account_id)}",
            "Accept": "application/json",
            "User-Agent": "PKWS-CameraHub/1",
        },
    )
    try:
        with urlopen(request, timeout=12) as response:
            result = json.load(response)
    except HTTPError as error:
        code = "netatmo-authentication-failed" if error.code in {401, 403} else "netatmo-api-failed"
        with DB_LOCK, connect() as conn:
            conn.execute(
                "UPDATE cloud_accounts SET status=?,last_error_code=?,updated_at=? WHERE id=?",
                ("reauth-required" if error.code == 401 else "error", code, now_iso(), account_id),
            )
        raise HTTPException(502, code) from error
    except (URLError, TimeoutError, ValueError) as error:
        raise HTTPException(502, "netatmo-unavailable") from error
    return result.get("body") if isinstance(result.get("body"), dict) else result


def refresh_netatmo_inventory(account_id: str) -> None:
    body = netatmo_api_json(account_id, "homesdata")
    homes = body.get("homes") or []
    devices: list[CloudInventoryDevice] = []
    for home in homes:
        home_id = str(home.get("id") or "")
        candidates = list(home.get("cameras") or [])
        candidates.extend(
            item
            for item in (home.get("modules") or [])
            if str(item.get("type") or "").upper() in {"NACAMERA", "NOC", "NDB", "NPC"}
        )
        for camera in candidates:
            external_id = str(camera.get("id") or camera.get("mac") or "")
            if not external_id:
                continue
            model = str(camera.get("type") or camera.get("module_name") or "Netatmo Kamera")
            unsupported = model.upper() == "NPC"
            devices.append(
                CloudInventoryDevice(
                    externalId=external_id,
                    homeId=home_id or None,
                    name=str(camera.get("name") or camera.get("module_name") or model),
                    model=model,
                    manufacturer="Netatmo",
                    capabilities={"provider": "netatmo", "homeName": str(home.get("name") or "")},
                    streamSupport="unsupported" if unsupported else "candidate",
                    errorCode="netatmo-npc-third-party-live-unavailable" if unsupported else None,
                )
            )
    update_cloud_inventory("netatmo", account_id, devices, "active", None)


def update_cloud_inventory(
    provider: str,
    account_id: str,
    devices: list[CloudInventoryDevice],
    status: str,
    error_code: str | None,
) -> None:
    stamp = now_iso()
    with DB_LOCK, connect() as conn:
        account = conn.execute(
            "SELECT * FROM cloud_accounts WHERE id=? AND provider=?",
            (account_id, provider),
        ).fetchone()
        if not account:
            raise HTTPException(404, "cloud-account-not-found")
        conn.execute(
            """UPDATE cloud_accounts SET status=?,last_error_code=?,last_verified_at=?,
               updated_at=? WHERE id=?""",
            (status, error_code, stamp if status == "active" else account["last_verified_at"], stamp, account_id),
        )
        for device in devices:
            external_hash = hashlib.blake2b(
                f"{provider}:{account_id}:{device.externalId}".encode(),
                key=AES_KEY,
                digest_size=32,
            ).hexdigest()
            existing = conn.execute(
                "SELECT id,stream_support FROM cloud_devices WHERE account_id=? AND external_id_hash=?",
                (account_id, external_hash),
            ).fetchone()
            device_id = existing["id"] if existing else str(uuid.uuid4())
            stream_support = (
                "unsupported"
                if device.streamSupport == "unsupported"
                else "verified"
                if existing and existing["stream_support"] == "verified"
                else device.streamSupport
            )
            conn.execute(
                """INSERT INTO cloud_devices(
                   id,account_id,external_id_hash,external_id_ct,home_id_ct,name,model,manufacturer,
                   capabilities_json,stream_support,last_error_code,last_seen_at,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(account_id,external_id_hash) DO UPDATE SET
                   external_id_ct=excluded.external_id_ct,home_id_ct=excluded.home_id_ct,
                   name=excluded.name,model=excluded.model,manufacturer=excluded.manufacturer,
                   capabilities_json=excluded.capabilities_json,stream_support=excluded.stream_support,
                   last_error_code=excluded.last_error_code,last_seen_at=excluded.last_seen_at,
                   updated_at=excluded.updated_at""",
                (
                    device_id,
                    account_id,
                    external_hash,
                    encrypt_text(device.externalId),
                    encrypt_text(device.homeId) if device.homeId else None,
                    device.name,
                    device.model,
                    device.manufacturer,
                    json.dumps(device.capabilities, separators=(",", ":")),
                    stream_support,
                    device.errorCode,
                    stamp,
                    stamp,
                    stamp,
                ),
            )


def cloud_discovery_results() -> list[dict]:
    with connect() as conn:
        accounts = conn.execute(
            "SELECT id FROM cloud_accounts WHERE provider='netatmo' AND enabled=1"
        ).fetchall()
    for account in accounts:
        try:
            refresh_netatmo_inventory(account["id"])
        except HTTPException:
            continue
    with connect() as conn:
        rows = conn.execute(
            """SELECT d.*,a.provider,a.label AS account_label,a.status AS account_status,
               c.id AS configured_camera_id,c.name AS configured_name
               FROM cloud_devices d JOIN cloud_accounts a ON a.id=d.account_id
               LEFT JOIN cameras c ON c.cloud_device_id=d.id
               WHERE a.enabled=1 ORDER BY a.provider,a.label,d.name"""
        ).fetchall()
    return [
        {
            "id": str(uuid.uuid4()),
            "origin": "cloud",
            "provider": row["provider"],
            "accountId": row["account_id"],
            "accountLabel": row["account_label"],
            "cloudDeviceId": row["id"],
            "name": row["name"],
            "manufacturer": row["manufacturer"] or row["provider"],
            "model": row["model"] or "Unbekannt",
            "streamSupport": row["stream_support"],
            "available": row["stream_support"] != "unsupported" and row["account_status"] == "active",
            "reason": row["last_error_code"],
            "configuredCameraId": row["configured_camera_id"],
            "configuredName": row["configured_name"],
            "previewAvailable": bool(row["configured_camera_id"]),
            "previewVerified": row["stream_support"] == "verified",
        }
        for row in rows
    ]


def safe_netatmo_stream_base(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
            return None
        if parsed.scheme == "https":
            hostname = parsed.hostname.lower()
            return value.rstrip("/") if hostname.endswith((".netatmo.net", ".netatmo.com")) else None
        if parsed.scheme != "http":
            return None
        address = ipaddress.ip_address(parsed.hostname)
        return value.rstrip("/") if address.is_private or address.is_loopback else None
    except ValueError:
        return None


def netatmo_stream_candidates(device_id: str) -> list[str]:
    cached = NETATMO_STREAM_CACHE.get(device_id)
    if cached and cached[0] > time.time():
        return cached[1]
    with connect() as conn:
        row = conn.execute(
            """SELECT d.*,a.provider FROM cloud_devices d JOIN cloud_accounts a ON a.id=d.account_id
               WHERE d.id=? AND a.provider='netatmo' AND a.enabled=1""",
            (device_id,),
        ).fetchone()
    if not row or row["stream_support"] == "unsupported":
        return []
    external_id = decrypt_text(row["external_id_ct"])
    home_id = decrypt_text(row["home_id_ct"])
    status = netatmo_api_json(row["account_id"], "homestatus", {"home_id": home_id})
    home = status.get("home") or {}
    candidates = list(home.get("cameras") or []) + list(home.get("modules") or [])
    camera = next((item for item in candidates if str(item.get("id") or item.get("mac") or "") == external_id), None)
    base = safe_netatmo_stream_base(str((camera or {}).get("vpn_url") or ""))
    urls = (
        [
            f"{base}/live/index.m3u8",
            f"{base}/live/files/high/index.m3u8",
            f"{base}/live/files/medium/index.m3u8",
        ]
        if base
        else []
    )
    NETATMO_STREAM_CACHE[device_id] = (time.time() + 60, urls)
    return urls


def probe_port(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def rtsp_options(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: PKWS-Discovery/1\r\n\r\n"
            sock.sendall(request.encode("ascii"))
            return sock.recv(512).startswith(b"RTSP/")
    except OSError:
        return False


def onvif_info(ip: str, port: int) -> tuple[bool, str, str]:
    scheme = "https" if port == 443 else "http"
    soap = b'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'''
    try:
        req = Request(f"{scheme}://{ip}:{port}/onvif/device_service", data=soap, headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "PKWS-Discovery/1"})
        with NO_REDIRECT_OPENER.open(req, timeout=2) as response:
            body = response.read(65536).decode("utf-8", "ignore")
        if "GetDeviceInformationResponse" not in body:
            return False, "", ""
        manufacturer = re.search(r"<(?:\w+:)?Manufacturer>([^<]+)", body)
        model = re.search(r"<(?:\w+:)?Model>([^<]+)", body)
        return True, manufacturer.group(1) if manufacturer else "", model.group(1) if model else ""
    except HTTPError as error:
        return (True, "", "") if error.code in {401, 403} else (False, "", "")
    except Exception:
        return False, "", ""


def soap_read(url: str, body: bytes) -> bytes:
    req = Request(url, data=body, headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "PKWS-Discovery/1"})
    if not safe_device_url(url):
        raise HTTPException(400, "onvif-endpoint-outside-network")
    with NO_REDIRECT_OPENER.open(req, timeout=2) as response:
        return response.read(262144)


def xml_values(payload: bytes, name: str) -> list[str]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return []
    return [(node.text or "").strip() for node in root.iter() if node.tag.rsplit("}", 1)[-1] == name and (node.text or "").strip()]


def safe_device_url(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        if parsed.scheme not in {"http", "https"} or address not in ALLOWED_NETWORK or parsed.username or parsed.password:
            return None
        return value
    except ValueError:
        return None


def safe_stream_path(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        if parsed.scheme != "rtsp" or address not in ALLOWED_NETWORK or not parsed.path.startswith("/"):
            return None
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    except ValueError:
        return None


def onvif_inventory(ip: str, port: int) -> dict:
    supported, manufacturer, model = onvif_info(ip, port)
    result = {"supported": supported, "manufacturer": manufacturer, "model": model, "profiles": [], "snapshotUri": None}
    if not supported:
        return result
    scheme = "https" if port == 443 else "http"
    device_url = f"{scheme}://{ip}:{port}/onvif/device_service"
    capabilities = b'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Category>Media</tds:Category></tds:GetCapabilities></s:Body></s:Envelope>'''
    try:
        capability_payload = soap_read(device_url, capabilities)
        candidates = [safe_device_url(value) for value in xml_values(capability_payload, "XAddr")]
    except Exception:
        candidates = []
    media_urls = [value for value in candidates if value]
    media_urls.extend([f"{scheme}://{ip}:{port}/onvif/Media", f"{scheme}://{ip}:{port}/onvif/media_service"])
    profiles_body = b'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>'''
    profiles_payload = b""
    media_url = None
    for candidate in dict.fromkeys(media_urls):
        try:
            profiles_payload = soap_read(candidate, profiles_body)
            if b"Profiles" in profiles_payload:
                media_url = candidate
                break
        except Exception:
            continue
    if not media_url:
        return result
    try:
        root = ET.fromstring(profiles_payload)
    except ET.ParseError:
        return result
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "Profiles":
            continue
        token = node.attrib.get("token", "")
        values: dict[str, str] = {}
        for child in node.iter():
            local = child.tag.rsplit("}", 1)[-1]
            if local in {"Name", "Encoding", "Width", "Height"} and local not in values and child.text:
                values[local] = child.text.strip()
        profile = {"token": token, "name": values.get("Name", token or "Profil"), "codec": values.get("Encoding", "").lower(), "width": int(values["Width"]) if values.get("Width", "").isdigit() else None, "height": int(values["Height"]) if values.get("Height", "").isdigit() else None}
        result["profiles"].append(profile)
    if result["profiles"]:
        for profile in result["profiles"][:12]:
            token = profile["token"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            stream_body = f'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetStreamUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:StreamSetup><tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream><tt:Transport xmlns:tt="http://www.onvif.org/ver10/schema"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri></s:Body></s:Envelope>'''.encode()
            try:
                stream_values = xml_values(soap_read(media_url, stream_body), "Uri")
                profile["streamPath"] = safe_stream_path(stream_values[0]) if stream_values else None
            except Exception:
                profile["streamPath"] = None
        token = result["profiles"][0]["token"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        snapshot_body = f'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetSnapshotUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetSnapshotUri></s:Body></s:Envelope>'''.encode()
        try:
            snapshot_values = xml_values(soap_read(media_url, snapshot_body), "Uri")
            if snapshot_values:
                result["snapshotUri"] = safe_device_url(snapshot_values[0])
        except Exception:
            pass
    return result


def ws_discovery() -> set[str]:
    message_id = f"uuid:{uuid.uuid4()}"
    probe = f'''<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>{message_id}</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>'''.encode()
    found: set[str] = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.6)
        sock.sendto(probe, ("239.255.255.250", 3702))
        deadline = time.time() + 2.5
        while time.time() < deadline:
            try:
                payload, sender = sock.recvfrom(65535)
            except socket.timeout:
                continue
            candidates = {sender[0]}
            text = payload.decode("utf-8", "ignore")
            for xaddr in re.findall(r"https?://[^<\s]+", text):
                if urlparse(xaddr).hostname:
                    candidates.add(urlparse(xaddr).hostname)
            for candidate in candidates:
                try:
                    address = ipaddress.ip_address(candidate)
                    if address in ALLOWED_NETWORK:
                        found.add(str(address))
                except ValueError:
                    continue
    except OSError:
        pass
    finally:
        sock.close()
    return found


def discovery_sort_key(item: dict) -> tuple:
    if item.get("origin") == "cloud":
        return (1, item.get("provider", ""), item.get("accountLabel", ""), item.get("name", ""))
    return (0, int(ipaddress.ip_address(item["address"])), "", "")


def scan_network(scan_id: str) -> None:
    with SCAN_LOCK:
        try:
            SCANS[scan_id].update(state="running", startedAt=now_iso())
            discovered = ws_discovery()
            with connect() as conn:
                configured = {}
                for row in conn.execute(
                    """SELECT cc.address,cc.camera_id,cc.stream_protocol,cc.stream_port,cc.onvif_port,
                              c.name,c.low_path,c.manufacturer,c.model,
                              cp.payload_json
                       FROM camera_connections cc
                       JOIN cameras c ON c.id=cc.camera_id
                       LEFT JOIN camera_capabilities cp
                         ON cp.camera_id=c.id AND cp.connection_id=cc.id
                       WHERE cc.state='active'"""
                ):
                    try:
                        saved_capabilities = json.loads(row["payload_json"] or "{}")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        saved_capabilities = {}
                    configured[row["address"]] = {
                        "cameraId": row["camera_id"],
                        "name": row["name"],
                        "lowPath": row["low_path"],
                        "streamProtocol": row["stream_protocol"],
                        "streamPort": row["stream_port"],
                        "onvifPort": row["onvif_port"],
                        "manufacturer": row["manufacturer"] or "",
                        "model": row["model"] or "",
                        "profiles": saved_capabilities.get("profiles", []),
                    }
            results = cloud_discovery_results() + [
                {
                    "id": str(uuid.uuid4()),
                    "origin": "local",
                    "address": address,
                    "manufacturer": known["manufacturer"] or "Unbekannt",
                    "model": known["model"] or "Unbekannt",
                    "onvif": bool(known["onvifPort"]),
                    "onvifPort": known["onvifPort"],
                    "rtsp": known["streamProtocol"] == "rtsp",
                    "wsDiscovery": address in discovered,
                    "openPorts": sorted(set(filter(None, (known["streamPort"], known["onvifPort"])))),
                    "profiles": known["profiles"],
                    "previewAvailable": True,
                    "configuredCameraId": known["cameraId"],
                    "configuredName": known["name"],
                    "_snapshotUri": None,
                    "_configuredPreviewPath": known["lowPath"],
                }
                for address, known in configured.items()
                if ipaddress.ip_address(address) in ALLOWED_NETWORK
            ]
            results.sort(key=discovery_sort_key)
            SCANS[scan_id].update(results=list(results))
            # Known cameras and WS-Discovery responders are checked first. This
            # avoids starving devices that limit parallel management sockets.
            priority_hosts = discovered | set(configured)
            hosts = sorted(
                (str(ip) for ip in ALLOWED_NETWORK.hosts()),
                key=lambda ip: (ip not in priority_hosts, ipaddress.ip_address(ip)),
            )
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def inspect_host(ip: str):
                known = configured.get(ip)
                if known:
                    return None
                open_ports = []
                for port in SCAN_PORTS:
                    # Some authenticated consumer cameras throttle or delay new
                    # RTSP/ONVIF sockets while a live session is active. Give
                    # only these two standard ports one bounded slow retry.
                    if (
                        probe_port(ip, port)
                        or probe_port(ip, port)
                        or (port in (554, 2020) and probe_port(ip, port, 1.5))
                    ):
                        open_ports.append(port)
                if known:
                    stream_port = known.get("streamPort")
                    if stream_port and stream_port not in open_ports and rtsp_options(ip, stream_port):
                        open_ports.append(stream_port)
                    onvif_port = known.get("onvifPort")
                    if onvif_port and onvif_port not in open_ports and probe_port(ip, onvif_port, 2.5):
                        open_ports.append(onvif_port)
                    open_ports.sort()
                if not open_ports:
                    return None
                inventory = {"supported": False, "manufacturer": "", "model": "", "profiles": [], "snapshotUri": None}
                onvif_port = None
                for port in [p for p in open_ports if p in (80, 443, 2020, 8000, 8080, 8899, 10080)]:
                    inventory = onvif_inventory(ip, port)
                    if inventory["supported"]:
                        onvif_port = port
                        break
                rtsp_ports = [p for p in open_ports if p in (554, 8554, 10554)]
                rtsp = any(rtsp_options(ip, port) for port in rtsp_ports)
                if not inventory["supported"] and not rtsp:
                    return None
                saved_profiles = known["profiles"] if known and known["profiles"] else []
                return {
                    "id": str(uuid.uuid4()),
                    "origin": "local",
                    "address": ip,
                    "manufacturer": inventory["manufacturer"] or (known["manufacturer"] if known else "") or "Unbekannt",
                    "model": inventory["model"] or (known["model"] if known else "") or "Unbekannt",
                    "onvif": inventory["supported"],
                    "onvifPort": onvif_port,
                    "rtsp": rtsp,
                    "wsDiscovery": ip in discovered,
                    "openPorts": open_ports,
                    "profiles": inventory["profiles"] or saved_profiles,
                    "previewAvailable": bool(inventory["snapshotUri"] or known),
                    "configuredCameraId": known["cameraId"] if known else None,
                    "configuredName": known["name"] if known else None,
                    "_snapshotUri": inventory["snapshotUri"],
                    "_configuredPreviewPath": known["lowPath"] if known else None,
                }
            with ThreadPoolExecutor(max_workers=24) as pool:
                futures = [pool.submit(inspect_host, ip) for ip in hosts]
                for completed, future in enumerate(as_completed(futures), start=1):
                    if SCANS[scan_id]["state"] == "cancel-requested":
                        for pending in futures:
                            pending.cancel()
                        SCANS[scan_id].update(state="cancelled", completedAt=now_iso(), results=[])
                        return
                    item = future.result()
                    if item:
                        results.append(item)
                        results.sort(key=discovery_sort_key)
                    SCANS[scan_id].update(results=list(results), completedHosts=completed, totalHosts=len(hosts))
            results.sort(key=discovery_sort_key)
            SCANS[scan_id].update(state="complete", completedAt=now_iso(), results=results)
        except Exception:
            SCANS[scan_id].update(state="failed", completedAt=now_iso(), error="scan-failed")


@app.post("/api/admin/discovery/scans")
def start_scan(_: sqlite3.Row = Depends(require_admin_elevated)):
    cutoff = time.time() - SCAN_TTL_SECONDS
    for key in list(SCANS):
        if SCANS[key]["createdEpoch"] < cutoff:
            del SCANS[key]
            for preview_key in [item for item in DISCOVERY_PREVIEW_CACHE if item[0] == key]:
                DISCOVERY_PREVIEW_CACHE.pop(preview_key, None)
    if any(item["state"] in {"queued", "running"} for item in SCANS.values()):
        raise HTTPException(409, "scan-already-running")
    if SCANS and time.time() - max(item["createdEpoch"] for item in SCANS.values()) < 60:
        raise HTTPException(429, "scan-cooldown-active")
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {"id": scan_id, "state": "queued", "network": str(ALLOWED_NETWORK), "createdAt": now_iso(), "createdEpoch": time.time(), "results": [], "completedHosts": 0, "totalHosts": ALLOWED_NETWORK.num_addresses - 2}
    threading.Thread(target=scan_network, args=(scan_id,), daemon=True).start()
    return {key: value for key, value in SCANS[scan_id].items() if key != "createdEpoch"}


@app.get("/api/admin/discovery/scans/{scan_id}")
def get_scan(scan_id: str, _: sqlite3.Row = Depends(require_admin)):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan-not-found")
    result = {key: value for key, value in scan.items() if key != "createdEpoch"}
    result["results"] = [{key: value for key, value in item.items() if not key.startswith("_")} for item in scan.get("results", [])]
    return result


def discovery_item(scan_id: str, device_id: str) -> tuple[dict, dict]:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan-not-found")
    item = next((candidate for candidate in scan.get("results", []) if candidate["id"] == device_id), None)
    if not item:
        raise HTTPException(404, "device-not-found")
    if item.get("origin") != "cloud":
        try:
            if ipaddress.ip_address(item["address"]) not in ALLOWED_NETWORK:
                raise HTTPException(400, "device-outside-discovery-network")
        except ValueError as exc:
            raise HTTPException(400, "device-address-invalid") from exc
    return scan, item


def public_discovery_item(item: dict) -> dict:
    return {key: value for key, value in item.items() if not key.startswith("_")}


@app.post("/api/admin/discovery/scans/{scan_id}/devices/{device_id}/probe")
def probe_discovery_streams(
    scan_id: str,
    device_id: str,
    body: DiscoveryProbeRequest,
    _: sqlite3.Row = Depends(require_admin_elevated),
):
    """Authenticate transiently, enumerate ONVIF profiles and prove one real video frame."""
    _, item = discovery_item(scan_id, device_id)
    if item.get("configuredCameraId"):
        raise HTTPException(409, "device-already-configured")
    if item.get("origin") == "cloud":
        if item.get("streamSupport") == "unsupported":
            raise HTTPException(422, item.get("reason") or "cloud-device-stream-unsupported")
        with connect() as conn:
            device = conn.execute(
                """SELECT d.*,a.provider FROM cloud_devices d JOIN cloud_accounts a ON a.id=d.account_id
                   WHERE d.id=? AND a.enabled=1""",
                (item["cloudDeviceId"],),
            ).fetchone()
        if not device:
            raise HTTPException(404, "cloud-device-not-found")
        probe_path = f"cloud-probe-{secrets.token_hex(8)}"
        lease = {
            "cameraId": f"probe-{device['id']}",
            "path": probe_path,
            "deviceId": device["id"],
            "accountId": device["account_id"],
            "active": True,
        }
        if device["provider"] == "czeview":
            lease["externalId"] = decrypt_text(device["external_id_ct"])
        CLOUD_PROBE_LEASES[device["id"]] = {
            "provider": device["provider"],
            "expiresAt": time.time() + 75,
            "lease": lease,
        }
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                paths, media_ok = media_paths()
                if media_ok and paths.get(probe_path, {}).get("ready"):
                    try:
                        frame = capture_rtsp_frame(probe_path, timeout=15)
                        break
                    except HTTPException:
                        pass
                time.sleep(0.75)
            else:
                raise HTTPException(504, f"{device['provider']}-preview-source-timeout")
        finally:
            CLOUD_PROBE_LEASES.pop(device["id"], None)
        DISCOVERY_PREVIEW_CACHE[(scan_id, device_id)] = (time.time() + 5 * 60, frame)
        with DB_LOCK, connect() as conn:
            conn.execute(
                """UPDATE cloud_devices SET stream_support='verified',last_error_code=NULL,
                   updated_at=? WHERE id=?""",
                (now_iso(), device["id"]),
            )
        item.update(
            streamSupport="verified",
            available=True,
            reason=None,
            previewAvailable=True,
            previewVerified=True,
            previewError=None,
        )
        return public_discovery_item(item)
    address = item["address"]
    onvif_port = item.get("onvifPort")
    if not onvif_port:
        onvif_port = next(
            (port for port in item.get("openPorts", []) if port in (2020, 80, 443, 8000, 8080, 8899, 10080)),
            None,
        )
    if not onvif_port:
        raise HTTPException(422, "onvif-service-unavailable")
    scheme = "https" if onvif_port == 443 else "http"
    device_url = f"{scheme}://{address}:{onvif_port}/onvif/device_service"
    try:
        client = OnvifClient(device_url, body.username, body.password, timeout=5, allowed_url=safe_onvif_url)
        capabilities = client.capabilities()
    except OnvifError as exc:
        allowed = {
            "onvif-authentication-failed",
            "onvif-timeout",
            "onvif-unreachable",
            "onvif-invalid-xml",
            "onvif-http-error",
        }
        raise HTTPException(422, exc.code if exc.code in allowed else "onvif-probe-failed") from exc

    profiles = []
    stream_sources = []
    for profile in capabilities.get("profiles", [])[:16]:
        sanitized = {
            key: profile.get(key)
            for key in ("token", "name", "codec", "width", "height", "frameRate", "bitrate", "audioCodec")
        }
        try:
            uri = client.stream_uri(profile.get("token", ""))
            parsed = urlparse(uri)
            stream_path = safe_stream_path(uri)
            if parsed.hostname != address or not stream_path:
                raise ValueError("unexpected stream endpoint")
            stream_port = parsed.port or 554
            sanitized["streamPath"] = stream_path
            sanitized["streamPort"] = stream_port
            auth = (
                f"{quote(body.username, safe='')}:{quote(body.password, safe='')}@"
                if body.username else ""
            )
            stream_sources.append(
                (sanitized, f"rtsp://{auth}{address}:{stream_port}{stream_path}")
            )
        except (OnvifError, ValueError):
            sanitized["streamPath"] = None
            sanitized["streamPort"] = None
        profiles.append(sanitized)
    if not stream_sources:
        raise HTTPException(422, "onvif-no-usable-stream-profile")

    stream_sources.sort(
        key=lambda entry: ((entry[0].get("width") or 0) * (entry[0].get("height") or 0), entry[0].get("name") or "")
    )
    preview_error = None
    for _, source_uri in stream_sources:
        try:
            frame = transient_rtsp_preview(source_uri)
            DISCOVERY_PREVIEW_CACHE[(scan_id, device_id)] = (time.time() + 5 * 60, frame)
            break
        except HTTPException as exc:
            preview_error = exc.detail
    else:
        frame = None

    device = capabilities.get("device", {})
    item.update(
        manufacturer=device.get("manufacturer") or item.get("manufacturer") or "Unbekannt",
        model=device.get("model") or item.get("model") or "Unbekannt",
        onvif=True,
        onvifPort=onvif_port,
        rtsp=True,
        profiles=profiles,
        previewAvailable=bool(frame),
        previewVerified=bool(frame),
        previewError=None if frame else (preview_error or "preview-frame-unavailable"),
    )
    return public_discovery_item(item)


@app.post("/api/admin/discovery/scans/{scan_id}/devices/{device_id}/import")
def import_cloud_discovery_device(
    scan_id: str,
    device_id: str,
    body: CloudCameraImport,
    actor: sqlite3.Row = Depends(require_admin_elevated),
):
    _, item = discovery_item(scan_id, device_id)
    if item.get("origin") != "cloud":
        raise HTTPException(422, "cloud-device-required")
    with DB_LOCK, connect() as conn:
        device = conn.execute(
            """SELECT d.*,a.provider FROM cloud_devices d JOIN cloud_accounts a ON a.id=d.account_id
               WHERE d.id=? AND a.enabled=1""",
            (item["cloudDeviceId"],),
        ).fetchone()
        if not device:
            raise HTTPException(404, "cloud-device-not-found")
        if device["stream_support"] != "verified":
            raise HTTPException(409, "cloud-device-frame-proof-required")
        existing = conn.execute("SELECT * FROM cameras WHERE cloud_device_id=?", (device["id"],)).fetchone()
        if existing:
            raise HTTPException(409, "device-already-configured")
        if conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0] >= MAX_CAMERAS:
            raise HTTPException(409, "camera-limit-reached")
        camera_id = f"{device['provider']}-{device['id'].replace('-', '')[:12]}"
        stream_path = f"{camera_id}-low"
        stamp = now_iso()
        capabilities = {
            "device": {
                "manufacturer": device["manufacturer"],
                "model": device["model"],
                "firmwareVersion": None,
                "serialNumber": None,
                "hardwareId": "cloud-adapter",
            },
            "profiles": [
                {
                    "token": "cloud",
                    "name": "Cloud-Livebild",
                    "codec": "h264",
                    "width": None,
                    "height": None,
                    "frameRate": None,
                    "bitrate": None,
                    "audioCodec": None,
                    "streamPath": stream_path,
                }
            ],
            "audio": {"supported": False, "codecs": []},
            "ptz": {
                "supported": False,
                "axes": [],
                "presets": [],
                "absoluteMove": False,
                "relativeMove": False,
                "continuousMove": False,
            },
            "snapshot": {"supported": True},
            "imaging": False,
            "events": False,
            "analytics": False,
            "deviceIo": False,
        }
        position = conn.execute("SELECT COALESCE(MAX(position),-1)+1 FROM cameras").fetchone()[0]
        conn.execute(
            """INSERT INTO cameras(
               id,name,position,enabled,source_label,low_path,high_path,detail_quality,
               managed,address,protocol,port,low_source_path,high_source_path,codec,
               manufacturer,model,on_demand,external_control_url,external_capabilities_json,
               cloud_device_id,created_at,updated_at)
               VALUES(?,?,?,1,?,?,?,?,0,NULL,'external',NULL,NULL,NULL,'h264',?,?,1,NULL,?,?,?,?)""",
            (
                camera_id,
                body.name or device["name"],
                position,
                f"{device['provider'].title()} Cloud · bei Bedarf",
                stream_path,
                stream_path,
                "Frame-geprüfter Cloud-Stream",
                device["manufacturer"],
                device["model"],
                json.dumps(capabilities, separators=(",", ":")),
                device["id"],
                stamp,
                stamp,
            ),
        )
        audit(conn, actor["user_id"], "camera.cloud.imported", "camera", camera_id)
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
    item.update(configuredCameraId=camera_id, configuredName=row["name"])
    return admin_camera(row)


@app.get("/api/admin/discovery/scans/{scan_id}/devices/{device_id}/preview")
def discovery_preview(scan_id: str, device_id: str, _: sqlite3.Row = Depends(require_admin)):
    _, item = discovery_item(scan_id, device_id)
    cached = DISCOVERY_PREVIEW_CACHE.get((scan_id, device_id))
    if cached and cached[0] > time.time():
        return Response(cached[1], media_type="image/jpeg", headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    configured_path = item.get("_configuredPreviewPath")
    if configured_path:
        frame = capture_rtsp_frame(configured_path)
        DISCOVERY_PREVIEW_CACHE[(scan_id, device_id)] = (time.time() + 30, frame)
        return Response(frame, media_type="image/jpeg", headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    uri = item.get("_snapshotUri")
    if not uri or not safe_device_url(uri):
        raise HTTPException(404, "preview-unavailable")
    try:
        request = Request(uri, headers={"User-Agent": "PKWS-Preview/1", "Accept": "image/jpeg,image/*"})
        with NO_REDIRECT_OPENER.open(request, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "")
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024 or not content_type.lower().startswith("image/"):
            raise HTTPException(502, "preview-invalid")
        return Response(data, media_type=content_type.split(";", 1)[0], headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "preview-failed")


@app.delete("/api/admin/discovery/scans/{scan_id}")
def cancel_scan(scan_id: str, _: sqlite3.Row = Depends(require_admin_elevated)):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan-not-found")
    if scan["state"] in {"queued", "running"}:
        scan["state"] = "cancel-requested"
    return {"state": scan["state"]}


def source_uri(row: sqlite3.Row, high: bool = False) -> str:
    with connect() as conn:
        current = active_connection(conn, row["id"])
        if current:
            return source_uri_from_connection(conn, current, high)
    path = row["high_source_path"] if high else row["low_source_path"]
    credentials = None
    if row["credential_id"]:
        with connect() as conn:
            credentials = conn.execute("SELECT * FROM credentials WHERE id=?", (row["credential_id"],)).fetchone()
    auth = ""
    if credentials:
        username, password = decrypt_text(credentials["username_ct"]), decrypt_text(credentials["password_ct"])
        if username:
            auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    scheme = "http" if row["protocol"] in {"hls", "mjpeg", "snapshot"} else "rtsp"
    return f"{scheme}://{auth}{row['address']}:{row['port']}{path}"


def ffprobe_uri(uri: str) -> dict:
    command = ["ffprobe", "-v", "error"]
    if uri.startswith("rtsp://"):
        command += ["-rtsp_transport", "tcp", "-rw_timeout", "12000000"]
    command += ["-read_intervals", "%+5", "-count_packets", "-show_entries", "stream=index,codec_type,codec_name,width,height,avg_frame_rate,has_b_frames,nb_read_packets", "-of", "json", uri]
    try:
        result = subprocess.run(command, capture_output=True, timeout=25, check=False)
        payload = json.loads(result.stdout or b"{}")
        video = next((item for item in payload.get("streams", []) if item.get("codec_type") == "video"), None)
        audio = next((item for item in payload.get("streams", []) if item.get("codec_type") == "audio"), None)
        if not video or int(video.get("nb_read_packets") or 0) < 1:
            return {"ok": False, "error": "no-video-packets"}
        return {
            "ok": True,
            "codec": video.get("codec_name"),
            "width": video.get("width"),
            "height": video.get("height"),
            "frameRate": video.get("avg_frame_rate"),
            "hasBFrames": int(video.get("has_b_frames") or 0),
            "packets": int(video.get("nb_read_packets") or 0),
            "audioAvailable": bool(audio and int(audio.get("nb_read_packets") or 0) > 0),
            "audioCodec": audio.get("codec_name") if audio else None,
            "audioPackets": int(audio.get("nb_read_packets") or 0) if audio else 0,
        }
    except (subprocess.TimeoutExpired, ValueError):
        return {"ok": False, "error": "probe-timeout-or-invalid"}


@app.post("/api/admin/cameras/test-source")
def test_source(body: CameraCreate, _: sqlite3.Row = Depends(require_admin_elevated)):
    auth = f"{quote(body.username, safe='')}:{quote(body.password, safe='')}@" if body.username else ""
    scheme = "http" if body.protocol in {"hls", "mjpeg", "snapshot"} else "rtsp"
    uri = f"{scheme}://{auth}{body.address}:{body.port}{body.lowSourcePath}"
    return ffprobe_uri(uri)


@app.post("/api/admin/cameras")
def add_camera(body: CameraCreate, _: sqlite3.Row = Depends(require_admin_elevated)):
    auth = f"{quote(body.username, safe='')}:{quote(body.password, safe='')}@" if body.username else ""
    scheme = "http" if body.protocol in {"hls", "mjpeg", "snapshot"} else "rtsp"
    proof = ffprobe_uri(f"{scheme}://{auth}{body.address}:{body.port}{body.lowSourcePath}")
    if not proof.get("ok"):
        raise HTTPException(422, "camera-frame-test-required")
    high_source = body.highSourcePath or body.lowSourcePath
    high_proof = proof
    if body.protocol == "rtsp" and high_source != body.lowSourcePath:
        high_proof = ffprobe_uri(f"{scheme}://{auth}{body.address}:{body.port}{high_source}")
    high_webrtc_compatible = int(
        high_source == body.lowSourcePath
        or (bool(high_proof.get("ok")) and not int(high_proof.get("hasBFrames") or 0))
    )
    force_transcode = int(
        int(proof.get("hasBFrames") or 0) > 0
        or int(high_proof.get("hasBFrames") or 0) > 0
    )
    with DB_LOCK, connect() as conn:
        if conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0] >= MAX_CAMERAS:
            raise HTTPException(409, "camera-limit-reached")
        duplicate = conn.execute(
            """SELECT camera_id FROM camera_connections
               WHERE address=? AND stream_port=? AND low_source_path=? AND state IN ('active','draft','last-good')
               LIMIT 1""",
            (body.address, body.port, body.lowSourcePath),
        ).fetchone()
        if duplicate:
            raise HTTPException(409, "camera-connection-already-configured")
        camera_id = re.sub(r"[^a-z0-9]+", "-", body.name.lower()).strip("-")[:30] or "kamera"
        if conn.execute("SELECT 1 FROM cameras WHERE id=?", (camera_id,)).fetchone():
            camera_id = f"{camera_id}-{secrets.token_hex(2)}"
        position = conn.execute("SELECT COALESCE(MAX(position),-1)+1 FROM cameras").fetchone()[0]
        credential_id = None
        if body.username or body.password:
            credential_id = str(uuid.uuid4())
            conn.execute("INSERT INTO credentials VALUES(?,?,?,?)", (credential_id, encrypt_text(body.username), encrypt_text(body.password), now_iso()))
        stamp = now_iso()
        conn.execute(
            """INSERT INTO cameras(id,name,position,enabled,source_label,low_path,high_path,detail_quality,managed,address,protocol,port,
               low_source_path,high_source_path,codec,high_webrtc_compatible,force_transcode,manufacturer,model,credential_id,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (camera_id, body.name, position, 1, "Dynamisch", f"{camera_id}-low", f"{camera_id}-high", "Automatisch erkannt", 1,
             body.address, body.protocol, body.port, body.lowSourcePath, high_source, body.codec, high_webrtc_compatible,
             force_transcode, body.manufacturer, body.model, credential_id, stamp, stamp),
        )
        connection_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO camera_connections(
               id,camera_id,revision,state,address,stream_protocol,stream_port,low_source_path,high_source_path,codec,
               onvif_scheme,onvif_port,onvif_path,credential_mode,shared_credential_id,test_status,created_at,updated_at,activated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                connection_id, camera_id, 1, "active", body.address, body.protocol, body.port, body.lowSourcePath,
                high_source, body.codec, body.onvifScheme, body.onvifPort, body.onvifPath, "shared" if credential_id else "none",
                credential_id, "verified", stamp, stamp, stamp,
            ),
        )
        conn.execute(
            "UPDATE cameras SET active_connection_id=?,last_good_connection_id=? WHERE id=?",
            (connection_id, connection_id, camera_id),
        )
        connection = conn.execute("SELECT * FROM camera_connections WHERE id=?", (connection_id,)).fetchone()
        if connection and body.protocol == "rtsp":
            try:
                client = OnvifClient(
                    f"{body.onvifScheme}://{body.address}:{body.onvifPort}{body.onvifPath}",
                    body.username,
                    body.password,
                    timeout=5,
                    allowed_url=safe_onvif_url,
                )
                capabilities = client.capabilities()
                save_capabilities(conn, camera_id, connection, capabilities)
                device = capabilities.get("device", {})
                conn.execute(
                    """UPDATE cameras SET manufacturer=COALESCE(NULLIF(?,''),manufacturer),
                       model=COALESCE(NULLIF(?,''),model),updated_at=? WHERE id=?""",
                    (device.get("manufacturer", ""), device.get("model", ""), stamp, camera_id),
                )
            except OnvifError:
                pass
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
    return admin_camera(row)


@app.patch("/api/admin/cameras/{camera_id}")
def patch_camera(camera_id: str, body: CameraPatch, _: sqlite3.Row = Depends(require_admin_elevated)):
    changes, values = [], []
    for field, column in (("name", "name"), ("enabled", "enabled"), ("sourceLabel", "source_label")):
        value = getattr(body, field)
        if value is not None:
            changes.append(f"{column}=?")
            values.append(int(value) if isinstance(value, bool) else value)
    if not changes:
        raise HTTPException(400, "no-changes")
    values.extend([now_iso(), camera_id])
    with connect() as conn:
        cursor = conn.execute(f"UPDATE cameras SET {','.join(changes)},updated_at=? WHERE id=?", values)
        if cursor.rowcount == 0:
            raise HTTPException(404, "camera-not-found")
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
    return admin_camera(row)


def connection_test_result(camera_id: str, body: ConnectionInput) -> dict:
    with connect() as conn:
        prior = base_connection(conn, camera_id, body.baseRevision)
        stream_user, stream_password = input_credential_pair(conn, body, prior, "stream")
        onvif_user, onvif_password = input_credential_pair(conn, body, prior, "onvif")
    stream_auth = f"{quote(stream_user, safe='')}:{quote(stream_password, safe='')}@" if stream_user else ""
    scheme = "http" if body.streamProtocol in {"hls", "mjpeg", "snapshot"} else "rtsp"
    low_uri = f"{scheme}://{stream_auth}{body.address}:{body.streamPort}{body.lowSourcePath}"
    high_path = body.highSourcePath or body.lowSourcePath
    high_uri = f"{scheme}://{stream_auth}{body.address}:{body.streamPort}{high_path}"
    low = ffprobe_uri(low_uri)
    high = low if high_path == body.lowSourcePath else ffprobe_uri(high_uri)
    onvif_result: dict = {"ok": False, "error": "onvif-not-tested"}
    capabilities = None
    device_url = f"{body.onvifScheme}://{body.address}:{body.onvifPort}{body.onvifPath}"
    try:
        client = OnvifClient(device_url, onvif_user, onvif_password, timeout=4, allowed_url=safe_onvif_url)
        capabilities = client.capabilities()
        onvif_result = {"ok": True, "device": capabilities["device"], "profileCount": len(capabilities["profiles"])}
    except OnvifError as exc:
        onvif_result = {"ok": False, "error": exc.code}
    return {
        "cameraId": camera_id, "verified": bool(low.get("ok")),
        "stream": {"low": low, "high": high, "authentication": "configured" if stream_user else "none"},
        "onvif": onvif_result, "capabilities": capabilities,
    }


@app.get("/api/admin/cameras/{camera_id}/connection")
def get_camera_connection(camera_id: str, _: sqlite3.Row = Depends(require_admin)):
    with connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera:
            raise HTTPException(404, "camera-not-found")
        active = active_connection(conn, camera_id)
        revisions = conn.execute(
            "SELECT * FROM camera_connections WHERE camera_id=? ORDER BY revision DESC LIMIT 10",
            (camera_id,),
        ).fetchall()
    return {
        "cameraId": camera_id,
        "activeRevision": active["revision"] if active else None,
        "rollout": {
            "relayMode": "dynamic" if camera["managed"] else "static-rollback",
            "liveRelayUsesActiveRevision": bool(camera["managed"]),
        },
        "connection": connection_payload(active) if active else None,
        "revisions": [connection_payload(row) for row in revisions],
    }


@app.post("/api/admin/cameras/{camera_id}/connection/test")
def test_camera_connection(camera_id: str, body: ConnectionInput, _: sqlite3.Row = Depends(require_admin_elevated)):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM cameras WHERE id=?", (camera_id,)).fetchone():
            raise HTTPException(404, "camera-not-found")
    result = connection_test_result(camera_id, body)
    if result["verified"]:
        CONNECTION_TESTS[camera_id] = (
            time.time() + 300,
            connection_input_digest(camera_id, body),
            result,
        )
    return result


@app.put("/api/admin/cameras/{camera_id}/connection")
def save_camera_connection(camera_id: str, body: ConnectionInput, actor: sqlite3.Row = Depends(require_admin_elevated)):
    with DB_LOCK, connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera:
            raise HTTPException(404, "camera-not-found")
        duplicate = conn.execute(
            """SELECT camera_id FROM camera_connections
               WHERE camera_id<>? AND address=? AND stream_port=? AND low_source_path=?
               AND state IN ('active','draft','last-good') LIMIT 1""",
            (camera_id, body.address, body.streamPort, body.lowSourcePath),
        ).fetchone()
        if duplicate:
            raise HTTPException(409, "camera-connection-already-configured")
        prior = base_connection(conn, camera_id, body.baseRevision)
        shared_id, onvif_id, stream_id = resolve_input_credentials(conn, body, prior)
        revision = conn.execute(
            "SELECT COALESCE(MAX(revision),0)+1 FROM camera_connections WHERE camera_id=?",
            (camera_id,),
        ).fetchone()[0]
        connection_id = str(uuid.uuid4())
        stamp = now_iso()
        tested = CONNECTION_TESTS.get(camera_id)
        test_status = "verified" if tested and tested[0] > time.time() and secrets.compare_digest(
            tested[1], connection_input_digest(camera_id, body)
        ) else "untested"
        test_result_json = json.dumps(tested[2]) if test_status == "verified" else None
        conn.execute(
            """INSERT INTO camera_connections(
               id,camera_id,revision,state,address,stream_protocol,stream_port,low_source_path,high_source_path,codec,
               onvif_scheme,onvif_port,onvif_path,credential_mode,shared_credential_id,onvif_credential_id,
               stream_credential_id,test_status,test_result_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                connection_id, camera_id, revision, "draft", body.address, body.streamProtocol, body.streamPort,
                body.lowSourcePath, body.highSourcePath or body.lowSourcePath, body.codec, body.onvifScheme,
                body.onvifPort, body.onvifPath, body.credentialMode, shared_id, onvif_id, stream_id,
                test_status, test_result_json, stamp, stamp,
            ),
        )
        CONNECTION_TESTS.pop(camera_id, None)
        audit(conn, actor["user_id"], "camera.connection.saved", "camera", camera_id)
        row = conn.execute("SELECT * FROM camera_connections WHERE id=?", (connection_id,)).fetchone()
    return connection_payload(row)


def activation_monitor(camera_id: str, connection_id: str, previous_id: str | None) -> None:
    duration = 3 if os.environ.get("ZMODO_TESTING") == "1" else 60
    with connect() as conn:
        camera_row = conn.execute(
            "SELECT low_path,active_connection_id FROM cameras WHERE id=?",
            (camera_id,),
        ).fetchone()
        if not camera_row or camera_row["active_connection_id"] != connection_id:
            return
        low_path = camera_row["low_path"]
    deadline = time.monotonic() + duration + 15
    ready_since: float | None = None
    initial_bytes: int | None = None
    verified = False
    while time.monotonic() < deadline:
        with connect() as conn:
            camera_row = conn.execute(
                "SELECT active_connection_id FROM cameras WHERE id=?",
                (camera_id,),
            ).fetchone()
        if not camera_row or camera_row["active_connection_id"] != connection_id:
            return
        paths, api_ok = media_paths()
        path = paths.get(low_path, {})
        received = int(path.get("bytesReceived") or path.get("inboundBytes") or 0)
        if api_ok and path.get("ready"):
            if ready_since is None:
                ready_since = time.monotonic()
                initial_bytes = received
            if (
                time.monotonic() - ready_since >= max(1, duration - 2)
                and received > int(initial_bytes or 0) + 65536
            ):
                verified = True
                break
        else:
            ready_since = None
            initial_bytes = None
        time.sleep(1)
    with ACTIVATION_LOCK, connect() as conn:
        camera = conn.execute("SELECT active_connection_id FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera or camera["active_connection_id"] != connection_id:
            return
        stamp = now_iso()
        if verified:
            conn.execute(
                "UPDATE camera_connections SET test_status='verified',tested_at=?,updated_at=? WHERE id=?",
                (stamp, stamp, connection_id),
            )
            conn.execute("UPDATE cameras SET last_good_connection_id=? WHERE id=?", (connection_id, camera_id))
        elif previous_id:
            conn.execute("UPDATE camera_connections SET state='rolled-back',test_status='failed',updated_at=? WHERE id=?", (stamp, connection_id))
            conn.execute("UPDATE camera_connections SET state='active',updated_at=? WHERE id=?", (stamp, previous_id))
            previous = conn.execute("SELECT * FROM camera_connections WHERE id=?", (previous_id,)).fetchone()
            conn.execute(
                """UPDATE cameras SET active_connection_id=?,address=?,protocol=?,port=?,low_source_path=?,
                   high_source_path=?,codec=?,high_webrtc_compatible=?,force_transcode=?,credential_id=?,updated_at=? WHERE id=?""",
                (
                    previous_id, previous["address"], previous["stream_protocol"], previous["stream_port"],
                    previous["low_source_path"], previous["high_source_path"], previous["codec"],
                    int(connection_high_webrtc_compatible(previous)),
                    int(connection_requires_transcode(previous)),
                    previous["shared_credential_id"], stamp, camera_id,
                ),
            )


@app.post("/api/admin/cameras/{camera_id}/connection/activate")
def activate_camera_connection(camera_id: str, body: ConnectionActivation, actor: sqlite3.Row = Depends(require_admin_elevated)):
    with ACTIVATION_LOCK, connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        target = conn.execute(
            "SELECT * FROM camera_connections WHERE camera_id=? AND revision=?",
            (camera_id, body.revision),
        ).fetchone()
        if not camera or not target:
            raise HTTPException(404, "connection-not-found")
        previous_id = camera["active_connection_id"]
        stamp = now_iso()
        if previous_id and previous_id != target["id"]:
            previous = conn.execute("SELECT test_status FROM camera_connections WHERE id=?", (previous_id,)).fetchone()
            if previous and previous["test_status"] in {"verified", "legacy-active", "stream-tested"}:
                conn.execute("UPDATE camera_connections SET state='last-good',updated_at=? WHERE id=?", (stamp, previous_id))
                conn.execute("UPDATE cameras SET last_good_connection_id=? WHERE id=?", (previous_id, camera_id))
            else:
                conn.execute("UPDATE camera_connections SET state='rolled-back',updated_at=? WHERE id=?", (stamp, previous_id))
        conn.execute(
            "UPDATE camera_connections SET state='active',activated_at=?,updated_at=? WHERE id=?",
            (stamp, stamp, target["id"]),
        )
        conn.execute("DELETE FROM camera_capabilities WHERE camera_id=?", (camera_id,))
        conn.execute("DELETE FROM camera_profiles WHERE camera_id=?", (camera_id,))
        conn.execute(
            """UPDATE cameras SET active_connection_id=?,address=?,protocol=?,port=?,low_source_path=?,
               high_source_path=?,codec=?,high_webrtc_compatible=?,force_transcode=?,credential_id=?,updated_at=? WHERE id=?""",
            (
                target["id"], target["address"], target["stream_protocol"], target["stream_port"],
                target["low_source_path"], target["high_source_path"], target["codec"],
                int(connection_high_webrtc_compatible(target, bool(camera["high_webrtc_compatible"]))),
                int(connection_requires_transcode(target, bool(camera["force_transcode"]))),
                target["shared_credential_id"], stamp, camera_id,
            ),
        )
        audit(conn, actor["user_id"], "camera.connection.activated", "camera", camera_id)
    threading.Thread(target=activation_monitor, args=(camera_id, target["id"], previous_id), daemon=True).start()
    return {
        "cameraId": camera_id,
        "revision": body.revision,
        "state": "monitoring",
        "rollbackAfterSeconds": 60,
        "relayMode": "dynamic" if camera["managed"] else "static-rollback",
        "liveRelayUsesActiveRevision": bool(camera["managed"]),
    }


@app.post("/api/admin/cameras/{camera_id}/connection/rollback")
def rollback_camera_connection(camera_id: str, actor: sqlite3.Row = Depends(require_admin_elevated)):
    with ACTIVATION_LOCK, connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera:
            raise HTTPException(404, "camera-not-found")
        target = conn.execute(
            """SELECT * FROM camera_connections
               WHERE camera_id=? AND id=? AND id<>? AND test_status IN ('verified','legacy-active','stream-tested')""",
            (camera_id, camera["last_good_connection_id"], camera["active_connection_id"]),
        ).fetchone()
        if not target:
            raise HTTPException(409, "rollback-unavailable")
        current_id = camera["active_connection_id"]
        stamp = now_iso()
        if current_id:
            conn.execute("UPDATE camera_connections SET state='rolled-back',updated_at=? WHERE id=?", (stamp, current_id))
        conn.execute("UPDATE camera_connections SET state='active',updated_at=? WHERE id=?", (stamp, target["id"]))
        conn.execute(
            """UPDATE cameras SET active_connection_id=?,address=?,protocol=?,port=?,low_source_path=?,
               high_source_path=?,codec=?,high_webrtc_compatible=?,force_transcode=?,credential_id=?,updated_at=? WHERE id=?""",
            (
                target["id"], target["address"], target["stream_protocol"], target["stream_port"],
                target["low_source_path"], target["high_source_path"], target["codec"],
                int(connection_high_webrtc_compatible(target)),
                int(connection_requires_transcode(target)),
                target["shared_credential_id"], stamp, camera_id,
            ),
        )
        conn.execute("DELETE FROM camera_capabilities WHERE camera_id=?", (camera_id,))
        conn.execute("DELETE FROM camera_profiles WHERE camera_id=?", (camera_id,))
        audit(conn, actor["user_id"], "camera.connection.rolled-back", "camera", camera_id)
    return {"cameraId": camera_id, "revision": target["revision"], "state": "active"}


def save_capabilities(conn: sqlite3.Connection, camera_id: str, connection: sqlite3.Row, payload: dict) -> None:
    revision = conn.execute(
        "SELECT COALESCE(revision,0)+1 FROM camera_capabilities WHERE camera_id=?",
        (camera_id,),
    ).fetchone()
    next_revision = revision[0] if revision and revision[0] is not None else 1
    stamp = now_iso()
    conn.execute(
        """INSERT INTO camera_capabilities(camera_id,connection_id,revision,payload_json,checked_at)
           VALUES(?,?,?,?,?) ON CONFLICT(camera_id) DO UPDATE SET
           connection_id=excluded.connection_id,revision=excluded.revision,payload_json=excluded.payload_json,checked_at=excluded.checked_at""",
        (camera_id, connection["id"], next_revision, json.dumps(payload), stamp),
    )
    conn.execute("DELETE FROM camera_profiles WHERE camera_id=?", (camera_id,))
    profiles = payload.get("profiles", [])
    for index, profile in enumerate(profiles):
        kind = "main" if index == 0 else ("sub" if index == 1 else "other")
        conn.execute(
            """INSERT INTO camera_profiles(
               id,camera_id,connection_id,token,name,kind,codec,width,height,frame_rate,bitrate,audio_codec,stream_path)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()), camera_id, connection["id"], profile.get("token", ""), profile.get("name", "Profil"),
                kind, profile.get("codec"), profile.get("width"), profile.get("height"), profile.get("frameRate"),
                profile.get("bitrate"), profile.get("audioCodec"), profile.get("streamPath"),
            ),
        )


@app.post("/api/admin/cameras/{camera_id}/capabilities/refresh")
def refresh_capabilities(camera_id: str, actor: sqlite3.Row = Depends(require_admin_elevated)):
    with connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if camera and camera["protocol"] == "external":
            payload = json.loads(camera["external_capabilities_json"] or "{}")
            if not payload:
                raise HTTPException(404, "external-capabilities-unavailable")
            audit(conn, actor["user_id"], "camera.capabilities.refreshed", "camera", camera_id)
            return {
                "cameraId": camera_id,
                "revision": 1,
                "checkedAt": camera["updated_at"],
                **payload,
            }
        connection = active_connection(conn, camera_id)
        if not connection:
            raise HTTPException(404, "connection-not-found")
        client = onvif_client_for(conn, connection)
    try:
        payload = client.capabilities()
    except OnvifError as exc:
        raise HTTPException(502, exc.code)
    with connect() as conn:
        save_capabilities(conn, camera_id, connection, payload)
        device = payload.get("device", {})
        conn.execute(
            "UPDATE cameras SET manufacturer=?,model=?,updated_at=? WHERE id=?",
            (device.get("manufacturer"), device.get("model"), now_iso(), camera_id),
        )
        audit(conn, actor["user_id"], "camera.capabilities.refreshed", "camera", camera_id)
        stored = conn.execute("SELECT * FROM camera_capabilities WHERE camera_id=?", (camera_id,)).fetchone()
    return {"cameraId": camera_id, "revision": stored["revision"], "checkedAt": stored["checked_at"], **payload}


@app.get("/api/admin/cameras/{camera_id}/capabilities")
def get_capabilities(camera_id: str, _: sqlite3.Row = Depends(require_admin)):
    with connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if camera and camera["protocol"] == "external":
            payload = json.loads(camera["external_capabilities_json"] or "{}")
            if not payload:
                return {"cameraId": camera_id, "revision": 0, "checkedAt": None, "available": False}
            return {
                "cameraId": camera_id,
                "revision": 1,
                "checkedAt": camera["updated_at"],
                "available": True,
                **payload,
            }
        row = conn.execute(
            """SELECT cp.* FROM camera_capabilities cp JOIN cameras c ON c.id=cp.camera_id
               WHERE cp.camera_id=? AND cp.connection_id=c.active_connection_id""",
            (camera_id,),
        ).fetchone()
    if not row:
        return {"cameraId": camera_id, "revision": 0, "checkedAt": None, "available": False}
    return {"cameraId": camera_id, "revision": row["revision"], "checkedAt": row["checked_at"], "available": True, **json.loads(row["payload_json"])}


def external_ptz_context(camera_id: str, profile_token: str) -> tuple[sqlite3.Row, dict] | None:
    with connect() as conn:
        camera = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
    if not camera or camera["protocol"] != "external":
        return None
    payload = json.loads(camera["external_capabilities_json"] or "{}")
    if (
        profile_token != "external"
        or not camera["external_control_url"]
        or not payload.get("ptz", {}).get("supported")
    ):
        raise HTTPException(409, "ptz-not-supported")
    return camera, payload


def external_control_request(camera: sqlite3.Row, action: str, direction: str | None = None) -> None:
    parsed = urlparse(camera["external_control_url"])
    if parsed.hostname is None or parsed.hostname.lower() not in EXTERNAL_CONTROL_HOSTS:
        raise HTTPException(502, "external-control-endpoint-invalid")
    body = {"direction": direction} if direction else {}
    request = Request(
        f"{camera['external_control_url']}/v1/cameras/{quote(camera['id'], safe='')}/ptz/{action}",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {INTERNAL_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=8) as response:
            result = json.load(response)
    except HTTPError as exc:
        if exc.code in {400, 404, 409, 422}:
            raise HTTPException(409, "external-ptz-rejected") from exc
        raise HTTPException(502, "external-ptz-failed") from exc
    except (OSError, ValueError, URLError) as exc:
        raise HTTPException(502, "external-ptz-unavailable") from exc
    if not result.get("ok"):
        raise HTTPException(502, "external-ptz-failed")


def ptz_context(camera_id: str, profile_token: str) -> tuple[OnvifClient, dict]:
    with connect() as conn:
        connection = active_connection(conn, camera_id)
        capabilities = conn.execute(
            "SELECT payload_json FROM camera_capabilities WHERE camera_id=? AND connection_id=?",
            (camera_id, connection["id"] if connection else ""),
        ).fetchone()
        profile = conn.execute(
            "SELECT 1 FROM camera_profiles WHERE camera_id=? AND connection_id=? AND token=?",
            (camera_id, connection["id"] if connection else "", profile_token),
        ).fetchone()
        if not connection or not capabilities or not profile:
            raise HTTPException(409, "ptz-capabilities-required")
        payload = json.loads(capabilities["payload_json"])
        if not payload.get("ptz", {}).get("supported"):
            raise HTTPException(409, "ptz-not-supported")
        client = onvif_client_for(conn, connection)
    try:
        client.discover_services()
    except OnvifError:
        pass
    return client, payload


def enforce_ptz_rate(camera_id: str) -> None:
    cutoff = time.time() - 1
    PTZ_ATTEMPTS[camera_id] = [stamp for stamp in PTZ_ATTEMPTS.get(camera_id, []) if stamp > cutoff]
    if len(PTZ_ATTEMPTS[camera_id]) >= 8:
        raise HTTPException(429, "ptz-rate-limited")
    PTZ_ATTEMPTS[camera_id].append(time.time())


@app.post("/api/admin/cameras/{camera_id}/ptz/move")
def ptz_move(camera_id: str, body: PTZMove, _: sqlite3.Row = Depends(require_admin_elevated)):
    enforce_ptz_rate(camera_id)
    external = external_ptz_context(camera_id, body.profileToken)
    if external:
        camera, payload = external
        components = {"x": body.x, "y": body.y, "zoom": body.zoom}
        active = [(axis, value) for axis, value in components.items() if abs(value) > 0.01]
        axes = set(payload.get("ptz", {}).get("axes", []))
        if len(active) != 1 or active[0][0] not in axes:
            raise HTTPException(409, "ptz-axis-not-supported")
        axis, value = active[0]
        direction = {
            ("x", -1): "left",
            ("x", 1): "right",
            ("y", -1): "down",
            ("y", 1): "up",
            ("zoom", -1): "out",
            ("zoom", 1): "in",
        }[(axis, -1 if value < 0 else 1)]
        external_control_request(camera, "start", direction)
        return {"ok": True}
    client, _ = ptz_context(camera_id, body.profileToken)
    try:
        client.ptz_move(body.profileToken, body.x, body.y, body.zoom)
    except OnvifError as exc:
        raise HTTPException(502, exc.code)
    return {"ok": True}


@app.post("/api/admin/cameras/{camera_id}/ptz/stop")
def ptz_stop(camera_id: str, body: PTZStop, _: sqlite3.Row = Depends(require_admin_csrf)):
    external = external_ptz_context(camera_id, body.profileToken)
    if external:
        external_control_request(external[0], "stop")
        return {"ok": True}
    client, _ = ptz_context(camera_id, body.profileToken)
    try:
        client.ptz_stop(body.profileToken)
    except OnvifError as exc:
        raise HTTPException(502, exc.code)
    return {"ok": True}


@app.post("/api/admin/cameras/{camera_id}/ptz/presets/{preset_token}/goto")
def ptz_goto_preset(camera_id: str, preset_token: str, body: PTZStop, _: sqlite3.Row = Depends(require_admin_elevated)):
    client, payload = ptz_context(camera_id, body.profileToken)
    if preset_token not in {item.get("token") for item in payload.get("ptz", {}).get("presets", [])}:
        raise HTTPException(404, "ptz-preset-not-found")
    try:
        client.goto_preset(body.profileToken, preset_token)
    except OnvifError as exc:
        raise HTTPException(502, exc.code)
    return {"ok": True}


@app.delete("/api/admin/cameras/{camera_id}")
def delete_camera(camera_id: str, _: sqlite3.Row = Depends(require_admin_elevated)):
    with DB_LOCK, connect() as conn:
        row = conn.execute("SELECT managed,credential_id FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not row:
            raise HTTPException(404, "camera-not-found")
        if not row["managed"]:
            raise HTTPException(409, "seed-camera-cannot-be-removed")
        credential_ids = {
            value
            for connection in conn.execute(
                "SELECT shared_credential_id,onvif_credential_id,stream_credential_id FROM camera_connections WHERE camera_id=?",
                (camera_id,),
            )
            for value in connection
            if value
        }
        if row["credential_id"]:
            credential_ids.add(row["credential_id"])
        conn.execute("DELETE FROM cameras WHERE id=?", (camera_id,))
        for credential_id in credential_ids:
            still_used = conn.execute(
                """SELECT 1 FROM camera_connections WHERE shared_credential_id=? OR onvif_credential_id=? OR stream_credential_id=? LIMIT 1""",
                (credential_id, credential_id, credential_id),
            ).fetchone()
            if not still_used:
                conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        remaining = conn.execute("SELECT id FROM cameras ORDER BY position").fetchall()
        for position, item in enumerate(remaining):
            conn.execute("UPDATE cameras SET position=? WHERE id=?", (position, item["id"]))
    return Response(status_code=204)


@app.put("/api/admin/cameras/order")
def update_order(body: OrderUpdate, _: sqlite3.Row = Depends(require_admin_elevated)):
    if len(set(body.cameraIds)) != len(body.cameraIds):
        raise HTTPException(400, "duplicate-camera-id")
    with DB_LOCK, connect() as conn:
        existing = [row[0] for row in conn.execute("SELECT id FROM cameras ORDER BY position")]
        if set(existing) != set(body.cameraIds):
            raise HTTPException(409, "order-set-mismatch")
        conn.execute("UPDATE cameras SET position=position+1000")
        for position, camera_id in enumerate(body.cameraIds):
            conn.execute("UPDATE cameras SET position=?,updated_at=? WHERE id=?", (position, now_iso(), camera_id))
    return {"cameraIds": body.cameraIds}


@app.get("/api/admin/cameras/{camera_id}/zones")
def get_zones(camera_id: str, _: sqlite3.Row = Depends(require_admin)):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM cameras WHERE id=?", (camera_id,)).fetchone():
            raise HTTPException(404, "camera-not-found")
        rows = conn.execute("SELECT * FROM zones WHERE camera_id=? ORDER BY updated_at,id", (camera_id,)).fetchall()
    revision = max((row["revision"] for row in rows), default=0)
    return {"cameraId": camera_id, "revision": revision, "zones": [{"id": row["id"], "name": row["name"], "kind": row["kind"], "points": json.loads(row["points_json"]), "enabled": bool(row["enabled"])} for row in rows]}


@app.put("/api/admin/cameras/{camera_id}/zones")
def put_zones(camera_id: str, body: ZonesUpdate, _: sqlite3.Row = Depends(require_admin_elevated)):
    with DB_LOCK, connect() as conn:
        current = conn.execute("SELECT COALESCE(MAX(revision),0) FROM zones WHERE camera_id=?", (camera_id,)).fetchone()[0]
        if current != body.revision:
            raise HTTPException(409, "zone-revision-conflict")
        revision = current + 1
        conn.execute("DELETE FROM zones WHERE camera_id=?", (camera_id,))
        for zone in body.zones:
            conn.execute("INSERT INTO zones VALUES(?,?,?,?,?,?,?,?)", (zone.id or str(uuid.uuid4()), camera_id, zone.name, zone.kind, json.dumps([point.model_dump() for point in zone.points]), int(zone.enabled), revision, now_iso()))
    return {"cameraId": camera_id, "revision": revision}


@app.get("/api/cameras/{camera_id}/snapshot")
@app.get("/api/admin/cameras/{camera_id}/preview")
def preview(camera_id: str, _: sqlite3.Row = Depends(require_session)):
    cached = PREVIEW_CACHE.get(camera_id)
    if cached and cached[0] > time.time():
        return Response(cached[1], media_type="image/jpeg", headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    with connect() as conn:
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        connection = active_connection(conn, camera_id) if row else None
        snapshot_credentials = connection_credentials(conn, connection, "stream") if connection and row["protocol"] == "snapshot" else ("", "")
    if not row:
        raise HTTPException(404, "preview-unavailable")
    if row["protocol"] == "snapshot":
        if not row["address"] or not connection:
            raise HTTPException(404, "preview-unavailable")
        username, password = snapshot_credentials
        uri = (
            f"http://{connection['address']}:{connection['stream_port']}"
            f"{connection['low_source_path']}"
        )
        if not safe_device_url(uri):
            raise HTTPException(400, "preview-endpoint-outside-network")
        headers = {"User-Agent": "PKWS-Preview/1", "Accept": "image/jpeg,image/*"}
        if username:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        if not PREVIEW_SEMAPHORE.acquire(blocking=False):
            raise HTTPException(429, "preview-busy")
        try:
            try:
                with NO_REDIRECT_OPENER.open(Request(uri, headers=headers), timeout=8) as response:
                    content_type = response.headers.get("Content-Type", "")
                    data = response.read(4 * 1024 * 1024 + 1)
            except HTTPError as exc:
                raise HTTPException(502, "preview-http-error") from exc
            except OSError as exc:
                raise HTTPException(502, "preview-failed") from exc
        finally:
            PREVIEW_SEMAPHORE.release()
        if len(data) > 4 * 1024 * 1024 or not content_type.lower().startswith("image/"):
            raise HTTPException(502, "preview-invalid")
        PREVIEW_CACHE[camera_id] = (time.time() + 2, data)
        return Response(data, media_type=content_type.split(";", 1)[0], headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    transient_lease_id = None
    try:
        if row["on_demand"]:
            transient_lease_id = f"preview-{secrets.token_urlsafe(12)}"
            LEASES.setdefault(camera_id, {})[transient_lease_id] = time.time() + 90
            deadline = time.monotonic() + 45
            while True:
                paths, api_ok = media_paths()
                if api_ok and paths.get(row["low_path"], {}).get("ready"):
                    break
                if time.monotonic() >= deadline:
                    raise HTTPException(504, "preview-source-timeout")
                time.sleep(0.5)
        uri = f"rtsp://mediamtx:8554/{quote(row['low_path'], safe='')}"
        command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-rtsp_transport", "tcp"]
        command += ["-i", uri, "-frames:v", "1", "-an", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"]
        if not PREVIEW_SEMAPHORE.acquire(blocking=False):
            raise HTTPException(429, "preview-busy")
        try:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=30 if row["on_demand"] else 12,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise HTTPException(504, "preview-timeout")
        finally:
            PREVIEW_SEMAPHORE.release()
        if result.returncode != 0 or not result.stdout.startswith(b"\xff\xd8"):
            raise HTTPException(502, "preview-failed")
        PREVIEW_CACHE[camera_id] = (time.time() + 2, result.stdout)
        return Response(result.stdout, media_type="image/jpeg", headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    finally:
        if transient_lease_id:
            leases = LEASES.get(camera_id)
            if leases:
                leases.pop(transient_lease_id, None)
                if not leases:
                    LEASES.pop(camera_id, None)


def active_camera_leases(camera_id: str) -> dict[str, float]:
    leases = LEASES.get(camera_id, {})
    now = time.time()
    for key, expiry in list(leases.items()):
        if expiry <= now:
            leases.pop(key, None)
    if not leases:
        LEASES.pop(camera_id, None)
    return leases


@app.post("/api/cameras/{camera_id}/lease")
def acquire_lease(camera_id: str, _: sqlite3.Row = Depends(require_csrf)):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM cameras WHERE id=? AND enabled=1", (camera_id,)).fetchone():
            raise HTTPException(404, "camera-not-found")
    lease_id = secrets.token_urlsafe(18)
    active_camera_leases(camera_id)
    leases = LEASES.setdefault(camera_id, {})
    leases[lease_id] = time.time() + 90
    return {"cameraId": camera_id, "leaseId": lease_id, "expiresIn": 90}


@app.put("/api/cameras/{camera_id}/lease")
def renew_lease(camera_id: str, leaseId: str | None = None, _: sqlite3.Row = Depends(require_csrf)):
    if not leaseId:
        raise HTTPException(400, "lease-id-required")
    leases = active_camera_leases(camera_id)
    if leaseId not in leases:
        raise HTTPException(404, "lease-not-found")
    leases[leaseId] = time.time() + 90
    return {"cameraId": camera_id, "leaseId": leaseId, "expiresIn": 90}


@app.delete("/api/cameras/{camera_id}/lease")
def release_lease(camera_id: str, leaseId: str | None = None, _: sqlite3.Row = Depends(require_csrf)):
    if not leaseId:
        raise HTTPException(400, "lease-id-required")
    leases = LEASES.get(camera_id)
    if leases:
        leases.pop(leaseId, None)
        if not leases:
            LEASES.pop(camera_id, None)
    return Response(status_code=204)


def require_internal(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {INTERNAL_TOKEN}"
    if not secrets.compare_digest(authorization, expected):
        raise HTTPException(401, "internal-auth-required")


def require_czeview_adapter(authorization: str = Header(default="")) -> None:
    if not CZEVIEW_ADAPTER_TOKEN or not secrets.compare_digest(
        authorization, f"Bearer {CZEVIEW_ADAPTER_TOKEN}"
    ):
        raise HTTPException(401, "czeview-adapter-auth-required")


def require_netatmo_adapter(authorization: str = Header(default="")) -> None:
    if not NETATMO_ADAPTER_TOKEN or not secrets.compare_digest(
        authorization, f"Bearer {NETATMO_ADAPTER_TOKEN}"
    ):
        raise HTTPException(401, "netatmo-adapter-auth-required")


@app.post("/internal/v1/providers/czeview/legacy-account")
def import_legacy_czeview_account(
    body: CzeviewAccountCreate,
    _: None = Depends(require_czeview_adapter),
):
    with DB_LOCK, connect() as conn:
        existing = conn.execute(
            "SELECT * FROM cloud_accounts WHERE provider='czeview' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if existing:
            return cloud_account_payload(existing)
        account_id, stamp = str(uuid.uuid4()), now_iso()
        auth = {
            "username": body.username,
            "email": body.email,
            "login": body.email or body.username,
            "password": body.password,
            "countryCode": body.countryCode,
            "phoneCode": body.phoneCode,
            "sourceApp": body.sourceApp,
            "deviceSerial": body.deviceSerial,
            "cameraName": body.cameraName,
        }
        conn.execute(
            """INSERT INTO cloud_accounts(
               id,provider,label,enabled,auth_payload_ct,scopes_json,status,legacy_source,created_at,updated_at)
               VALUES(?,'czeview',?,1,?,'[]','pending','poc.env',?,?)""",
            (account_id, body.label, encrypt_json(auth), stamp, stamp),
        )
        audit(conn, None, "cloud.account.legacy-imported", "cloud-account", account_id)
        row = conn.execute("SELECT * FROM cloud_accounts WHERE id=?", (account_id,)).fetchone()
    return cloud_account_payload(row)


@app.get("/internal/v1/providers/czeview/accounts")
def czeview_adapter_accounts(_: None = Depends(require_czeview_adapter)):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM cloud_accounts WHERE provider='czeview' AND enabled=1 ORDER BY created_at"
        ).fetchall()
    return {
        "accounts": [
            {
                "id": row["id"],
                "label": row["label"],
                "authRevision": row["auth_revision"],
                "credentials": decrypt_json(row["auth_payload_ct"]),
            }
            for row in rows
        ]
    }


@app.post("/internal/v1/providers/czeview/inventory")
def update_czeview_inventory(
    body: CloudInventoryUpdate,
    _: None = Depends(require_czeview_adapter),
):
    stamp = now_iso()
    result = []
    with DB_LOCK, connect() as conn:
        account = conn.execute(
            "SELECT * FROM cloud_accounts WHERE id=? AND provider='czeview'",
            (body.accountId,),
        ).fetchone()
        if not account:
            raise HTTPException(404, "cloud-account-not-found")
        conn.execute(
            """UPDATE cloud_accounts SET status=?,last_error_code=?,last_verified_at=?,
               updated_at=? WHERE id=?""",
            (
                body.status,
                body.errorCode,
                stamp if body.status == "active" else account["last_verified_at"],
                stamp,
                body.accountId,
            ),
        )
        for device in body.devices:
            external_hash = hashlib.blake2b(
                f"czeview:{body.accountId}:{device.externalId}".encode(),
                key=AES_KEY,
                digest_size=32,
            ).hexdigest()
            existing = conn.execute(
                "SELECT id,stream_support FROM cloud_devices WHERE account_id=? AND external_id_hash=?",
                (body.accountId, external_hash),
            ).fetchone()
            device_id = existing["id"] if existing else str(uuid.uuid4())
            stream_support = (
                "verified"
                if existing and existing["stream_support"] == "verified"
                else "unsupported"
                if device.streamSupport == "unsupported"
                else "candidate"
            )
            conn.execute(
                """INSERT INTO cloud_devices(
                   id,account_id,external_id_hash,external_id_ct,home_id_ct,name,model,manufacturer,
                   capabilities_json,stream_support,last_error_code,last_seen_at,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(account_id,external_id_hash) DO UPDATE SET
                   external_id_ct=excluded.external_id_ct,home_id_ct=excluded.home_id_ct,
                   name=excluded.name,model=excluded.model,manufacturer=excluded.manufacturer,
                   capabilities_json=excluded.capabilities_json,stream_support=excluded.stream_support,
                   last_error_code=excluded.last_error_code,last_seen_at=excluded.last_seen_at,
                   updated_at=excluded.updated_at""",
                (
                    device_id,
                    body.accountId,
                    external_hash,
                    encrypt_text(device.externalId),
                    encrypt_text(device.homeId) if device.homeId else None,
                    device.name,
                    device.model,
                    device.manufacturer,
                    json.dumps(device.capabilities, separators=(",", ":")),
                    stream_support,
                    device.errorCode,
                    stamp,
                    stamp,
                    stamp,
                ),
            )
            result.append({"externalId": device.externalId, "deviceId": device_id})
        if account["legacy_source"] and result:
            auth = decrypt_json(account["auth_payload_ct"])
            preferred = str(auth.get("deviceSerial") or "")
            selected = next(
                (item for item in result if preferred and item["externalId"] == preferred),
                result[0] if len(result) == 1 else None,
            )
            if selected:
                conn.execute(
                    """UPDATE cameras SET cloud_device_id=?,updated_at=?
                       WHERE id='czeview' AND protocol='external' AND cloud_device_id IS NULL""",
                    (selected["deviceId"], stamp),
                )
    return {"accountId": body.accountId, "devices": result}


@app.get("/internal/v1/providers/czeview/leases")
def czeview_adapter_leases(_: None = Depends(require_czeview_adapter)):
    with connect() as conn:
        rows = conn.execute(
            """SELECT c.id AS camera_id,c.low_path,c.enabled,d.id AS device_id,d.external_id_ct,
               d.account_id FROM cameras c JOIN cloud_devices d ON d.id=c.cloud_device_id
               JOIN cloud_accounts a ON a.id=d.account_id
               WHERE a.provider='czeview' AND a.enabled=1"""
        ).fetchall()
    cameras = [
            {
                "cameraId": row["camera_id"],
                "path": row["low_path"],
                "deviceId": row["device_id"],
                "externalId": decrypt_text(row["external_id_ct"]),
                "accountId": row["account_id"],
                "active": bool(row["enabled"] and active_camera_leases(row["camera_id"])),
            }
            for row in rows
    ]
    now = time.time()
    for device_id, probe in list(CLOUD_PROBE_LEASES.items()):
        if probe["expiresAt"] <= now:
            CLOUD_PROBE_LEASES.pop(device_id, None)
            continue
        if probe["provider"] == "czeview":
            cameras.append(probe["lease"].copy())
    return {"cameras": cameras}


@app.get("/internal/v1/providers/netatmo/streams")
def netatmo_adapter_streams(_: None = Depends(require_netatmo_adapter)):
    with connect() as conn:
        rows = conn.execute(
            """SELECT c.id AS camera_id,c.low_path,c.enabled,d.id AS device_id,d.account_id
               FROM cameras c JOIN cloud_devices d ON d.id=c.cloud_device_id
               JOIN cloud_accounts a ON a.id=d.account_id
               WHERE a.provider='netatmo' AND a.enabled=1"""
        ).fetchall()
    streams = []
    for row in rows:
        active = bool(row["enabled"] and active_camera_leases(row["camera_id"]))
        streams.append(
            {
                "cameraId": row["camera_id"],
                "path": row["low_path"],
                "deviceId": row["device_id"],
                "accountId": row["account_id"],
                "active": active,
                "streamCandidates": netatmo_stream_candidates(row["device_id"]) if active else [],
            }
        )
    now = time.time()
    for device_id, probe in list(CLOUD_PROBE_LEASES.items()):
        if probe["expiresAt"] <= now:
            CLOUD_PROBE_LEASES.pop(device_id, None)
            continue
        if probe["provider"] == "netatmo":
            lease = probe["lease"].copy()
            lease["streamCandidates"] = netatmo_stream_candidates(device_id)
            streams.append(lease)
    return {"cameras": streams}


@app.put("/internal/v1/external-cameras/{camera_id}")
def ensure_external_camera(
    camera_id: str,
    body: ExternalCameraInput,
    _: None = Depends(require_internal),
):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", camera_id):
        raise HTTPException(422, "invalid-camera-id")
    stamp = now_iso()
    axes = list(dict.fromkeys(body.ptzAxes))
    capabilities = {
        "device": {
            "manufacturer": body.manufacturer,
            "model": body.model,
            "firmwareVersion": None,
            "serialNumber": None,
            "hardwareId": "external-adapter",
        },
        "profiles": [{
            "token": "external",
            "name": "CZEview P2P",
            "codec": body.codec,
            "width": body.width,
            "height": body.height,
            "frameRate": None,
            "bitrate": None,
            "audioCodec": None,
            "streamPath": body.path,
        }],
        "audio": {"supported": False, "codecs": []},
        "ptz": {
            "supported": bool(body.controlUrl and axes),
            "axes": axes,
            "presets": [],
            "absoluteMove": False,
            "relativeMove": False,
            "continuousMove": bool(body.controlUrl and axes),
        },
        "snapshot": {"supported": True},
        "imaging": False,
        "events": False,
        "analytics": False,
        "deviceIo": False,
    }
    capabilities_json = json.dumps(capabilities, separators=(",", ":"))
    with DB_LOCK, connect() as conn:
        row = conn.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if row and row["protocol"] != "external":
            raise HTTPException(409, "camera-id-in-use")
        if row:
            conn.execute(
                """UPDATE cameras SET source_label=?,low_path=?,high_path=?,detail_quality=?,
                   protocol='external',codec=?,manufacturer=?,model=?,on_demand=1,
                   external_control_url=?,external_capabilities_json=?,updated_at=?
                   WHERE id=?""",
                (
                    body.sourceLabel, body.path, body.path, body.detailQuality,
                    body.codec, body.manufacturer, body.model, body.controlUrl,
                    capabilities_json, stamp, camera_id,
                ),
            )
        else:
            position = conn.execute("SELECT COALESCE(MAX(position),-1)+1 FROM cameras").fetchone()[0]
            try:
                conn.execute(
                    """INSERT INTO cameras(
                       id,name,position,enabled,source_label,low_path,high_path,detail_quality,
                       managed,address,protocol,port,low_source_path,high_source_path,codec,
                       manufacturer,model,on_demand,external_control_url,
                       external_capabilities_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        camera_id, body.name, position, 1, body.sourceLabel, body.path, body.path,
                        body.detailQuality, 0, None, "external", None, None, None, body.codec,
                        body.manufacturer, body.model, 1, body.controlUrl,
                        capabilities_json, stamp, stamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(409, "camera-path-in-use") from exc
    return {
        "cameraId": camera_id,
        "path": body.path,
        "registered": True,
        "ptz": capabilities["ptz"]["supported"],
        "active": bool(active_camera_leases(camera_id)),
    }


@app.get("/internal/v1/external-cameras/{camera_id}/lease")
def external_camera_lease(camera_id: str, _: None = Depends(require_internal)):
    with connect() as conn:
        row = conn.execute(
            "SELECT enabled,on_demand FROM cameras WHERE id=? AND protocol='external'",
            (camera_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "external-camera-not-found")
    leases = active_camera_leases(camera_id)
    now = time.time()
    return {
        "cameraId": camera_id,
        "enabled": bool(row["enabled"]),
        "active": bool(row["enabled"] and leases),
        "leaseCount": len(leases),
        "expiresIn": max(0, int(max(leases.values()) - now)) if leases else 0,
    }


@app.get("/internal/v1/relay-config")
def relay_config(_: None = Depends(require_internal)):
    now = time.time()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM cameras WHERE enabled=1 AND managed=1 AND protocol!='snapshot' ORDER BY position").fetchall()
    items = []
    for row in rows:
        with connect() as conn:
            connection = active_connection(conn, row["id"])
            capability_row = conn.execute(
                "SELECT payload_json FROM camera_capabilities WHERE camera_id=? AND connection_id=?",
                (row["id"], connection["id"] if connection else ""),
            ).fetchone()
        if not connection:
            continue
        capability_payload = json.loads(capability_row["payload_json"]) if capability_row else {}
        audio = bool(capability_payload.get("audio", {}).get("supported"))
        camera_leases = active_camera_leases(row["id"])
        active = row["codec"] == "h264" or bool(camera_leases)
        items.append({"id": f"{row['id']}-low", "cameraId": row["id"], "connectionId": connection["id"], "connectionRevision": connection["revision"], "path": row["low_path"], "sourceUri": source_uri(row), "codec": row["codec"], "audio": audio, "transcode": bool(row["force_transcode"]), "active": active})
        if row["high_path"] != row["low_path"] and row["high_source_path"] != row["low_source_path"]:
            items.append({"id": f"{row['id']}-high", "cameraId": row["id"], "connectionId": connection["id"], "connectionRevision": connection["revision"], "path": row["high_path"], "sourceUri": source_uri(row, high=True), "codec": row["codec"], "audio": audio, "transcode": bool(row["force_transcode"]), "active": active})
    return {"revision": int(now), "cameras": items}


@app.get("/internal/v1/detection/cameras")
def detection_config(_: None = Depends(require_internal)):
    with connect() as conn:
        cameras = conn.execute("SELECT id,name,low_path FROM cameras WHERE enabled=1 AND protocol!='snapshot' ORDER BY position").fetchall()
        zones = conn.execute("SELECT * FROM zones ORDER BY camera_id,id").fetchall()
    by_camera: dict[str, list] = {}
    for zone in zones:
        by_camera.setdefault(zone["camera_id"], []).append({"id": zone["id"], "name": zone["name"], "kind": zone["kind"], "points": json.loads(zone["points_json"]), "enabled": bool(zone["enabled"]), "revision": zone["revision"]})
    return {"enabled": False, "cameras": [{"id": row["id"], "name": row["name"], "streamPath": row["low_path"], "zones": by_camera.get(row["id"], [])} for row in cameras]}


@app.post("/internal/v1/events")
def detection_events(_: None = Depends(require_internal)):
    raise HTTPException(503, "detection-adapter-disabled")


class ProtectedStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        content_type = response.headers.get("content-type", "")
        response.headers["Cache-Control"] = "no-cache" if content_type.startswith("text/html") or not path or path.endswith((".html", ".js", ".css", ".webmanifest")) else "public, max-age=86400"
        return response


app.mount("/", ProtectedStaticFiles(directory=WEB_ROOT, html=True), name="web")
