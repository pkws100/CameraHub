from __future__ import annotations

import base64
import http.cookiejar
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import parse_qs, unquote, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TEMP = tempfile.mkdtemp(prefix="pkws-test-")
SEED_PATH = os.path.join(TEMP, "cameras.json")
with open(SEED_PATH, "w", encoding="utf-8") as seed_file:
    json.dump({
        "cameras": [
            {
                "id": camera_id,
                "name": name,
                "lowPath": f"{camera_id}-low",
                "highPath": f"{camera_id}-low",
                "source": "Direkt",
                "address": f"192.168.50.{address_suffix}",
                "protocol": "rtsp",
                "port": 8554,
                "lowSourcePath": "/stream/sub",
                "highSourcePath": "/stream/main",
                "codec": "h264",
            }
            for camera_id, name, address_suffix in (
                ("garten", "Garten", 8),
                ("eingang", "Eingang", 9),
                ("serverraum", "Serverraum", 11),
                ("rueckseite", "Rückseite", 12),
                ("einfahrt", "Einfahrt", 13),
                ("garage", "Garage", 14),
            )
        ]
    }, seed_file)
os.environ.update({
    "ZMODO_TESTING": "1",
    "DATABASE_PATH": os.path.join(TEMP, "test.db"),
    "CAMERA_CONFIG": SEED_PATH,
    "WEB_ROOT": "/app",
    "MEDIAMTX_API": "http://127.0.0.1:9",
    "DISCOVERY_NETWORK": "192.168.50.0/24",
    "HTTP_DIAGNOSTIC_ONLY": "1",
    "ALLOW_INSECURE_LOOPBACK_MANAGEMENT": "1",
})

import uvicorn
import app as camera_app

# Prove the additive 1.3.2/1.3.3 -> 1.5 schema path before the main API test.
legacy_db = os.path.join(TEMP, "legacy-1.3.3.db")
with sqlite3.connect(legacy_db) as legacy:
    legacy.executescript(
        """
        CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO schema_migrations(version,applied_at) VALUES(8,'2026-01-01T00:00:00Z');
        CREATE TABLE display_profile_cameras(
          profile_id TEXT NOT NULL,
          camera_id TEXT NOT NULL,
          position INTEGER NOT NULL,
          PRIMARY KEY(profile_id,camera_id)
        );
        """
    )
main_db_path = camera_app.DB_PATH
camera_app.DB_PATH = camera_app.Path(legacy_db)
camera_app.initialize_database()
with camera_app.connect() as migrated:
    assert "stream_mode" in {
        row["name"] for row in migrated.execute("PRAGMA table_info(display_profile_cameras)")
    }
    assert migrated.execute(
        "SELECT 1 FROM schema_migrations WHERE version=10"
    ).fetchone()
camera_app.DB_PATH = main_db_path


PORT = 18090
server = uvicorn.Server(uvicorn.Config(camera_app.app, host="127.0.0.1", port=PORT, log_level="error", proxy_headers=False))
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
deadline = time.time() + 10
while not server.started and time.time() < deadline:
    time.sleep(0.05)

jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
base = f"http://127.0.0.1:{PORT}"


def request(path: str, method: str = "GET", body=None, csrf: str | None = None, expected: int = 200, opener=None):
    headers = {"Host": "127.0.0.1"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with (opener or client).open(req, timeout=10) as response:
            assert response.status == expected, (response.status, expected)
            return json.load(response) if response.length != 0 else None
    except urllib.error.HTTPError as error:
        assert error.code == expected, (error.code, expected, error.read())
        return json.load(error)


try:
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version=7"
        ).fetchone()
    state = request("/api/auth/state")
    assert state == {"setupRequired": True, "authenticated": False}
    assert request("/api/auth/setup", "POST", {"username": "owner", "password": "short7"}, expected=422)["detail"]
    password = "Test-42!"
    session = request("/api/auth/setup", "POST", {"username": "owner", "password": password})
    csrf = session["csrfToken"]
    assert session["user"]["role"] == "owner" and session["permissions"]["manageUsers"] is True
    assert request("/api/auth/setup", "POST", {"username": "other", "password": password}, expected=409)["detail"] == "setup-complete"

    viewer_password = "Viewer-Test-Password-42!"
    admin_password = "Admin-Test-Password-42!"
    viewer = request("/api/admin/users", "POST", {"username": "viewer1", "displayName": "Viewer One", "role": "viewer", "password": viewer_password}, csrf)
    admin = request("/api/admin/users", "POST", {"username": "admin1", "displayName": "Admin One", "role": "admin", "password": admin_password}, csrf)
    assert "password" not in viewer and "password" not in admin
    assert {item["role"] for item in request("/api/admin/users")["users"]} == {"owner", "admin", "viewer"}

    viewer_client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    viewer_session = request("/api/auth/login", "POST", {"username": "viewer1", "password": viewer_password}, opener=viewer_client)
    assert viewer_session["permissions"]["view"] and not viewer_session["permissions"]["manageCameras"]
    assert request("/api/cameras", opener=viewer_client)["cameras"]
    assert request("/api/admin/cameras", expected=403, opener=viewer_client)["detail"] == "insufficient-role"
    assert request("/api/admin/users", expected=403, opener=viewer_client)["detail"] == "insufficient-role"
    denied_viewer_write = request("/api/admin/cameras/order", "PUT", {"cameraIds": ["garten"]}, viewer_session["csrfToken"], 403, viewer_client)
    assert denied_viewer_write["detail"] == "insufficient-role"

    admin_client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    admin_session = request("/api/auth/login", "POST", {"username": "admin1", "password": admin_password}, opener=admin_client)
    assert admin_session["permissions"]["manageCameras"] and not admin_session["permissions"]["manageUsers"]

    direct_http_login = urllib.request.Request(
        base + "/api/auth/login",
        data=json.dumps({"username": "admin1", "password": admin_password}).encode(),
        method="POST",
        headers={"Host": "192.168.50.160", "Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(direct_http_login, timeout=10)
        raise AssertionError("direct insecure LAN login was accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 426 and json.load(error)["detail"] == "https-required-for-application"

    original_private_http = camera_app.ALLOW_INSECURE_PRIVATE_MANAGEMENT
    original_private_networks = camera_app.PRIVATE_HTTP_NETWORKS
    camera_app.ALLOW_INSECURE_PRIVATE_MANAGEMENT = True
    camera_app.PRIVATE_HTTP_NETWORKS = (camera_app.ipaddress.ip_network("192.168.50.0/24"),)
    with urllib.request.urlopen(direct_http_login, timeout=10) as response:
        assert response.status == 200 and json.load(response)["user"]["role"] == "admin"
    camera_app.ALLOW_INSECURE_PRIVATE_MANAGEMENT = original_private_http
    camera_app.PRIVATE_HTTP_NETWORKS = original_private_networks

    original_trusted_proxies = camera_app.TRUSTED_PROXY_NETWORKS
    camera_app.TRUSTED_PROXY_NETWORKS = (camera_app.ipaddress.ip_network("127.0.0.0/8"),)
    trusted_proxy_login = urllib.request.Request(
        base + "/api/auth/login",
        data=json.dumps({"username": "admin1", "password": admin_password}).encode(),
        method="POST",
        headers={
            "Host": "camera.example.test",
            "Content-Type": "application/json",
            "X-Forwarded-For": "192.168.50.25",
            "X-Forwarded-Proto": "https",
        },
    )
    with urllib.request.urlopen(trusted_proxy_login, timeout=10) as response:
        assert response.status == 200 and json.load(response)["user"]["role"] == "admin"
    camera_app.TRUSTED_PROXY_NETWORKS = original_trusted_proxies

    admin_cameras = request("/api/admin/cameras", opener=admin_client)["cameras"]
    assert admin_cameras
    garden_admin = next(item for item in admin_cameras if item["id"] == "garten")
    assert garden_admin["activeCredentials"] == {"mode": "none", "shared": False, "onvif": False, "stream": False}
    assert garden_admin["draftCredentials"] == {"mode": "none", "shared": False, "onvif": False, "stream": False}
    assert garden_admin["liveAccess"]["usesActiveRevision"] is False
    assert garden_admin["liveAccess"]["credentialSource"] == "none"
    assert garden_admin["liveAccess"]["authenticatedLive"] is False
    assert request("/api/admin/users", expected=403, opener=admin_client)["detail"] == "insufficient-role"
    assert request("/api/admin/users/owner", "DELETE", csrf=csrf, expected=409)["detail"] == "cannot-delete-self"

    replacement_viewer_password = "Viewer-Replacement-Password-43!"
    request(f"/api/admin/users/{viewer['id']}/password", "POST", {"password": replacement_viewer_password}, csrf)
    assert request("/api/auth/state", opener=viewer_client)["authenticated"] is False
    replacement_client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    replacement_session = request("/api/auth/login", "POST", {"username": "viewer1", "password": replacement_viewer_password}, opener=replacement_client)
    assert replacement_session["user"]["role"] == "viewer"

    cameras = request("/api/cameras")["cameras"]
    assert [item["id"] for item in cameras] == ["garten", "eingang", "serverraum", "rueckseite", "einfahrt", "garage"]
    assert all(item["usesCredentials"] is False for item in cameras)
    serialized = json.dumps(cameras)
    assert "192.168.50." not in serialized and password not in serialized and "rtsp://" not in serialized
    ciphertext = camera_app.encrypt_text("camera-secret")
    assert "camera-secret" not in ciphertext and camera_app.decrypt_text(ciphertext) == "camera-secret"
    assert 2020 in camera_app.SCAN_PORTS

    owner_profile = request(
        "/api/display-profiles",
        "POST",
        {"name": "Eingänge", "cameraIds": ["eingang", "garten"]},
        csrf,
        expected=201,
    )
    assert owner_profile["cameraIds"] == ["eingang", "garten"]
    assert [item["id"] for item in request(f"/api/cameras?profileId={owner_profile['id']}")["cameras"]] == ["eingang", "garten"]
    assert request(
        "/api/display-profiles",
        "POST",
        {"name": "EINGÄNGE", "cameraIds": []},
        csrf,
        expected=409,
    )["detail"] == "display-profile-name-exists"
    assert request(
        "/api/display-profiles",
        "POST",
        {"name": "Ungültig", "cameraIds": ["nicht-vorhanden"]},
        csrf,
        expected=400,
    )["detail"] == "invalid-camera-selection"
    viewer_profile = request(
        "/api/display-profiles",
        "POST",
        {"name": "Tablet", "cameraIds": ["garage"]},
        replacement_session["csrfToken"],
        expected=201,
        opener=replacement_client,
    )
    viewer_profiles = request("/api/display-profiles", opener=replacement_client)
    assert [item["id"] for item in viewer_profiles["profiles"]] == [viewer_profile["id"]]
    assert any(item["id"] == "garten" and item["enabled"] for item in viewer_profiles["cameraOptions"])
    assert request(
        f"/api/cameras?profileId={owner_profile['id']}",
        expected=404,
        opener=replacement_client,
    )["detail"] == "display-profile-not-found"
    assert request(
        f"/api/display-profiles/{viewer_profile['id']}",
        "PUT",
        {"name": "Fremd", "cameraIds": []},
        csrf,
        expected=404,
    )["detail"] == "display-profile-not-found"
    request("/api/admin/cameras/garten", "PATCH", {"enabled": False}, csrf)
    assert [item["id"] for item in request(f"/api/cameras?profileId={owner_profile['id']}")["cameras"]] == ["eingang"]
    assert request("/api/display-profiles")["profiles"][0]["cameraIds"] == ["eingang", "garten"]
    request("/api/admin/cameras/garten", "PATCH", {"enabled": True}, csrf)
    updated_profile = request(
        f"/api/display-profiles/{owner_profile['id']}",
        "PUT",
        {"name": "Eingänge", "cameraIds": ["garten", "eingang"]},
        csrf,
    )
    assert updated_profile["cameraIds"] == ["garten", "eingang"]
    assert [item["id"] for item in request(f"/api/cameras?profileId={owner_profile['id']}")["cameras"]] == ["garten", "eingang"]
    updated_profile = request(
        f"/api/display-profiles/{owner_profile['id']}",
        "PUT",
        {
            "name": updated_profile["name"],
            "cameraIds": ["garten", "eingang"],
            "cameraModes": {"garten": "high", "eingang": "hls"},
            "schedules": [],
        },
        csrf,
    )
    assert updated_profile["cameraModes"] == {"garten": "high", "eingang": "hls"}
    profiled_cameras = request(f"/api/cameras?profileId={owner_profile['id']}")["cameras"]
    assert [item["streamMode"] for item in profiled_cameras] == ["high", "hls"]

    display_device = request(
        "/api/owner/display-devices",
        "POST",
        {
            "name": "Leitstellen-TV",
            "enabled": True,
            "profileIds": [owner_profile["id"]],
        },
        csrf,
        expected=201,
    )
    assert display_device["profileIds"] == [owner_profile["id"]]
    assert request(
        "/api/owner/display-devices",
        expected=403,
        opener=admin_client,
    )["detail"] == "insufficient-role"
    pair_code = request(
        f"/api/owner/display-devices/{display_device['id']}/pairing-code",
        "POST",
        csrf=csrf,
    )["code"]
    assert len(pair_code) == 8 and pair_code.isdigit()
    cross_origin_pair = urllib.request.Request(
        base + "/api/display/pair",
        data=json.dumps({"code": pair_code}).encode(),
        method="POST",
        headers={
            "Host": "127.0.0.1",
            "Origin": "http://untrusted.example",
            "Content-Type": "application/json",
        },
    )
    try:
        urllib.request.urlopen(cross_origin_pair, timeout=10)
        raise AssertionError("cross-origin display pairing was accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 403 and json.load(error)["detail"] == "display-origin-invalid"
    display_client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    paired = request(
        "/api/display/pair",
        "POST",
        {"code": pair_code},
        opener=display_client,
    )
    assert paired["paired"] and paired["active"]
    second_display_client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    assert request(
        "/api/display/pair",
        "POST",
        {"code": pair_code},
        expected=400,
        opener=second_display_client,
    )["detail"] == "display-pair-code-invalid"
    expired_code = request(
        f"/api/owner/display-devices/{display_device['id']}/pairing-code",
        "POST",
        csrf=csrf,
    )["code"]
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE display_pairing_codes SET expires_at=0 WHERE code_hash=?",
            (camera_app.hash_pairing_code(expired_code),),
        )
    assert request(
        "/api/display/pair",
        "POST",
        {"code": expired_code},
        expected=400,
        opener=second_display_client,
    )["detail"] == "display-pair-code-invalid"
    initial_display_revision = paired["configRevision"]
    request("/api/admin/cameras/garten", "PATCH", {"enabled": False}, csrf)
    disabled_display_state = request("/api/display/state", opener=display_client)
    assert disabled_display_state["configRevision"] != initial_display_revision
    assert [
        item["id"]
        for item in request("/api/display/cameras", opener=display_client)["cameras"]
    ] == ["eingang"]
    request("/api/admin/cameras/garten", "PATCH", {"enabled": True}, csrf)
    assert (
        request("/api/display/state", opener=display_client)["configRevision"]
        != disabled_display_state["configRevision"]
    )
    display_cameras = request("/api/display/cameras", opener=display_client)
    assert [item["id"] for item in display_cameras["cameras"]] == ["garten", "eingang"]
    assert [item["streamMode"] for item in display_cameras["cameras"]] == ["high", "hls"]
    assert request(
        "/api/admin/users",
        expected=401,
        opener=display_client,
    )["detail"] == "authentication-required"
    display_lease = request(
        "/api/display/cameras/garten/lease",
        "POST",
        opener=display_client,
    )
    assert display_lease["leaseId"].startswith(f"display-{display_device['id']}-")
    assert request(
        "/api/display/cameras/garage/lease",
        "POST",
        expected=404,
        opener=display_client,
    )["detail"] == "display-camera-not-assigned"
    request(
        f"/api/display/cameras/garten/lease?leaseId={display_lease['leaseId']}",
        "DELETE",
        expected=204,
        opener=display_client,
    )
    allowed_media = urllib.request.Request(
        base + "/api/auth/authorize",
        headers={"X-Forwarded-Uri": "/whep/garten-low/whep"},
    )
    with display_client.open(allowed_media, timeout=10) as response:
        assert response.status == 204
    denied_media = urllib.request.Request(
        base + "/api/auth/authorize",
        headers={"X-Forwarded-Uri": "/hls/garage-low/"},
    )
    try:
        display_client.open(denied_media, timeout=10)
        raise AssertionError("display accessed an unassigned media path")
    except urllib.error.HTTPError as error:
        assert error.code == 403

    with camera_app.connect() as conn:
        original_paths = conn.execute(
            "SELECT low_path,high_path FROM cameras WHERE id='garten'"
        ).fetchone()
        conn.execute(
            "UPDATE cameras SET low_path='garten-low-only',high_path='garten-high-only' WHERE id='garten'"
        )
    high_media = urllib.request.Request(
        base + "/api/auth/authorize",
        headers={"X-Forwarded-Uri": "/whep/garten-high-only/whep"},
    )
    with display_client.open(high_media, timeout=10) as response:
        assert response.status == 204
    forbidden_low_media = urllib.request.Request(
        base + "/api/auth/authorize",
        headers={"X-Forwarded-Uri": "/whep/garten-low-only/whep"},
    )
    try:
        display_client.open(forbidden_low_media, timeout=10)
        raise AssertionError("high-only display profile accessed its low stream")
    except urllib.error.HTTPError as error:
        assert error.code == 403
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE cameras SET low_path=?,high_path=? WHERE id='garten'",
            (original_paths["low_path"], original_paths["high_path"]),
        )

    midnight_profile = request(
        f"/api/display-profiles/{owner_profile['id']}",
        "PUT",
        {
            "name": updated_profile["name"],
            "cameraIds": ["garten", "eingang"],
            "cameraModes": {"garten": "high", "eingang": "hls"},
            "schedules": [
                {"weekday": 6, "startMinute": 1380, "endMinute": 90}
            ],
        },
        csrf,
    )
    assert midnight_profile["schedules"] == [
        {"weekday": 6, "startMinute": 1380, "endMinute": 1440},
        {"weekday": 0, "startMinute": 0, "endMinute": 90},
    ]
    request(
        f"/api/display-profiles/{owner_profile['id']}",
        "PUT",
        {
            "name": updated_profile["name"],
            "cameraIds": ["garten", "eingang"],
            "cameraModes": {"garten": "high", "eingang": "hls"},
            "schedules": [],
        },
        csrf,
    )

    with camera_app.connect() as conn:
        stamp = camera_app.now_iso()
        secondary_profile_id = "owner-secondary-test"
        conn.execute(
            """INSERT INTO display_profiles(id,user_id,name,name_key,created_at,updated_at)
               VALUES(?,?,?,?,?,?)""",
            (
                secondary_profile_id,
                "owner",
                "Sekundärprofil",
                "sekundärprofil",
                stamp,
                stamp,
            ),
        )
        conn.execute(
            """INSERT INTO display_device_profiles(device_id,profile_id,position)
               VALUES(?,?,?)""",
            (display_device["id"], secondary_profile_id, 1),
        )
        conn.execute(
            """INSERT INTO display_profile_schedules(
               id,profile_id,weekday,start_minute,end_minute,position)
               VALUES(?,?,?,?,?,?)""",
            ("test-window", owner_profile["id"], 0, 600, 660, 0),
        )
        conn.execute(
            """INSERT INTO display_profile_schedules(
               id,profile_id,weekday,start_minute,end_minute,position)
               VALUES(?,?,?,?,?,?)""",
            ("test-overlap", secondary_profile_id, 0, 600, 660, 0),
        )
        monday_active = camera_app.datetime(
            2026, 1, 5, 10, 30, tzinfo=camera_app.DISPLAY_TIMEZONE
        )
        monday_idle = camera_app.datetime(
            2026, 1, 5, 11, 30, tzinfo=camera_app.DISPLAY_TIMEZONE
        )
        assert camera_app.active_display_profile(
            conn, display_device["id"], monday_active
        )[0]["id"] == owner_profile["id"]
        assert camera_app.active_display_profile(
            conn, display_device["id"], monday_idle
        )[0] is None
        # Overlapping weekly windows always select the device assignment with
        # the lower position (the owner's explicitly configured priority).
        assert camera_app.active_display_profile(
            conn, display_device["id"], monday_active
        )[0]["id"] == owner_profile["id"]
        conn.execute(
            "DELETE FROM display_profile_schedules WHERE id IN ('test-window','test-overlap')"
        )
        conn.execute(
            """INSERT INTO display_profile_schedules(
               id,profile_id,weekday,start_minute,end_minute,position)
               VALUES(?,?,?,?,?,?)""",
            ("test-dst", owner_profile["id"], 6, 150, 210, 0),
        )
        before_dst_gap = camera_app.datetime(
            2026, 3, 28, 12, 0, tzinfo=camera_app.DISPLAY_TIMEZONE
        )
        dst_start = camera_app.next_profile_start(
            conn, display_device["id"], before_dst_gap
        )[0]
        assert (dst_start.hour, dst_start.minute) == (3, 30)
        # Both occurrences of 02:30 during the autumn clock change remain
        # inside the configured weekly window.
        for fold in (0, 1):
            autumn = camera_app.datetime(
                2026,
                10,
                25,
                2,
                30,
                fold=fold,
                tzinfo=camera_app.DISPLAY_TIMEZONE,
            )
            assert camera_app.profile_active_at(conn, owner_profile["id"], autumn)
        conn.execute("DELETE FROM display_profile_schedules WHERE id='test-dst'")
        conn.execute(
            "DELETE FROM display_device_profiles WHERE profile_id=?",
            (secondary_profile_id,),
        )
        conn.execute(
            "DELETE FROM display_profiles WHERE id=?", (secondary_profile_id,)
        )
    request(
        f"/api/display-profiles/{viewer_profile['id']}",
        "DELETE",
        csrf=replacement_session["csrfToken"],
        expected=204,
        opener=replacement_client,
    )
    assert request("/api/display-profiles", opener=replacement_client)["profiles"] == []

    denied = request("/api/admin/cameras/order", "PUT", {"cameraIds": [item["id"] for item in cameras]}, expected=403)
    assert denied["detail"] == "csrf-invalid"
    order = [item["id"] for item in reversed(cameras)]
    assert request("/api/admin/cameras/order", "PUT", {"cameraIds": order}, csrf)["cameraIds"] == order
    assert [item["id"] for item in request("/api/cameras")["cameras"]] == order
    spoofed = urllib.request.Request(
        base + "/api/admin/cameras/order",
        data=json.dumps({"cameraIds": order}).encode(),
        method="PUT",
        headers={
            "Host": "192.168.50.160",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
            "X-Forwarded-Proto": "https",
        },
    )
    try:
        client.open(spoofed, timeout=10)
        raise AssertionError("untrusted forwarded HTTPS header was accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 426 and json.load(error)["detail"] == "https-required-for-application"

    zone_payload = {"revision": 0, "zones": [{"name": "Einfahrt Alarm", "kind": "alarm", "enabled": True, "points": [{"x": .1, "y": .1}, {"x": .8, "y": .1}, {"x": .5, "y": .8}]}]}
    assert request("/api/admin/cameras/garten/zones", "PUT", zone_payload, csrf)["revision"] == 1
    zones = request("/api/admin/cameras/garten/zones")
    assert zones["zones"][0]["points"][2] == {"x": .5, "y": .8}
    zone_id = zones["zones"][0]["id"]
    detection_camera = request("/api/admin/cameras/garten/detection")
    assert detection_camera["supported"] is True and detection_camera["enabled"] is False
    configured_detection = request(
        "/api/admin/cameras/garten/detection",
        "PUT",
        {
            "enabled": True,
            "schedules": [],
            "zones": [{
                "zoneId": zone_id,
                "enabled": True,
                "sensitivity": 50,
                "minAreaPercent": 1.5,
                "confirmationSeconds": 1,
                "quietSeconds": 5,
                "cooldownSeconds": 30,
                "snapshotEnabled": True,
                "schedules": [],
            }],
        },
        csrf,
    )
    assert configured_detection["enabled"] is True
    with camera_app.connect() as conn:
        camera_app.replace_detection_schedules(
            conn,
            "camera_detection_schedules",
            "camera_id",
            "garten",
            [camera_app.DetectionScheduleInput(
                weekday=0, startMinute=1320, endMinute=120
            )],
        )
        split = conn.execute(
            """SELECT weekday,start_minute,end_minute
               FROM camera_detection_schedules
               WHERE camera_id='garten' ORDER BY position"""
        ).fetchall()
        assert [tuple(row) for row in split] == [(0, 1320, 1440), (1, 0, 120)]
        conn.execute("DELETE FROM camera_detection_schedules WHERE camera_id='garten'")
    assert request(
        "/api/owner/detection", "PUT", {"mode": "observe"}, csrf
    )["mode"] == "observe"
    internal_config = urllib.request.Request(
        base + "/internal/v1/detection/config",
        headers={"Authorization": f"Bearer {camera_app.DETECTION_ADAPTER_TOKEN}"},
    )
    with urllib.request.urlopen(internal_config, timeout=5) as response:
        live_detection = json.load(response)
    assert live_detection["enabled"] is True
    assert [item["id"] for item in live_detection["cameras"]] == ["garten"]
    assert all("sourceUri" not in item for item in live_detection["cameras"])
    worker_event_id = uuid.uuid4().hex
    motion_body = {
        "workerEventId": worker_event_id,
        "cameraId": "garten",
        "zoneId": zone_id,
        "state": "started",
        "motionPercent": 3.2,
        "strength": 72,
    }
    motion_request = urllib.request.Request(
        base + "/internal/v1/detection/events",
        data=json.dumps(motion_body).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {camera_app.DETECTION_ADAPTER_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(motion_request, timeout=5) as response:
        motion_started = json.load(response)
    assert motion_started["status"] == "open" and motion_started["snapshotRequested"]
    motion_view = request("/api/events?status=open&eventType=zone.motion")
    assert motion_view["summary"]["open"] == 1
    assert all(item["type"] == "zone.motion" for item in motion_view["events"])
    tiny_jpeg = bytes.fromhex("ffd8ffc0000b080001000101011100ffd9")
    snapshot_request = urllib.request.Request(
        base + f"/internal/v1/detection/events/{motion_started['eventId']}/snapshot",
        data=tiny_jpeg,
        method="POST",
        headers={
            "Authorization": f"Bearer {camera_app.DETECTION_ADAPTER_TOKEN}",
            "Content-Type": "image/jpeg",
        },
    )
    with urllib.request.urlopen(snapshot_request, timeout=5) as response:
        assert json.load(response)["stored"] is True
    motion_snapshot = urllib.request.Request(
        base + f"/api/motion-events/{motion_started['eventId']}/snapshot",
        headers={"Host": "127.0.0.1"},
    )
    with client.open(motion_snapshot, timeout=5) as response:
        assert response.read() == tiny_jpeg
        assert response.headers["Cache-Control"] == "no-store, private"
    with camera_app.connect() as conn:
        asset = conn.execute(
            "SELECT asset_path FROM motion_event_assets WHERE event_id=?",
            (motion_started["eventId"],),
        ).fetchone()
    asset_file = camera_app.MOTION_ASSET_ROOT / asset["asset_path"]
    encrypted_asset = asset_file.read_bytes()
    assert tiny_jpeg not in encrypted_asset
    asset_file.write_bytes(b"corrupted")
    assert request(
        f"/api/motion-events/{motion_started['eventId']}/snapshot",
        expected=500,
    )["detail"] == "motion-snapshot-decryption-failed"
    asset_file.unlink()
    assert request(
        f"/api/motion-events/{motion_started['eventId']}/snapshot",
        expected=404,
    )["detail"] == "motion-snapshot-not-found"
    asset_file.write_bytes(encrypted_asset)
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE motion_event_assets SET expires_at=0 WHERE event_id=?",
            (motion_started["eventId"],),
        )
    assert camera_app.detection_maintenance_once()["removedAssets"] == 1
    assert not asset_file.exists()
    with camera_app.connect() as conn:
        cleaned_details = json.loads(conn.execute(
            "SELECT details_json FROM system_events WHERE id=?",
            (motion_started["eventId"],),
        ).fetchone()["details_json"])
    assert cleaned_details["snapshotAvailable"] is False
    with urllib.request.urlopen(motion_request, timeout=5) as response:
        assert json.load(response)["eventId"] == motion_started["eventId"]
    motion_body["state"] = "ended"
    motion_end_request = urllib.request.Request(
        base + "/internal/v1/detection/events",
        data=json.dumps(motion_body).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {camera_app.DETECTION_ADAPTER_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(motion_end_request, timeout=5) as response:
        assert json.load(response)["status"] == "resolved"
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM system_events WHERE dedupe_key=?",
            (f"zone.motion:{worker_event_id}",),
        ).fetchone()[0] == 1
    request("/api/owner/detection", "PUT", {"mode": "observe"}, csrf)
    stale_motion_id = uuid.uuid4().hex
    stale_motion = camera_app.detection_events(
        camera_app.DetectionEventInput(
            workerEventId=stale_motion_id,
            cameraId="garten",
            zoneId=zone_id,
            state="started",
            motionPercent=2,
            strength=55,
        ),
        None,
    )
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE detection_settings SET worker_last_seen_at=? WHERE id=1",
            ("2020-01-01T00:00:00+00:00",),
        )
    assert camera_app.detection_maintenance_once()["resolvedEvents"] >= 1
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT status FROM system_events WHERE id=?", (stale_motion["eventId"],)
        ).fetchone()["status"] == "resolved"
    assert request("/api/owner/detection", "PUT", {"mode": "off"}, csrf)["mode"] == "off"

    vendor_secret = "Vendor-Only-Test-Secret!"
    original_ffprobe = camera_app.ffprobe_uri
    camera_app.ffprobe_uri = lambda _uri: {"ok": True, "codec": "mjpeg", "width": 640, "height": 480, "packets": 2}
    added = request("/api/admin/cameras", "POST", {
        "name": "OpenCam Vorschau", "address": "192.168.50.220", "protocol": "snapshot", "port": 8080,
        "lowSourcePath": "/snapshot.jpg", "codec": "mjpeg", "username": "viewer", "password": vendor_secret,
        "onvifScheme": "http", "onvifPort": 2020, "onvifPath": "/onvif/device_service",
        "manufacturer": "OpenCam", "model": "Standards-Test",
    }, csrf)
    assert added["managed"] is True and added["hasCredentials"] is True and "password" not in added
    assert added["activeCredentials"]["stream"] is True
    assert added["liveAccess"]["usesActiveRevision"] is True
    assert added["liveAccess"]["credentialSource"] == "active-revision"
    assert added["liveAccess"]["authenticationConfigured"] is True
    assert added["liveAccess"]["authenticatedLive"] is False
    viewer_camera = next(item for item in request("/api/cameras")["cameras"] if item["id"] == added["id"])
    assert viewer_camera["displayMode"] == "snapshot" and viewer_camera["snapshotPath"].endswith("/snapshot")
    assert viewer_camera["usesCredentials"] is True
    assert "192.168.50.220" not in json.dumps(viewer_camera) and vendor_secret not in json.dumps(viewer_camera)
    request(
        f"/api/display-profiles/{owner_profile['id']}",
        "PUT",
        {"name": "Eingänge", "cameraIds": [added["id"], "garten", "eingang"]},
        csrf,
    )
    with camera_app.connect() as conn:
        stored = conn.execute("SELECT username_ct,password_ct FROM credentials").fetchone()
        stored_connection = conn.execute(
            "SELECT onvif_scheme,onvif_port,onvif_path FROM camera_connections WHERE camera_id=?",
            (added["id"],),
        ).fetchone()
    assert vendor_secret not in stored["password_ct"] and camera_app.decrypt_text(stored["password_ct"]) == vendor_secret
    assert dict(stored_connection) == {
        "onvif_scheme": "http",
        "onvif_port": 2020,
        "onvif_path": "/onvif/device_service",
    }
    renamed = request(f"/api/admin/cameras/{added['id']}", "PATCH", {"name": "OpenCam Eingang"}, csrf)
    assert renamed["name"] == "OpenCam Eingang"
    request(f"/api/admin/cameras/{added['id']}", "DELETE", csrf=csrf, expected=204)
    camera_app.ffprobe_uri = original_ffprobe
    assert all(item["id"] != added["id"] for item in request("/api/cameras")["cameras"])
    assert request("/api/display-profiles")["profiles"][0]["cameraIds"] == ["garten", "eingang"]

    invalid = {"name": "Outside", "address": "8.8.8.8", "protocol": "rtsp", "port": 554, "lowSourcePath": "/live", "codec": "h264"}
    assert request("/api/admin/cameras/test-source", "POST", invalid, csrf, expected=422)["detail"]

    shared_secret = "Authenticated-Camera-Test-Secret!"
    connection_body = {
        "address": "192.168.50.8", "streamProtocol": "rtsp", "streamPort": 8554,
        "lowSourcePath": "/tcp/av0_1", "highSourcePath": "/tcp/av0_0", "codec": "h264",
        "onvifScheme": "http", "onvifPort": 10080, "onvifPath": "/onvif/device_service",
        "credentialMode": "shared", "sharedUsername": "camera-user", "sharedPassword": shared_secret,
    }
    original_connection_test = camera_app.connection_test_result
    camera_app.connection_test_result = lambda camera_id, body: {
        "cameraId": camera_id, "verified": True,
        "stream": {"low": {"ok": True, "codec": "h264", "width": 640, "height": 480, "packets": 30, "hasBFrames": 0}, "high": {"ok": True, "codec": "h264", "width": 1280, "height": 720, "packets": 30, "hasBFrames": 2}},
        "onvif": {"ok": True, "device": {"manufacturer": "OpenCam", "model": "Authenticated"}},
        "capabilities": None,
    }
    tested = request("/api/admin/cameras/garten/connection/test", "POST", connection_body, csrf)
    assert tested["verified"] and shared_secret not in json.dumps(tested)
    draft = request("/api/admin/cameras/garten/connection", "PUT", connection_body, csrf)
    assert draft["state"] == "draft" and draft["credentials"]["shared"] and "sharedPassword" not in draft
    connection_view = request("/api/admin/cameras/garten/connection")
    assert connection_view["revisions"][0]["revision"] == draft["revision"]
    assert shared_secret not in json.dumps(connection_view) and "camera-user" not in json.dumps(connection_view)
    garden_with_draft = next(item for item in request("/api/admin/cameras")["cameras"] if item["id"] == "garten")
    assert garden_with_draft["draftCredentials"]["stream"] is True
    assert garden_with_draft["draftTestStatus"] == "verified"
    assert garden_with_draft["liveAccess"]["usesActiveRevision"] is False
    assert garden_with_draft["liveAccess"]["authenticationConfigured"] is False
    with camera_app.connect() as conn:
        encrypted = conn.execute(
            """SELECT cr.username_ct,cr.password_ct FROM camera_connections cc
               JOIN credentials cr ON cr.id=cc.shared_credential_id WHERE cc.id=?""",
            (draft["id"],),
        ).fetchone()
    assert shared_secret not in encrypted["password_ct"] and camera_app.decrypt_text(encrypted["password_ct"]) == shared_secret

    original_monitor = camera_app.activation_monitor
    camera_app.activation_monitor = lambda *_args: None
    activated = request("/api/admin/cameras/garten/connection/activate", "POST", {"revision": draft["revision"]}, csrf)
    assert activated["state"] == "monitoring" and request("/api/admin/cameras/garten/connection")["activeRevision"] == draft["revision"]
    activated_viewer = next(item for item in request("/api/cameras")["cameras"] if item["id"] == "garten")
    assert activated_viewer["highWebRTCCompatible"] is False
    assert activated_viewer["compatibilityRelay"] is True
    with camera_app.connect() as conn:
        conn.execute("UPDATE cameras SET managed=1 WHERE id='garten'")
        conn.commit()
    dynamic_config = camera_app.relay_config()
    dynamic_garden = next(item for item in dynamic_config["cameras"] if item["cameraId"] == "garten")
    dynamic_source = camera_app.urlparse(dynamic_garden["sourceUri"])
    assert dynamic_garden["connectionRevision"] == draft["revision"]
    assert dynamic_garden["transcode"] is True
    assert unquote(dynamic_source.username or "") == "camera-user"
    assert unquote(dynamic_source.password or "") == shared_secret
    with camera_app.connect() as conn:
        conn.execute("UPDATE cameras SET managed=0 WHERE id='garten'")
        conn.commit()
    rolled_back = request("/api/admin/cameras/garten/connection/rollback", "POST", csrf=csrf)
    assert rolled_back["state"] == "active" and rolled_back["revision"] == 1
    rolled_back_viewer = next(item for item in request("/api/cameras")["cameras"] if item["id"] == "garten")
    assert rolled_back_viewer["highWebRTCCompatible"] is True
    assert rolled_back_viewer["compatibilityRelay"] is False
    camera_app.activation_monitor = original_monitor
    camera_app.connection_test_result = original_connection_test

    capability_payload = {
        "device": {"manufacturer": "OpenCam", "model": "PTZ Test", "firmwareVersion": "1", "serialNumber": "redacted", "hardwareId": "mock"},
        "profiles": [{"token": "profile1", "name": "Main", "codec": "h264", "width": 1920, "height": 1080, "frameRate": 25, "bitrate": 2048, "audioCodec": "pcma", "streamPath": "/live"}],
        "snapshot": {"supported": True}, "audio": {"supported": True, "codecs": ["pcma"]},
        "ptz": {"supported": True, "presets": [{"token": "preset1", "name": "Einfahrt"}], "absoluteMove": False, "relativeMove": False, "continuousMove": True},
        "imaging": True, "events": True, "analytics": False, "deviceIo": True, "relayOutputs": [], "talkback": False,
    }
    class FakeOnvif:
        def capabilities(self): return capability_payload
    original_client_factory = camera_app.onvif_client_for
    camera_app.onvif_client_for = lambda *_args: FakeOnvif()
    refreshed = request("/api/admin/cameras/garten/capabilities/refresh", "POST", csrf=csrf)
    assert refreshed["ptz"]["supported"] and refreshed["audio"]["supported"]
    stored_capabilities = request("/api/admin/cameras/garten/capabilities")
    assert stored_capabilities["available"] and stored_capabilities["profiles"][0]["token"] == "profile1"
    camera_app.onvif_client_for = original_client_factory

    ptz_calls = []
    class FakePTZ:
        def ptz_move(self, *args): ptz_calls.append(("move", args))
        def ptz_stop(self, *args): ptz_calls.append(("stop", args))
        def goto_preset(self, *args): ptz_calls.append(("preset", args))
    original_ptz_context = camera_app.ptz_context
    camera_app.ptz_context = lambda *_args: (FakePTZ(), capability_payload)
    assert request("/api/admin/cameras/garten/ptz/move", "POST", {"x": .3, "y": 0, "zoom": 0, "profileToken": "profile1"}, csrf)["ok"]
    assert request("/api/admin/cameras/garten/ptz/stop", "POST", {"profileToken": "profile1"}, csrf)["ok"]
    assert request("/api/admin/cameras/garten/ptz/presets/preset1/goto", "POST", {"profileToken": "profile1"}, csrf)["ok"]
    assert [item[0] for item in ptz_calls] == ["move", "stop", "preset"]
    camera_app.ptz_context = original_ptz_context

    class OnvifMock(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_POST(self):
            request_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if b"GetCapabilities" in request_body:
                body = f'<GetCapabilitiesResponse><XAddr>http://127.0.0.1:{self.server.server_port}/onvif/Media</XAddr></GetCapabilitiesResponse>'.encode()
            elif b"GetProfiles" in request_body:
                body = b'<GetProfilesResponse><Profiles token="profile1"><Name>Main</Name><Encoding>H264</Encoding><Resolution><Width>1920</Width><Height>1080</Height></Resolution></Profiles></GetProfilesResponse>'
            elif b"GetStreamUri" in request_body:
                body = f'<GetStreamUriResponse><Uri>rtsp://127.0.0.1:{self.server.server_port}/live</Uri></GetStreamUriResponse>'.encode()
            elif b"GetSnapshotUri" in request_body:
                body = f'<GetSnapshotUriResponse><Uri>http://127.0.0.1:{self.server.server_port}/snapshot.jpg</Uri></GetSnapshotUriResponse>'.encode()
            else:
                body = b'<GetDeviceInformationResponse><Manufacturer>OpenCam</Manufacturer><Model>Standards-Test</Model></GetDeviceInformationResponse>'
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    mock = ThreadingHTTPServer(("127.0.0.1", 0), OnvifMock)
    mock_thread = threading.Thread(target=mock.serve_forever, daemon=True); mock_thread.start()
    supported, manufacturer, model = camera_app.onvif_info("127.0.0.1", mock.server_port)
    original_network = camera_app.ALLOWED_NETWORK
    camera_app.ALLOWED_NETWORK = camera_app.ipaddress.ip_network("127.0.0.0/8")
    inventory = camera_app.onvif_inventory("127.0.0.1", mock.server_port)
    camera_app.ALLOWED_NETWORK = original_network
    mock.shutdown(); mock_thread.join(timeout=2)
    assert supported and manufacturer == "OpenCam" and model == "Standards-Test"
    assert inventory["profiles"][0] == {"token": "profile1", "name": "Main", "codec": "h264", "width": 1920, "height": 1080, "streamPath": "/live"}
    assert inventory["snapshotUri"].endswith("/snapshot.jpg")
    wsse = camera_app.OnvifClient("http://127.0.0.1/onvif/device_service", "owner", "transient-secret").wsse_header()
    assert "PasswordDigest" in wsse and "transient-secret" not in wsse and "<wsse:Nonce" in wsse

    discovery_secret = "Discovery-Only-Secret-42!"
    discovery_user = "discovery-user"
    discovery_scan_id = "scan-auth-preview"
    discovery_device_id = "device-auth-preview"
    camera_app.SCANS[discovery_scan_id] = {
        "id": discovery_scan_id,
        "state": "complete",
        "createdAt": camera_app.now_iso(),
        "createdEpoch": time.time(),
        "results": [{
            "id": discovery_device_id,
            "address": "192.168.50.199",
            "manufacturer": "Unbekannt",
            "model": "Unbekannt",
            "onvif": True,
            "onvifPort": 2020,
            "rtsp": True,
            "openPorts": [554, 2020],
            "profiles": [],
            "previewAvailable": False,
            "configuredCameraId": None,
            "configuredName": None,
            "_snapshotUri": None,
        }],
    }

    class DiscoveryOnvif:
        def __init__(self, *_args, **_kwargs):
            pass
        def capabilities(self):
            return {
                "device": {"manufacturer": "StandardsCam", "model": "ONVIF Preview"},
                "profiles": [
                    {"token": "low", "name": "Sub", "codec": "h264", "width": 640, "height": 360, "frameRate": 15, "bitrate": 512, "audioCodec": "pcma"},
                    {"token": "high", "name": "Main", "codec": "h264", "width": 1920, "height": 1080, "frameRate": 25, "bitrate": 2048, "audioCodec": "pcma"},
                ],
            }
        def stream_uri(self, token):
            return f"rtsp://192.168.50.199:554/{token}"

    original_onvif_client = camera_app.OnvifClient
    original_transient_preview = camera_app.transient_rtsp_preview
    captured_source = []
    camera_app.OnvifClient = DiscoveryOnvif
    camera_app.transient_rtsp_preview = lambda uri: captured_source.append(uri) or b"\xff\xd8discovery-frame\xff\xd9"
    discovery_result = request(
        f"/api/admin/discovery/scans/{discovery_scan_id}/devices/{discovery_device_id}/probe",
        "POST",
        {"username": discovery_user, "password": discovery_secret},
        admin_session["csrfToken"],
        opener=admin_client,
    )
    camera_app.OnvifClient = original_onvif_client
    camera_app.transient_rtsp_preview = original_transient_preview
    assert discovery_result["previewAvailable"] and discovery_result["previewVerified"]
    assert discovery_result["profiles"][0]["streamPath"] == "/low"
    assert "streamUri" not in json.dumps(discovery_result)
    assert discovery_secret not in json.dumps(discovery_result)
    assert discovery_secret not in json.dumps(camera_app.SCANS[discovery_scan_id])
    assert discovery_user not in json.dumps(camera_app.SCANS[discovery_scan_id])
    parsed_discovery_source = camera_app.urlparse(captured_source[0])
    assert unquote(parsed_discovery_source.username or "") == discovery_user
    assert unquote(parsed_discovery_source.password or "") == discovery_secret
    preview_request = urllib.request.Request(
        base + f"/api/admin/discovery/scans/{discovery_scan_id}/devices/{discovery_device_id}/preview",
        headers={"Host": "127.0.0.1"},
    )
    with admin_client.open(preview_request, timeout=10) as response:
        assert response.headers["Cache-Control"] == "no-store, private"
        assert response.headers["Content-Type"].startswith("image/jpeg")
        assert response.read().startswith(b"\xff\xd8")

    configured_scan_id = "scan-configured-preview"
    configured_device_id = "device-configured-preview"
    camera_app.SCANS[configured_scan_id] = {
        "id": configured_scan_id,
        "state": "complete",
        "createdAt": camera_app.now_iso(),
        "createdEpoch": time.time(),
        "results": [{
            "id": configured_device_id,
            "address": "192.168.50.8",
            "manufacturer": "Configured",
            "model": "Camera",
            "onvif": True,
            "onvifPort": 80,
            "rtsp": True,
            "openPorts": [554],
            "profiles": [],
            "previewAvailable": True,
            "configuredCameraId": "garten",
            "configuredName": "Garten",
            "_configuredPreviewPath": "garten-low",
            "_snapshotUri": None,
        }],
    }
    original_capture_frame = camera_app.capture_rtsp_frame
    configured_paths = []
    camera_app.capture_rtsp_frame = lambda path: configured_paths.append(path) or b"\xff\xd8configured-frame\xff\xd9"
    configured_preview_request = urllib.request.Request(
        base + f"/api/admin/discovery/scans/{configured_scan_id}/devices/{configured_device_id}/preview",
        headers={"Host": "127.0.0.1"},
    )
    with admin_client.open(configured_preview_request, timeout=10) as response:
        assert response.read().startswith(b"\xff\xd8")
    camera_app.capture_rtsp_frame = original_capture_frame
    assert configured_paths == ["garten-low"]

    internal = urllib.request.Request(base + "/internal/v1/detection/config", headers={"Authorization": f"Bearer {camera_app.DETECTION_ADAPTER_TOKEN}"})
    with urllib.request.urlopen(internal, timeout=5) as response:
        detection = json.load(response)
    assert detection["enabled"] is False and detection["cameras"] == []

    external_payload = {
        "name": "CZEview Test", "path": "czeview-low", "sourceLabel": "CZEview P2P · bei Bedarf",
        "codec": "h264", "manufacturer": "CZEview (Plattformmarke)",
        "model": "API-Gerätetyp 5", "detailQuality": "2304 × 1296 · H.264 (verifiziert)",
        "width": 2304, "height": 1296, "controlUrl": "http://czeview-bridge:8787", "ptzAxes": ["x"],
    }
    external_request = urllib.request.Request(
        base + "/internal/v1/external-cameras/czeview",
        data=json.dumps(external_payload).encode(),
        method="PUT",
        headers={"Authorization": f"Bearer {camera_app.INTERNAL_TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(external_request, timeout=5) as response:
        registered = json.load(response)
    assert registered["registered"] and registered["path"] == "czeview-low"
    external_camera = next(item for item in request("/api/cameras")["cameras"] if item["id"] == "czeview")
    assert external_camera["externalSource"] and external_camera["onDemand"] and external_camera["usesCredentials"]
    assert external_camera["features"]["ptz"] and external_camera["features"]["ptzAxes"] == ["x"]
    external_admin = next(item for item in request("/api/admin/cameras")["cameras"] if item["id"] == "czeview")
    assert external_admin["relayMode"] == "external-on-demand"
    assert request(
        "/api/admin/cameras/czeview/detection",
        "PUT",
        {"enabled": True, "schedules": [], "zones": []},
        csrf,
        expected=409,
    )["detail"] == "detection-camera-not-supported"
    external_capabilities = request("/api/admin/cameras/czeview/capabilities")
    assert external_capabilities["available"] and external_capabilities["profiles"][0]["token"] == "external"
    assert external_capabilities["ptz"]["axes"] == ["x"]
    external_ptz_calls = []
    original_external_control = camera_app.external_control_request
    camera_app.external_control_request = lambda _camera, action, direction=None: external_ptz_calls.append((action, direction))
    assert request(
        "/api/admin/cameras/czeview/ptz/move", "POST",
        {"x": -.3, "y": 0, "zoom": 0, "profileToken": "external"}, csrf,
    )["ok"]
    assert request(
        "/api/admin/cameras/czeview/ptz/stop", "POST",
        {"profileToken": "external"}, csrf,
    )["ok"]
    rejected_axis = request(
        "/api/admin/cameras/czeview/ptz/move", "POST",
        {"x": 0, "y": .3, "zoom": 0, "profileToken": "external"}, csrf, 409,
    )
    assert rejected_axis["detail"] == "ptz-axis-not-supported"
    assert external_ptz_calls == [("start", "left"), ("stop", None)]
    camera_app.external_control_request = original_external_control
    lease = request("/api/cameras/czeview/lease", "POST", csrf=csrf)
    renewed = request(f"/api/cameras/czeview/lease?leaseId={lease['leaseId']}", "PUT", csrf=csrf)
    assert renewed["expiresIn"] == 90
    lease_request = urllib.request.Request(
        base + "/internal/v1/external-cameras/czeview/lease",
        headers={"Authorization": f"Bearer {camera_app.INTERNAL_TOKEN}"},
    )
    with urllib.request.urlopen(lease_request, timeout=5) as response:
        lease_state = json.load(response)
    assert lease_state["active"] and lease_state["leaseCount"] == 1
    request(f"/api/cameras/czeview/lease?leaseId={lease['leaseId']}", "DELETE", csrf=csrf, expected=204)
    with urllib.request.urlopen(lease_request, timeout=5) as response:
        assert json.load(response)["active"] is False
    original_media_paths = camera_app.media_paths
    original_subprocess_run = camera_app.subprocess.run
    camera_app.media_paths = lambda: ({"czeview-low": {"ready": True}}, True)
    camera_app.subprocess.run = lambda *_args, **_kwargs: type(
        "PreviewResult", (), {"returncode": 0, "stdout": b"\xff\xd8test-jpeg"}
    )()
    try:
        preview = camera_app.preview("czeview", None)
        assert preview.body.startswith(b"\xff\xd8")
        assert "czeview" not in camera_app.LEASES
    finally:
        camera_app.subprocess.run = original_subprocess_run
    camera_app.media_paths = lambda: ({}, True)
    health_payload = json.loads(camera_app.healthz().body)
    camera_app.media_paths = original_media_paths
    assert health_payload["sourcesExpected"] == 6

    cloud_password = "Cloud-Secret-42!"
    cloud_account = request(
        "/api/admin/cloud/accounts/czeview",
        "POST",
        {
            "label": "Testhaus",
            "username": "cloud-user",
            "email": "cloud@example.invalid",
            "password": cloud_password,
            "countryCode": "DE",
            "phoneCode": "49",
            "sourceApp": "141",
        },
        csrf,
    )
    assert cloud_account["provider"] == "czeview" and "password" not in cloud_account
    assert request("/api/admin/cloud/accounts", expected=403, opener=admin_client)["detail"] == "insufficient-role"
    assert cloud_password.encode() not in open(os.environ["DATABASE_PATH"], "rb").read()
    with camera_app.connect() as conn:
        inventory_auth_revision = conn.execute(
            "SELECT auth_revision FROM cloud_accounts WHERE id=?",
            (cloud_account["id"],),
        ).fetchone()["auth_revision"]
    inventory_request = urllib.request.Request(
        base + "/internal/v1/providers/czeview/inventory",
        data=json.dumps(
            {
                "accountId": cloud_account["id"],
                "status": "active",
                "devices": [
                    {
                        "externalId": "serial-cloud-test",
                        "name": "Cloud Kamera",
                        "model": "API-Gerätetyp 5",
                        "manufacturer": "CZEview (Plattformmarke)",
                        "capabilities": {"provider": "czeview"},
                        "streamSupport": "candidate",
                    }
                ],
            }
        ).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {camera_app.CZEVIEW_ADAPTER_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(inventory_request, timeout=5) as response:
        inventory = json.load(response)
    cloud_device_id = inventory["devices"][0]["deviceId"]
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT auth_revision FROM cloud_accounts WHERE id=?",
            (cloud_account["id"],),
        ).fetchone()["auth_revision"] == inventory_auth_revision
    cloud_scan_id, cloud_scan_device_id = "cloud-scan", "cloud-result"
    camera_app.SCANS[cloud_scan_id] = {
        "id": cloud_scan_id,
        "state": "complete",
        "createdAt": camera_app.now_iso(),
        "createdEpoch": time.time(),
        "results": [
            {
                "id": cloud_scan_device_id,
                "origin": "cloud",
                "provider": "czeview",
                "accountId": cloud_account["id"],
                "accountLabel": "Testhaus",
                "cloudDeviceId": cloud_device_id,
                "name": "Cloud Kamera",
                "manufacturer": "CZEview (Plattformmarke)",
                "model": "API-Gerätetyp 5",
                "streamSupport": "candidate",
                "available": False,
                "previewAvailable": False,
                "previewVerified": False,
                "configuredCameraId": None,
                "configuredName": None,
            }
        ],
    }
    original_media_paths = camera_app.media_paths
    original_capture_frame = camera_app.capture_rtsp_frame
    observed_cloud_probe = {}

    def cloud_probe_media_paths():
        probe = camera_app.CLOUD_PROBE_LEASES.get(cloud_device_id)
        assert probe and probe["lease"]["active"] is True
        observed_cloud_probe["path"] = probe["lease"]["path"]
        return ({probe["lease"]["path"]: {"ready": True}}, True)

    def cloud_probe_frame(path, timeout=0):
        assert path == observed_cloud_probe["path"] and timeout == 15
        return b"\xff\xd8cloud-frame\xff\xd9"

    camera_app.media_paths = cloud_probe_media_paths
    camera_app.capture_rtsp_frame = cloud_probe_frame
    try:
        probed_cloud = request(
            f"/api/admin/discovery/scans/{cloud_scan_id}/devices/{cloud_scan_device_id}/probe",
            "POST",
            {},
            csrf,
        )
    finally:
        camera_app.media_paths = original_media_paths
        camera_app.capture_rtsp_frame = original_capture_frame
    assert probed_cloud["streamSupport"] == "verified"
    assert probed_cloud["previewVerified"] is True
    assert cloud_device_id not in camera_app.CLOUD_PROBE_LEASES
    assert camera_app.DISCOVERY_PREVIEW_CACHE[
        (cloud_scan_id, cloud_scan_device_id)
    ][1].startswith(b"\xff\xd8")
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT stream_support FROM cloud_devices WHERE id=?",
            (cloud_device_id,),
        ).fetchone()["stream_support"] == "verified"
    imported_cloud = request(
        f"/api/admin/discovery/scans/{cloud_scan_id}/devices/{cloud_scan_device_id}/import",
        "POST",
        {"name": "Cloud Kamera"},
        csrf,
    )
    assert imported_cloud["externalSource"] and imported_cloud["onDemand"]
    replacement_secret = "Cloud-Replacement-Secret-43!"
    with camera_app.connect() as conn:
        previous_auth_revision = conn.execute(
            "SELECT auth_revision FROM cloud_accounts WHERE id=?",
            (cloud_account["id"],),
        ).fetchone()["auth_revision"]
    replaced_cloud_account = request(
        f"/api/admin/cloud/accounts/{cloud_account['id']}/czeview",
        "PUT",
        {
            "label": "Testhaus aktualisiert",
            "username": "cloud-user-new",
            "email": "cloud-new@example.invalid",
            "password": replacement_secret,
            "countryCode": "DE",
            "phoneCode": "49",
            "sourceApp": "141",
        },
        csrf,
    )
    assert replaced_cloud_account["status"] == "pending"
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT auth_revision FROM cloud_accounts WHERE id=?",
            (cloud_account["id"],),
        ).fetchone()["auth_revision"] == previous_auth_revision + 1
        assert conn.execute(
            "SELECT 1 FROM cloud_devices WHERE id=? AND account_id=?",
            (cloud_device_id, cloud_account["id"]),
        ).fetchone()
        assert conn.execute(
            "SELECT 1 FROM cameras WHERE cloud_device_id=?",
            (cloud_device_id,),
        ).fetchone()
    assert replacement_secret.encode() not in open(os.environ["DATABASE_PATH"], "rb").read()
    assert request(
        f"/api/admin/cloud/accounts/{cloud_account['id']}",
        "DELETE",
        csrf=csrf,
        expected=409,
    )["detail"] == "cloud-account-has-linked-cameras"
    assert request(
        "/api/admin/cloud/providers/netatmo",
        "PUT",
        {
            "clientId": "client",
            "clientSecret": "secret",
            "redirectUri": "http://example.com/api/cloud/oauth/netatmo/callback",
        },
        csrf,
        expected=422,
    )["detail"] == "netatmo-http-redirect-must-be-private"
    assert camera_app.safe_netatmo_stream_base("https://prodvpn-eu-2.netatmo.net/example")
    assert camera_app.safe_netatmo_stream_base("https://attacker.invalid/example") is None
    assert camera_app.safe_netatmo_stream_base("http://192.168.50.42/example")
    request(
        "/api/admin/cloud/providers/netatmo",
        "PUT",
        {
            "clientId": "client",
            "clientSecret": "secret",
            "redirectUri": "http://127.0.0.1/api/cloud/oauth/netatmo/callback",
        },
        csrf,
    )
    netatmo_account_id = "netatmo-test-account"
    with camera_app.connect() as conn:
        stamp = camera_app.now_iso()
        conn.execute(
            """INSERT INTO cloud_accounts(
               id,provider,label,enabled,auth_payload_ct,scopes_json,status,created_at,updated_at)
               VALUES(?,'netatmo','Netatmo Test',1,?,'[]','active',?,?)""",
            (
                netatmo_account_id,
                camera_app.encrypt_json(
                    {"accessToken": "test-access", "refreshToken": "test-refresh", "expiresAt": int(time.time()) + 3600}
                ),
                stamp,
                stamp,
            ),
        )
    reconnect = request(
        "/api/admin/cloud/accounts/netatmo/authorize",
        "POST",
        {"label": "Netatmo Test neu", "accountId": netatmo_account_id},
        csrf,
    )
    reconnect_state = parse_qs(urlparse(reconnect["authorizationUrl"]).query)["state"][0]
    original_form_request_json = camera_app.form_request_json
    camera_app.form_request_json = lambda *_args, **_kwargs: {
        "access_token": "replacement-access",
        "refresh_token": "replacement-refresh",
        "expires_in": 10800,
        "scope": camera_app.NETATMO_SCOPES,
    }
    try:
        callback = camera_app.netatmo_oauth_callback(state=reconnect_state, code="test-code")
        assert callback.status_code == 303
    finally:
        camera_app.form_request_json = original_form_request_json
    with camera_app.connect() as conn:
        reconnected = conn.execute(
            "SELECT * FROM cloud_accounts WHERE id=?",
            (netatmo_account_id,),
        ).fetchone()
        assert reconnected["label"] == "Netatmo Test neu" and reconnected["status"] == "active"
        assert camera_app.decrypt_json(reconnected["auth_payload_ct"])["refreshToken"] == "replacement-refresh"
    original_netatmo_api_json = camera_app.netatmo_api_json

    def fake_netatmo_api(_account_id, path, _params=None):
        if path == "homesdata":
            return {
                "homes": [
                    {
                        "id": "home-1",
                        "name": "Haus",
                        "modules": [
                            {"id": "noc-1", "type": "NOC", "name": "Außen"},
                            {"id": "npc-1", "type": "NPC", "name": "Advance"},
                        ],
                    }
                ]
            }
        return {
            "home": {
                "modules": [
                    {
                        "id": "noc-1",
                        "type": "NOC",
                        "vpn_url": "https://prodvpn-eu-2.netatmo.net/example/noc-1",
                    }
                ]
            }
        }

    camera_app.netatmo_api_json = fake_netatmo_api
    try:
        camera_app.refresh_netatmo_inventory(netatmo_account_id)
        with camera_app.connect() as conn:
            netatmo_devices = conn.execute(
                "SELECT id,model,stream_support,last_error_code FROM cloud_devices WHERE account_id=? ORDER BY model",
                (netatmo_account_id,),
            ).fetchall()
        assert {row["model"]: row["stream_support"] for row in netatmo_devices} == {
            "NOC": "candidate",
            "NPC": "unsupported",
        }
        noc_device = next(row for row in netatmo_devices if row["model"] == "NOC")
        npc_device = next(row for row in netatmo_devices if row["model"] == "NPC")
        assert camera_app.netatmo_stream_candidates(noc_device["id"])[0].endswith("/live/index.m3u8")
        assert camera_app.netatmo_stream_candidates(npc_device["id"]) == []
    finally:
        camera_app.netatmo_api_json = original_netatmo_api_json

    with camera_app.connect() as conn:
        assert conn.execute("SELECT 1 FROM schema_migrations WHERE version=8").fetchone()
        for table in (
            "system_events", "webhook_targets", "webhook_deliveries",
            "detection_settings", "camera_detection_settings",
            "zone_detection_settings", "camera_detection_schedules",
            "zone_detection_schedules", "motion_event_assets",
        ):
            assert conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()

    viewer_client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    request(
        "/api/auth/login",
        "POST",
        {"username": "viewer1", "password": replacement_viewer_password},
        opener=viewer_client,
    )
    assert request("/api/events", opener=viewer_client)["summary"]["open"] == 0
    assert request("/api/owner/webhooks", expected=403, opener=viewer_client)["detail"] == "insufficient-role"
    webhook = request(
        "/api/owner/webhooks",
        "POST",
        {
            "label": "Lokaler Test",
            "url": "http://127.0.0.1:18099/events",
            "enabled": True,
            "eventTypes": ["camera.offline", "zone.motion"],
        },
        csrf,
        expected=201,
    )
    assert webhook["secret"] and webhook["url"].startswith("http://127.0.0.1")
    with camera_app.connect() as conn:
        stored_target = conn.execute(
            "SELECT * FROM webhook_targets WHERE id=?", (webhook["id"],)
        ).fetchone()
        assert camera_app.decrypt_text(stored_target["secret_ct"]) == webhook["secret"]
        assert webhook["secret"].encode() not in open(os.environ["DATABASE_PATH"], "rb").read()

    incident_now = time.time()
    assert camera_app.observe_incident(
        "test-camera:offline",
        True,
        event_type="camera.offline",
        severity="warning",
        title="Testkamera nicht erreichbar",
        description="Testausfall",
        recommendation="Test prüfen",
        camera_id="garten",
        observed_at=incident_now,
    ) == "pending"
    assert camera_app.observe_incident(
        "test-camera:offline",
        True,
        event_type="camera.offline",
        severity="warning",
        title="Testkamera nicht erreichbar",
        description="Testausfall",
        recommendation="Test prüfen",
        camera_id="garten",
        observed_at=incident_now + camera_app.INCIDENT_THRESHOLD_SECONDS - 1,
    ) == "pending"
    assert camera_app.observe_incident(
        "test-camera:offline",
        True,
        event_type="camera.offline",
        severity="warning",
        title="Testkamera nicht erreichbar",
        description="Testausfall",
        recommendation="Test prüfen",
        camera_id="garten",
        observed_at=incident_now + camera_app.INCIDENT_THRESHOLD_SECONDS,
    ) == "open"
    with camera_app.connect() as conn:
        event_row = conn.execute(
            "SELECT * FROM system_events WHERE dedupe_key='test-camera:offline'"
        ).fetchone()
        assert event_row["status"] == "open"
        assert conn.execute(
            "SELECT COUNT(*) FROM system_events WHERE dedupe_key='test-camera:offline'"
        ).fetchone()[0] == 1
        delivery = conn.execute(
            "SELECT * FROM webhook_deliveries WHERE event_id=? AND event_status='open'",
            (event_row["id"],),
        ).fetchone()
        assert delivery
    event_api = request("/api/events?status=open")
    api_incident = next(
        item for item in event_api["events"] if item["id"] == event_row["id"]
    )
    assert api_incident["durationSeconds"] == camera_app.INCIDENT_THRESHOLD_SECONDS
    assert api_incident["cameraName"] == "Garten"

    captured_webhooks = []

    class TestWebhookResponse:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class TestWebhookOpener:
        def open(self, outgoing, timeout=0):
            captured_webhooks.append((outgoing, timeout))
            return TestWebhookResponse()

    original_webhook_opener = camera_app.NO_REDIRECT_OPENER
    camera_app.NO_REDIRECT_OPENER = TestWebhookOpener()
    try:
        assert camera_app.dispatch_due_webhooks(now_epoch=int(time.time()) + 1) == 1
        outgoing, timeout = captured_webhooks[-1]
        payload = outgoing.data
        timestamp = outgoing.get_header("X-camerahub-timestamp")
        signature = outgoing.get_header("X-camerahub-signature")
        expected_signature = hmac.new(
            webhook["secret"].encode(),
            timestamp.encode() + b"." + payload,
            hashlib.sha256,
        ).hexdigest()
        assert timeout == 5 and signature == f"sha256={expected_signature}"
        assert b"password" not in payload.lower() and b"token" not in payload.lower()
        assert camera_app.observe_incident(
            "test-camera:offline",
            False,
            event_type="camera.offline",
            severity="warning",
            title="Testkamera wieder erreichbar",
            description="Test behoben",
            recommendation="Keine Aktion",
            camera_id="garten",
            observed_at=incident_now + camera_app.INCIDENT_THRESHOLD_SECONDS + 1,
        ) == "resolved"
        assert camera_app.dispatch_due_webhooks(now_epoch=int(time.time()) + 2) == 1
        assert json.loads(captured_webhooks[-1][0].data)["status"] == "resolved"
    finally:
        camera_app.NO_REDIRECT_OPENER = original_webhook_opener

    assert request(
        "/api/owner/detection", "PUT", {"mode": "observe"}, csrf
    )["mode"] == "observe"
    observe_motion_id = uuid.uuid4().hex
    observe_motion = camera_app.DetectionEventInput(
        workerEventId=observe_motion_id,
        cameraId="garten",
        zoneId=zone_id,
        state="started",
        motionPercent=2,
        strength=60,
    )
    observe_started = camera_app.detection_events(observe_motion, None)
    observe_motion.state = "ended"
    camera_app.detection_events(observe_motion, None)
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM webhook_deliveries WHERE event_id=?",
            (observe_started["eventId"],),
        ).fetchone()[0] == 0

    assert request(
        "/api/owner/detection", "PUT", {"mode": "armed"}, csrf
    )["mode"] == "armed"
    armed_motion_id = uuid.uuid4().hex
    armed_motion = camera_app.DetectionEventInput(
        workerEventId=armed_motion_id,
        cameraId="garten",
        zoneId=zone_id,
        state="started",
        motionPercent=2.4,
        strength=66,
    )
    armed_started = camera_app.detection_events(armed_motion, None)
    with camera_app.connect() as conn:
        motion_delivery = conn.execute(
            """SELECT d.*,e.details_json FROM webhook_deliveries d
               JOIN system_events e ON e.id=d.event_id
               WHERE e.dedupe_key=? AND d.event_status='open'""",
            (f"zone.motion:{armed_motion_id}",),
        ).fetchone()
        assert motion_delivery
    camera_app.NO_REDIRECT_OPENER = TestWebhookOpener()
    try:
        assert camera_app.dispatch_due_webhooks(
            now_epoch=int(time.time()) + 3, delivery_id=motion_delivery["id"]
        ) == 1
        motion_payload = json.loads(captured_webhooks[-1][0].data)
        assert motion_payload["type"] == "zone.motion"
        assert motion_payload["motion"]["zoneId"] == zone_id
        assert "url" not in json.dumps(motion_payload).lower()
        armed_motion.state = "ended"
        camera_app.detection_events(armed_motion, None)
        with camera_app.connect() as conn:
            resolution = conn.execute(
                """SELECT id FROM webhook_deliveries
                   WHERE event_id=? AND event_status='resolved'""",
                (armed_started["eventId"],),
            ).fetchone()
        assert resolution
        assert camera_app.dispatch_due_webhooks(
            now_epoch=int(time.time()) + 4, delivery_id=resolution["id"]
        ) == 1
        assert json.loads(captured_webhooks[-1][0].data)["status"] == "resolved"
    finally:
        camera_app.NO_REDIRECT_OPENER = original_webhook_opener
    request("/api/owner/detection", "PUT", {"mode": "off"}, csrf)

    retry_delivery_id, retry_now = str(uuid.uuid4()), int(time.time())
    with camera_app.connect() as conn:
        conn.execute(
            """INSERT INTO webhook_deliveries(
               id,target_id,event_id,event_status,attempt,status,next_attempt_at,payload_json,
               created_at,updated_at) VALUES(?,?,?,'test',0,'pending',?,?,?,?)""",
            (
                retry_delivery_id,
                webhook["id"],
                str(uuid.uuid4()),
                retry_now,
                '{"type":"system.webhook-test"}',
                camera_app.now_iso(),
                camera_app.now_iso(),
            ),
        )

    class FailingWebhookOpener:
        def open(self, *_args, **_kwargs):
            raise OSError("test endpoint unavailable")

    camera_app.NO_REDIRECT_OPENER = FailingWebhookOpener()
    try:
        assert camera_app.dispatch_due_webhooks(
            now_epoch=retry_now, delivery_id=retry_delivery_id
        ) == 0
    finally:
        camera_app.NO_REDIRECT_OPENER = original_webhook_opener
    with camera_app.connect() as conn:
        retry_delivery = conn.execute(
            "SELECT * FROM webhook_deliveries WHERE id=?", (retry_delivery_id,)
        ).fetchone()
        assert retry_delivery["status"] == "pending"
        assert retry_delivery["attempt"] == 1
        assert retry_delivery["next_attempt_at"] == retry_now + 60
        assert retry_delivery["claim_token"] is None

    concurrent_delivery_id = str(uuid.uuid4())
    with camera_app.connect() as conn:
        conn.execute(
            """INSERT INTO webhook_deliveries(
               id,target_id,event_id,event_status,attempt,status,next_attempt_at,payload_json,
               created_at,updated_at) VALUES(?,?,?,'test',0,'pending',?,?,?,?)""",
            (
                concurrent_delivery_id,
                webhook["id"],
                str(uuid.uuid4()),
                retry_now,
                '{"type":"system.webhook-concurrency-test"}',
                camera_app.now_iso(),
                camera_app.now_iso(),
            ),
        )
    concurrent_calls = []
    concurrent_lock = threading.Lock()

    class SlowWebhookOpener:
        def open(self, *_args, **_kwargs):
            with concurrent_lock:
                concurrent_calls.append(time.time())
            time.sleep(0.1)
            return TestWebhookResponse()

    camera_app.NO_REDIRECT_OPENER = SlowWebhookOpener()
    try:
        dispatch_threads = [
            threading.Thread(
                target=camera_app.dispatch_due_webhooks,
                kwargs={"now_epoch": retry_now, "delivery_id": concurrent_delivery_id},
            )
            for _ in range(2)
        ]
        for dispatch_thread in dispatch_threads:
            dispatch_thread.start()
        for dispatch_thread in dispatch_threads:
            dispatch_thread.join(timeout=5)
        assert len(concurrent_calls) == 1
    finally:
        camera_app.NO_REDIRECT_OPENER = original_webhook_opener

    on_demand_row = None
    with camera_app.connect() as conn:
        on_demand_row = conn.execute(
            "SELECT * FROM cameras WHERE id=?", (imported_cloud["id"],)
        ).fetchone()
    paths_before = camera_app.media_paths
    camera_app.media_paths = lambda: ({}, True)
    try:
        monitor_result = camera_app.monitor_once(observed_at=time.time())
        assert on_demand_row["id"] not in monitor_result
        assert camera_app.camera_status(on_demand_row, {}, True)["state"] == "sleeping"
    finally:
        camera_app.media_paths = paths_before

    media_incident_now = time.time()
    for observed in (
        media_incident_now,
        media_incident_now + camera_app.INCIDENT_THRESHOLD_SECONDS,
    ):
        camera_app.observe_incident(
            "camera:garten:offline",
            True,
            event_type="camera.offline",
            severity="warning",
            title="Garten nicht erreichbar",
            description="Testausfall",
            recommendation="Test prüfen",
            camera_id="garten",
            observed_at=observed,
        )
    camera_app.media_paths = lambda: ({}, False)
    try:
        camera_app.monitor_once(observed_at=media_incident_now + 301)
    finally:
        camera_app.media_paths = paths_before
    with camera_app.connect() as conn:
        assert conn.execute(
            """SELECT status FROM system_events
               WHERE dedupe_key='camera:garten:offline' ORDER BY created_at DESC"""
        ).fetchone()["status"] == "open"

    cloud_incident_now = time.time()
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE cloud_accounts SET status='reauth-required' WHERE id=?",
            (cloud_account["id"],),
        )
        cloud_camera_row = conn.execute(
            "SELECT * FROM cameras WHERE id=?", (imported_cloud["id"],)
        ).fetchone()
    assert camera_app.camera_status(cloud_camera_row, {}, True)["state"] == "cloud-auth-required"
    camera_app.monitor_once(observed_at=cloud_incident_now)
    camera_app.monitor_once(
        observed_at=cloud_incident_now + camera_app.INCIDENT_THRESHOLD_SECONDS
    )
    with camera_app.connect() as conn:
        conn.execute(
            "UPDATE cloud_accounts SET status='pending' WHERE id=?",
            (cloud_account["id"],),
        )
    camera_app.monitor_once(observed_at=cloud_incident_now + 301)
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT status FROM system_events WHERE dedupe_key=?",
            (f"cloud-account:{cloud_account['id']}:auth",),
        ).fetchone()["status"] == "open"
        conn.execute(
            "UPDATE cloud_accounts SET status='active' WHERE id=?",
            (cloud_account["id"],),
        )
    camera_app.monitor_once(observed_at=cloud_incident_now + 302)
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT status FROM system_events WHERE dedupe_key=?",
            (f"cloud-account:{cloud_account['id']}:auth",),
        ).fetchone()["status"] == "resolved"

    backup_profile = request(
        "/api/display-profiles",
        "POST",
        {
            "name": "Backup-Zeitplan",
            "cameraIds": ["eingang"],
            "cameraModes": {"eingang": "low"},
            "schedules": [
                {"weekday": 4, "startMinute": 1320, "endMinute": 120}
            ],
        },
        csrf,
        expected=201,
    )
    request(
        f"/api/owner/display-devices/{display_device['id']}/pairing-code",
        "POST",
        csrf=csrf,
    )
    backup_passphrase = "Portable-Backup-Test-42!"
    backup_archive = camera_app.create_backup_archive(backup_passphrase)
    assert backup_passphrase.encode() not in backup_archive
    assert len(backup_archive) <= camera_app.BACKUP_ENVELOPE_MAX_BYTES
    assert json.loads(backup_archive)["kdf"]["n"] == camera_app.BACKUP_SCRYPT_N
    manifest, backup_database, source_key = camera_app.decode_backup_archive(
        backup_archive, backup_passphrase
    )
    assert manifest["schemaVersion"] == 10 and manifest["appVersion"] == "1.5.0-dev"
    assert len(backup_database) <= camera_app.BACKUP_DATABASE_MAX_BYTES
    assert camera_app.BACKUP_EXPANDED_MAX_BYTES > len(base64.b64encode(backup_database))
    for invalid_archive, invalid_passphrase, expected_code in (
        (backup_archive, "Falsche-Passphrase-42!", "backup-passphrase-or-data-invalid"),
        (backup_archive[:-20] + b"corrupted-archive-data", backup_passphrase, "backup-passphrase-or-data-invalid"),
        (
            json.dumps({**json.loads(backup_archive), "version": 999}).encode(),
            backup_passphrase,
            "backup-version-unsupported",
        ),
    ):
        try:
            camera_app.decode_backup_archive(invalid_archive, invalid_passphrase)
            raise AssertionError("invalid backup unexpectedly accepted")
        except camera_app.HTTPException as error:
            assert error.detail == expected_code

    original_application_key = camera_app.AES_KEY
    camera_app.AES_KEY = hashlib.sha256(b"portable-target-key").digest()
    try:
        _, portable_candidate = camera_app.validate_backup_database(
            backup_database, source_key
        )
        with sqlite3.connect(portable_candidate) as portable:
            portable.row_factory = sqlite3.Row
            assert portable.execute(
                "SELECT COUNT(*) FROM display_devices WHERE id=?",
                (display_device["id"],),
            ).fetchone()[0] == 1
            assert portable.execute(
                "SELECT COUNT(*) FROM display_device_profiles WHERE device_id=?",
                (display_device["id"],),
            ).fetchone()[0] == 1
            assert portable.execute(
                """SELECT stream_mode FROM display_profile_cameras
                   WHERE profile_id=? AND camera_id='eingang'""",
                (backup_profile["id"],),
            ).fetchone()["stream_mode"] == "low"
            assert portable.execute(
                "SELECT COUNT(*) FROM display_profile_schedules WHERE profile_id=?",
                (backup_profile["id"],),
            ).fetchone()[0] == 2
            assert portable.execute(
                "SELECT COUNT(*) FROM motion_event_assets"
            ).fetchone()[0] == 0
            assert portable.execute(
                "SELECT mode FROM detection_settings WHERE id=1"
            ).fetchone()["mode"] == "off"
            assert portable.execute(
                """SELECT enabled FROM camera_detection_settings
                   WHERE camera_id='garten'"""
            ).fetchone()["enabled"] == 1
            assert portable.execute(
                """SELECT COUNT(*) FROM zone_detection_settings
                   WHERE enabled=1"""
            ).fetchone()[0] >= 1
            assert portable.execute(
                """SELECT COUNT(*) FROM system_events
                   WHERE event_type='zone.motion'"""
            ).fetchone()[0] >= 1
            assert portable.execute(
                "SELECT COUNT(*) FROM display_device_sessions"
            ).fetchone()[0] == 0
            assert portable.execute(
                "SELECT COUNT(*) FROM display_pairing_codes"
            ).fetchone()[0] == 0
            assert portable.execute(
                "SELECT paired_at FROM display_devices WHERE id=?",
                (display_device["id"],),
            ).fetchone()["paired_at"] is None
            portable_account = portable.execute(
                "SELECT auth_payload_ct FROM cloud_accounts WHERE id=?",
                (cloud_account["id"],),
            ).fetchone()
            assert json.loads(
                camera_app.crypt_text_with_key(
                    portable_account["auth_payload_ct"],
                    camera_app.AES_KEY,
                    decrypt=True,
                )
            )["password"] == replacement_secret
        portable_candidate.unlink(missing_ok=True)
    finally:
        camera_app.AES_KEY = original_application_key

    with camera_app.connect() as conn:
        original_camera_name = conn.execute(
            "SELECT name FROM cameras WHERE id='garten'"
        ).fetchone()["name"]
        conn.execute("UPDATE cameras SET name='Nicht im Backup' WHERE id='garten'")
    _, interrupted_candidate = camera_app.validate_backup_database(backup_database, source_key)
    original_audit = camera_app.audit

    def failing_restore_audit(conn, actor_id, action, target_type, target_id=None):
        if action == "system.backup.restored":
            raise OSError("simulated restore interruption")
        return original_audit(conn, actor_id, action, target_type, target_id)

    camera_app.audit = failing_restore_audit
    try:
        try:
            camera_app.restore_backup_database(
                interrupted_candidate, session["user"]["id"]
            )
            raise AssertionError("interrupted restore unexpectedly succeeded")
        except OSError:
            pass
    finally:
        camera_app.audit = original_audit
        interrupted_candidate.unlink(missing_ok=True)
    with camera_app.connect() as conn:
        assert conn.execute(
            "SELECT name FROM cameras WHERE id='garten'"
        ).fetchone()["name"] == "Nicht im Backup"
    _, restore_candidate = camera_app.validate_backup_database(backup_database, source_key)
    restore_point = camera_app.restore_backup_database(restore_candidate, session["user"]["id"])
    assert restore_point.startswith("before-restore-") and not restore_candidate.exists()
    with camera_app.connect() as conn:
        assert conn.execute("SELECT name FROM cameras WHERE id='garten'").fetchone()["name"] == original_camera_name
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM display_device_sessions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM display_pairing_codes").fetchone()[0] == 0
    assert request("/api/auth/state")["authenticated"] is False
    session = request("/api/auth/login", "POST", {"username": "owner", "password": password})
    csrf = session["csrfToken"]

    lifecycle_client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    lifecycle_code = request(
        f"/api/owner/display-devices/{display_device['id']}/pairing-code",
        "POST",
        csrf=csrf,
    )["code"]
    request(
        "/api/display/pair",
        "POST",
        {"code": lifecycle_code},
        opener=lifecycle_client,
    )
    lifecycle_lease = request(
        "/api/display/cameras/garten/lease",
        "POST",
        opener=lifecycle_client,
    )["leaseId"]
    assert lifecycle_lease in camera_app.LEASES.get("garten", {})
    request(
        f"/api/owner/display-devices/{display_device['id']}",
        "PUT",
        {"name": "Leitstellen-TV", "enabled": False, "profileIds": [owner_profile["id"]]},
        csrf,
    )
    assert request(
        "/api/display/state", expected=401, opener=lifecycle_client
    )["detail"] == "display-session-expired"
    assert lifecycle_lease not in camera_app.LEASES.get("garten", {})
    request(
        f"/api/owner/display-devices/{display_device['id']}",
        "PUT",
        {"name": "Leitstellen-TV", "enabled": True, "profileIds": [owner_profile["id"]]},
        csrf,
    )
    lifecycle_code = request(
        f"/api/owner/display-devices/{display_device['id']}/pairing-code",
        "POST",
        csrf=csrf,
    )["code"]
    request(
        "/api/display/pair",
        "POST",
        {"code": lifecycle_code},
        opener=lifecycle_client,
    )
    lifecycle_lease = request(
        "/api/display/cameras/garten/lease",
        "POST",
        opener=lifecycle_client,
    )["leaseId"]
    request(
        f"/api/owner/display-devices/{display_device['id']}/revoke",
        "POST",
        csrf=csrf,
    )
    assert request(
        "/api/display/state", expected=401, opener=lifecycle_client
    )["detail"] == "display-session-expired"
    assert lifecycle_lease not in camera_app.LEASES.get("garten", {})

    camera_app.DISPLAY_PAIR_ATTEMPTS.clear()
    for attempt in range(12):
        assert request(
            "/api/display/pair",
            "POST",
            {"code": f"{70_000_000 + attempt:08d}"},
            expected=400,
            opener=second_display_client,
        )["detail"] == "display-pair-code-invalid"
    assert request(
        "/api/display/pair",
        "POST",
        {"code": "99999999"},
        expected=429,
        opener=second_display_client,
    )["detail"] == "display-pair-rate-limited"

    print("integration-ok: password-only-setup rbac-owner-admin-viewer session-revocation auth csrf encryption migration-v10 personal-display-profiles profile-order profile-isolation camera-disable-retention camera-delete-cascade ordering zones detection-default-off detection-dedup encrypted-motion-snapshot on-demand-detection-blocked vendor-snapshot-crud connection-revisions encrypted-shared-auth dynamic-relay-active-credentials activation-rollback capabilities ptz wsse-password-digest network-boundary onvif-profile-mock authenticated-discovery-preview configured-discovery-preview internal-adapter external-on-demand-camera external-ptz transient-snapshot renewable-leases encrypted-cloud-accounts cloud-credential-replacement provider-isolation cloud-frame-gated-import netatmo-private-callback netatmo-account-reconnect netatmo-inventory-models netatmo-stream-allowlist display-pair-expiry display-pair-one-use display-pair-rate-limit display-device-disable display-device-revoke display-media-isolation weekly-schedules-midnight-dst-priority operations-schema event-threshold event-dedup event-recovery passive-on-demand-monitor hmac-webhooks backup-encryption backup-corruption backup-restore restore-session-revocation")
finally:
    server.should_exit = True
    thread.join(timeout=5)
    shutil.rmtree(TEMP, ignore_errors=True)
