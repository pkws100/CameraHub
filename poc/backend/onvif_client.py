from __future__ import annotations

import base64
import hashlib
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import (
    HTTPBasicAuthHandler,
    HTTPDigestAuthHandler,
    HTTPRedirectHandler,
    HTTPPasswordMgrWithDefaultRealm,
    Request,
    build_opener,
)


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
PTZ_NS = "http://www.onvif.org/ver20/ptz/wsdl"
IMAGING_NS = "http://www.onvif.org/ver20/imaging/wsdl"
EVENTS_NS = "http://www.onvif.org/ver10/events/wsdl"
DEVICEIO_NS = "http://www.onvif.org/ver10/deviceIO/wsdl"
ANALYTICS_NS = "http://www.onvif.org/ver20/analytics/wsdl"


class OnvifError(RuntimeError):
    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


class NoRedirectHandler(HTTPRedirectHandler):
    """ONVIF endpoints must never escape the validated camera address."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def first_text(root: ET.Element, name: str, default: str = "") -> str:
    for node in root.iter():
        if local_name(node.tag) == name and node.text:
            return node.text.strip()
    return default


def all_text(root: ET.Element, name: str) -> list[str]:
    return [(node.text or "").strip() for node in root.iter() if local_name(node.tag) == name and (node.text or "").strip()]


def parse_xml(payload: bytes) -> ET.Element:
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise OnvifError("onvif-invalid-xml") from exc


def xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class OnvifClient:
    """Small read-oriented ONVIF client with standard HTTP and WSSE authentication."""

    def __init__(
        self,
        device_url: str,
        username: str = "",
        password: str = "",
        timeout: float = 4.0,
        allowed_url=None,
    ):
        self.device_url = device_url
        self.username = username
        self.password = password
        self.timeout = timeout
        self.allowed_url = allowed_url or (lambda _value: True)
        manager = HTTPPasswordMgrWithDefaultRealm()
        if username:
            manager.add_password(None, device_url, username, password)
        self.opener = build_opener(
            NoRedirectHandler(),
            HTTPDigestAuthHandler(manager),
            HTTPBasicAuthHandler(manager),
        )
        parsed = urlparse(device_url)
        base = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
        self.services: dict[str, str] = {
            "device": device_url,
            "media": base + "/onvif/Media",
            "ptz": base + "/onvif/PTZ",
            "imaging": base + "/onvif/Imaging",
            "events": base + "/onvif/Events",
            "deviceio": base + "/onvif/DeviceIO",
        }
        self.advertised_services: set[str] = set()

    def wsse_header(self) -> str:
        if not self.username:
            return ""
        nonce = os.urandom(20)
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + self.password.encode()).digest()).decode()
        encoded_nonce = base64.b64encode(nonce).decode()
        return (
            '<wsse:Security s:mustUnderstand="1" '
            'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
            'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
            "<wsse:UsernameToken>"
            f"<wsse:Username>{xml_escape(self.username)}</wsse:Username>"
            '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
            f"{digest}</wsse:Password>"
            '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
            f"{encoded_nonce}</wsse:Nonce><wsu:Created>{created}</wsu:Created>"
            "</wsse:UsernameToken></wsse:Security>"
        )

    def envelope(self, body: str) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<s:Envelope xmlns:s="{SOAP_NS}"><s:Header>{self.wsse_header()}</s:Header><s:Body>{body}</s:Body></s:Envelope>'
        ).encode()

    def call(self, url: str, body: str) -> ET.Element:
        if not self.allowed_url(url):
            raise OnvifError("onvif-endpoint-outside-network")
        request = Request(
            url,
            data=self.envelope(body),
            headers={"Content-Type": "application/soap+xml; charset=utf-8", "User-Agent": "PKWS-CameraHub/1"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return parse_xml(response.read(512 * 1024))
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise OnvifError("onvif-authentication-failed", exc.code) from exc
            raise OnvifError("onvif-http-error", exc.code) from exc
        except TimeoutError as exc:
            raise OnvifError("onvif-timeout") from exc
        except OSError as exc:
            raise OnvifError("onvif-unreachable") from exc

    def discover_services(self) -> dict[str, str]:
        root = self.call(
            self.device_url,
            f'<tds:GetServices xmlns:tds="{DEVICE_NS}"><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>',
        )
        namespace_map = {
            MEDIA_NS: "media",
            PTZ_NS: "ptz",
            IMAGING_NS: "imaging",
            EVENTS_NS: "events",
            DEVICEIO_NS: "deviceio",
            ANALYTICS_NS: "analytics",
        }
        for service in root.iter():
            if local_name(service.tag) != "Service":
                continue
            namespace = first_text(service, "Namespace")
            xaddr = first_text(service, "XAddr")
            key = namespace_map.get(namespace)
            if key and xaddr and self.allowed_url(xaddr):
                self.services[key] = xaddr
                self.advertised_services.add(key)
        parsed = urlparse(self.device_url)
        base = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
        self.services.setdefault("media", base + "/onvif/Media")
        self.services.setdefault("ptz", base + "/onvif/PTZ")
        self.services.setdefault("imaging", base + "/onvif/Imaging")
        self.services.setdefault("events", base + "/onvif/Events")
        self.services.setdefault("deviceio", base + "/onvif/DeviceIO")
        self.services.setdefault("analytics", base + "/onvif/Analytics")
        return self.services

    def device_information(self) -> dict:
        root = self.call(
            self.device_url,
            f'<tds:GetDeviceInformation xmlns:tds="{DEVICE_NS}"/>',
        )
        return {
            "manufacturer": first_text(root, "Manufacturer"),
            "model": first_text(root, "Model"),
            "firmwareVersion": first_text(root, "FirmwareVersion"),
            "serialNumber": first_text(root, "SerialNumber"),
            "hardwareId": first_text(root, "HardwareId"),
        }

    def profiles(self) -> list[dict]:
        root = self.call(self.services["media"], f'<trt:GetProfiles xmlns:trt="{MEDIA_NS}"/>')
        profiles: list[dict] = []
        for node in root.iter():
            if local_name(node.tag) != "Profiles":
                continue
            token = node.attrib.get("token", "")
            encoder = next((child for child in node.iter() if local_name(child.tag) == "VideoEncoderConfiguration"), None)
            audio = next((child for child in node.iter() if local_name(child.tag) == "AudioEncoderConfiguration"), None)
            video_source = next((child for child in node.iter() if local_name(child.tag) == "VideoSourceConfiguration"), None)
            profiles.append(
                {
                    "token": token,
                    "name": first_text(node, "Name", token or "Profil"),
                    "codec": first_text(encoder, "Encoding").lower() if encoder is not None else "",
                    "width": int(first_text(encoder, "Width", "0") or 0) or None if encoder is not None else None,
                    "height": int(first_text(encoder, "Height", "0") or 0) or None if encoder is not None else None,
                    "frameRate": int(first_text(encoder, "FrameRateLimit", "0") or 0) or None if encoder is not None else None,
                    "bitrate": int(first_text(encoder, "BitrateLimit", "0") or 0) or None if encoder is not None else None,
                    "audioCodec": first_text(audio, "Encoding").lower() if audio is not None else "",
                    "videoSourceToken": first_text(video_source, "SourceToken") if video_source is not None else "",
                }
            )
        return profiles

    def audio_information(self) -> dict:
        result = {"supported": False, "codecs": [], "sources": 0, "outputs": 0}
        try:
            root = self.call(self.services["media"], f'<trt:GetAudioSources xmlns:trt="{MEDIA_NS}"/>')
            result["sources"] = sum(1 for node in root.iter() if local_name(node.tag) == "AudioSources")
        except OnvifError:
            pass
        try:
            root = self.call(self.services["media"], f'<trt:GetAudioEncoderConfigurations xmlns:trt="{MEDIA_NS}"/>')
            result["codecs"] = sorted(set(all_text(root, "Encoding")))
        except OnvifError:
            pass
        if "deviceio" in self.advertised_services:
            try:
                root = self.call(self.services["deviceio"], f'<tmd:GetAudioOutputs xmlns:tmd="{DEVICEIO_NS}"/>')
                result["outputs"] = sum(1 for node in root.iter() if local_name(node.tag) == "AudioOutputs")
            except OnvifError:
                pass
        result["supported"] = bool(result["sources"] or result["codecs"])
        return result

    def event_information(self) -> dict:
        result = {"supported": False, "topics": []}
        if "events" not in self.advertised_services:
            return result
        try:
            root = self.call(self.services["events"], f'<tev:GetEventProperties xmlns:tev="{EVENTS_NS}"/>')
            topics = []
            for node in root.iter():
                if local_name(node.tag) in {"TopicSet", "MessageDescription"}:
                    continue
                if node.attrib.get("IsProperty") is not None or node.attrib.get("topic") is not None:
                    topics.append(local_name(node.tag))
            result["topics"] = sorted(set(topics))[:64]
            result["supported"] = True
        except OnvifError:
            pass
        return result

    def device_io_information(self) -> dict:
        result = {"supported": False, "relayOutputs": [], "talkback": False}
        if "deviceio" not in self.advertised_services:
            return result
        result["supported"] = True
        try:
            root = self.call(self.services["deviceio"], f'<tmd:GetRelayOutputs xmlns:tmd="{DEVICEIO_NS}"/>')
            for node in root.iter():
                if local_name(node.tag) != "RelayOutputs":
                    continue
                result["relayOutputs"].append(
                    {
                        "token": node.attrib.get("token", ""),
                        "mode": first_text(node, "Mode"),
                        "idleState": first_text(node, "IdleState"),
                    }
                )
        except OnvifError:
            pass
        try:
            root = self.call(self.services["deviceio"], f'<tmd:GetAudioOutputs xmlns:tmd="{DEVICEIO_NS}"/>')
            result["talkback"] = any(local_name(node.tag) == "AudioOutputs" for node in root.iter())
        except OnvifError:
            pass
        return result

    def stream_uri(self, token: str) -> str:
        root = self.call(
            self.services["media"],
            f'<trt:GetStreamUri xmlns:trt="{MEDIA_NS}"><trt:StreamSetup>'
            '<tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream>'
            '<tt:Transport xmlns:tt="http://www.onvif.org/ver10/schema"><tt:Protocol>RTSP</tt:Protocol></tt:Transport>'
            f"</trt:StreamSetup><trt:ProfileToken>{xml_escape(token)}</trt:ProfileToken></trt:GetStreamUri>",
        )
        return first_text(root, "Uri")

    def snapshot_uri(self, token: str) -> str:
        root = self.call(
            self.services["media"],
            f'<trt:GetSnapshotUri xmlns:trt="{MEDIA_NS}"><trt:ProfileToken>{xml_escape(token)}</trt:ProfileToken></trt:GetSnapshotUri>',
        )
        return first_text(root, "Uri")

    def ptz_information(self, profile_token: str = "") -> dict:
        result = {"supported": False, "presets": [], "absoluteMove": False, "relativeMove": False, "continuousMove": False}
        try:
            root = self.call(self.services["ptz"], f'<tptz:GetNodes xmlns:tptz="{PTZ_NS}"/>')
        except OnvifError:
            return result
        result["supported"] = any(local_name(node.tag) == "PTZNode" for node in root.iter()) or "PTZNode" in ET.tostring(root, encoding="unicode")
        text = ET.tostring(root, encoding="unicode")
        result["absoluteMove"] = "AbsolutePanTiltPositionSpace" in text or "AbsoluteZoomPositionSpace" in text
        result["relativeMove"] = "RelativePanTiltTranslationSpace" in text or "RelativeZoomTranslationSpace" in text
        result["continuousMove"] = "ContinuousPanTiltVelocitySpace" in text or "ContinuousZoomVelocitySpace" in text
        if profile_token:
            try:
                presets_root = self.call(
                    self.services["ptz"],
                    f'<tptz:GetPresets xmlns:tptz="{PTZ_NS}"><tptz:ProfileToken>{xml_escape(profile_token)}</tptz:ProfileToken></tptz:GetPresets>',
                )
                for node in presets_root.iter():
                    if local_name(node.tag) == "Preset":
                        result["presets"].append({"token": node.attrib.get("token", ""), "name": first_text(node, "Name", "Preset")})
            except OnvifError:
                pass
        return result

    def optional_service_support(self) -> dict:
        events = self.event_information()
        device_io = self.device_io_information()
        return {
            "imaging": "imaging" in self.advertised_services,
            "events": events["supported"],
            "eventTopics": events["topics"],
            "analytics": "analytics" in self.advertised_services,
            "deviceIo": device_io["supported"],
            "relayOutputs": device_io["relayOutputs"],
            "talkback": device_io["talkback"],
        }

    def capabilities(self) -> dict:
        device = self.device_information()
        try:
            self.discover_services()
        except OnvifError:
            pass
        profiles = self.profiles()
        for profile in profiles[:16]:
            try:
                profile["streamPath"] = urlparse(self.stream_uri(profile["token"])).path or None
            except OnvifError:
                profile["streamPath"] = None
        snapshot_available = False
        if profiles:
            try:
                snapshot_available = bool(self.snapshot_uri(profiles[0]["token"]))
            except OnvifError:
                pass
        ptz = self.ptz_information(profiles[0]["token"] if profiles else "")
        audio = self.audio_information()
        audio_codecs = sorted({item["audioCodec"] for item in profiles if item.get("audioCodec")} | {item.lower() for item in audio["codecs"]})
        return {
            "device": device,
            "profiles": profiles,
            "snapshot": {"supported": snapshot_available},
            "audio": {
                "supported": bool(audio_codecs or audio["sources"]),
                "codecs": audio_codecs,
                "sources": audio["sources"],
                "outputs": audio["outputs"],
            },
            "ptz": ptz,
            **self.optional_service_support(),
        }

    def ptz_move(self, profile_token: str, x: float, y: float, zoom: float) -> None:
        self.call(
            self.services["ptz"],
            f'<tptz:ContinuousMove xmlns:tptz="{PTZ_NS}"><tptz:ProfileToken>{xml_escape(profile_token)}</tptz:ProfileToken>'
            '<tptz:Velocity><tt:PanTilt xmlns:tt="http://www.onvif.org/ver10/schema" '
            f'x="{x:.3f}" y="{y:.3f}"/><tt:Zoom xmlns:tt="http://www.onvif.org/ver10/schema" x="{zoom:.3f}"/>'
            "</tptz:Velocity></tptz:ContinuousMove>",
        )

    def ptz_stop(self, profile_token: str) -> None:
        self.call(
            self.services["ptz"],
            f'<tptz:Stop xmlns:tptz="{PTZ_NS}"><tptz:ProfileToken>{xml_escape(profile_token)}</tptz:ProfileToken>'
            "<tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>",
        )

    def goto_preset(self, profile_token: str, preset_token: str) -> None:
        if not re.fullmatch(r"[\w.:\-]{1,128}", preset_token):
            raise OnvifError("onvif-invalid-preset-token")
        self.call(
            self.services["ptz"],
            f'<tptz:GotoPreset xmlns:tptz="{PTZ_NS}"><tptz:ProfileToken>{xml_escape(profile_token)}</tptz:ProfileToken>'
            f"<tptz:PresetToken>{xml_escape(preset_token)}</tptz:PresetToken></tptz:GotoPreset>",
        )
