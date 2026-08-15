from __future__ import annotations

import json
import struct
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

import bridge


def framed_video(video: bytes, audio: bytes = b"") -> bytes:
    total = 32 + len(video) + len(audio)
    data = bytearray(total)
    data[:4] = bridge.FRAME_MAGIC
    struct.pack_into("<I", data, 4, total)
    struct.pack_into("<I", data, 20, len(video))
    data[32 : 32 + len(video)] = video
    data[32 + len(video) :] = audio
    return bytes(data)


def media_packet(payload: bytes) -> bytes:
    data = bytearray(28 + len(payload))
    data[:4] = bridge.MEDIA_MAGIC
    struct.pack_into("<H", data, 14, len(data))
    data[28:] = payload
    return bytes(data)


class BridgeTests(unittest.TestCase):
    def test_config_maps_second_stream_after_all_physical_channels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            path.write_text(json.dumps({
                "host": "192.0.2.10", "username": "Admin", "password": "redacted",
                "channelCount": 8,
                "channels": [{"channel": 5, "stream": 1, "path": "sannce-5-low"}],
            }), encoding="utf-8")
            config = bridge.load_config(path)
        self.assertEqual(config.channels[0].stream_index, 12)
        self.assertEqual(config.channel_count, 8)
        self.assertEqual(config.discover_channels, ())

    def test_config_creates_safe_discovery_channel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            path.write_text(json.dumps({
                "host": "192.0.2.10", "username": "Admin", "password": "redacted",
                "channelCount": 8, "discoverChannels": [2],
                "channels": [{"channel": 5, "stream": 1, "path": "sannce-5-low"}],
            }), encoding="utf-8")
            config = bridge.load_config(path)
        self.assertEqual(config.discover_channels[0].physical, 2)
        self.assertEqual(config.discover_channels[0].stream_index, 9)
        self.assertEqual(config.discover_channels[0].path, "sannce-2-low")

    def test_command_packet_has_expected_little_endian_lengths(self):
        packet = bridge.command_packet("hello")
        self.assertEqual(packet[:4], bridge.COMMAND_MAGIC)
        self.assertEqual(struct.unpack_from("<H", packet, 6)[0], 25)
        self.assertEqual(struct.unpack_from("<H", packet, 18)[0], 5)

    def test_frame_parser_reassembles_chunks_and_excludes_audio(self):
        video = b"\x00\x00\x00\x01\x67video"
        packet = framed_video(video, b"audio")
        parser = bridge.FrameParser()
        self.assertEqual(list(parser.feed(packet[:17])), [])
        self.assertEqual(list(parser.feed(packet[17:])), [video])

    def test_frame_parser_resynchronizes_after_noise(self):
        video = b"\x00\x00\x01\x67frame"
        parser = bridge.FrameParser()
        self.assertEqual(list(parser.feed(b"noise" + framed_video(video))), [video])

    def test_media_parser_preserves_packets_split_between_websocket_messages(self):
        first, second = media_packet(b"first"), media_packet(b"second")
        stream = b"noise" + first + second
        parser = bridge.MediaParser()
        self.assertEqual(list(parser.feed(stream[:37])), [])
        self.assertEqual(list(parser.feed(stream[37:-2])), [b"first"])
        self.assertEqual(list(parser.feed(stream[-2:])), [b"second"])

    def test_sps_detection_accepts_three_and_four_byte_start_codes(self):
        self.assertTrue(bridge.has_h264_sps(b"\x00\x00\x00\x01\x67x"))
        self.assertTrue(bridge.has_h264_sps(b"\x00\x00\x01\x67x"))
        self.assertFalse(bridge.has_h264_sps(b"\x00\x00\x00\x01\x65x"))

    def test_codec_detection_recognizes_h264_and_h265_parameter_sets(self):
        self.assertEqual(bridge.detected_codec(b"\x00\x00\x00\x01\x67x"), "h264")
        self.assertEqual(bridge.detected_codec(b"\x00\x00\x00\x01\x40x"), "h265")
        self.assertIsNone(bridge.detected_codec(b"\x00\x00\x00\x01\x65x"))

    def test_command_maintenance_tolerates_idle_timeouts_and_drains_ping(self):
        class FakeWebSocket:
            def __init__(self):
                self.calls = 0

            def receive(self):
                self.calls += 1
                if self.calls == 1:
                    raise TimeoutError
                finished.set()
                return b""

        finished = threading.Event()
        websocket = FakeWebSocket()
        bridge.maintain_command_socket(websocket, finished)
        self.assertEqual(websocket.calls, 2)

    def test_recording_search_normalizes_recorder_local_time_and_hides_filename(self):
        config = bridge.Config(
            host="192.0.2.10", port=3002, username="Admin", password="redacted",
            channel_count=8, channels=(), discover_channels=(),
        )
        result = ET.fromstring("""<CMSearchResult><numOfMatches>1</numOfMatches><matchList>
          <matchElement><chanNo>4</chanNo><type>Timer</type><fileName>secret.sdv</fileName>
          <timeSpan><startTime>2026-08-15T10:00:00Z</startTime><endTime>2026-08-15T10:05:00Z</endTime></timeSpan>
          </matchElement></matchList></CMSearchResult>""")
        with patch.object(bridge, "recorder_post_xml", return_value=result):
            total, recordings = bridge.search_recordings(
                config, 5, datetime(2026, 8, 15), datetime(2026, 8, 16)
            )
        self.assertEqual(total, 1)
        self.assertEqual(recordings[0].channel, 5)
        self.assertEqual(recordings[0].start_at, "2026-08-15T08:00:00Z")
        self.assertRegex(recordings[0].token, r"^[a-f0-9]{40}$")
        self.assertNotIn("secret.sdv", recordings[0].token)

    def test_recording_search_rejects_other_channels_and_unsafe_filenames(self):
        config = bridge.Config("192.0.2.10", 3002, "Admin", "redacted", 8, (), ())
        result = ET.fromstring("""<CMSearchResult><numOfMatches>2</numOfMatches><matchList>
          <matchElement><chanNo>3</chanNo><type>Timer</type><fileName>other.sdv</fileName><timeSpan><startTime>2026-08-15T10:00:00Z</startTime><endTime>2026-08-15T10:05:00Z</endTime></timeSpan></matchElement>
          <matchElement><chanNo>4</chanNo><type>Timer</type><fileName>bad&#10;name.sdv</fileName><timeSpan><startTime>2026-08-15T10:00:00Z</startTime><endTime>2026-08-15T10:05:00Z</endTime></timeSpan></matchElement>
          </matchList></CMSearchResult>""")
        with patch.object(bridge, "recorder_post_xml", return_value=result):
            _, recordings = bridge.search_recordings(
                config, 5, datetime(2026, 8, 15), datetime(2026, 8, 16)
            )
        self.assertEqual(recordings, [])

    def test_daily_recordings_continue_until_a_short_provider_page(self):
        config = bridge.Config("192.0.2.10", 3002, "Admin", "redacted", 8, (), ())
        item = bridge.Recording("a" * 40, 3, "Timer", "2026-08-15T08:00:00Z", "2026-08-15T08:01:00Z", "hidden.sdv")
        with patch.object(
            bridge,
            "search_recordings",
            side_effect=[(500, [item] * 500), (2, [item, item])],
        ) as search:
            recordings = bridge.recordings_for_day(config, 3, date(2026, 8, 15))
        self.assertEqual(len(recordings), 502)
        self.assertEqual(search.call_args_list[1].kwargs["position"], 501)

    def test_availability_uses_first_and_last_items_across_provider_pages(self):
        config = bridge.Config("192.0.2.10", 3002, "Admin", "redacted", 8, (), ())
        first = bridge.Recording("a" * 40, 3, "Timer", "2026-08-13T08:00:00Z", "2026-08-13T08:01:00Z", "first.sdv")
        last = bridge.Recording("b" * 40, 3, "Timer", "2026-08-15T09:00:00Z", "2026-08-15T09:01:00Z", "last.sdv")
        with patch.object(
            bridge,
            "search_recordings",
            side_effect=[(1000, [first] * 1000), (1, [last])],
        ):
            availability = bridge.recording_availability(config, 3)
        self.assertEqual(availability["availableFrom"], first.start_at)
        self.assertEqual(availability["availableTo"], last.end_at)
        self.assertFalse(availability["limited"])


if __name__ == "__main__":
    unittest.main()
