from __future__ import annotations

import json
import struct
import tempfile
import threading
import unittest
from pathlib import Path

import bridge


def framed_video(video: bytes, audio: bytes = b"") -> bytes:
    total = 32 + len(video) + len(audio)
    data = bytearray(total)
    data[:4] = bridge.FRAME_MAGIC
    struct.pack_into("<I", data, 4, total - 8)
    struct.pack_into("<I", data, 20, len(video))
    data[32 : 32 + len(video)] = video
    data[32 + len(video) :] = audio
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


if __name__ == "__main__":
    unittest.main()
