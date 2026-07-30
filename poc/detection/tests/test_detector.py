import unittest

import cv2
import numpy as np

from detector import MotionEngine


def config(kind="alarm", **values):
    zone = {
        "id": "zone-1",
        "kind": kind,
        "points": [
            {"x": 0.1, "y": 0.1}, {"x": 0.9, "y": 0.1},
            {"x": 0.9, "y": 0.9}, {"x": 0.1, "y": 0.9},
        ],
        "sensitivity": 50,
        "minAreaRatio": 0.015,
        "confirmationSeconds": 1,
        "quietSeconds": 5,
        "cooldownSeconds": 30,
        **values,
    }
    return {"zones": [zone]}


class MotionEngineTests(unittest.TestCase):
    def test_warmup_suppresses_alarm(self):
        engine = MotionEngine(config(), width=64, height=36, warmup_seconds=10, clock=lambda: 0)
        self.assertEqual(engine.process(np.full((36, 64), 255, np.uint8), now=5), [])

    def test_confirmation_and_quiet_end(self):
        engine = MotionEngine(config(), width=64, height=36, warmup_seconds=.5, clock=lambda: 0)
        background = np.zeros((36, 64), np.uint8)
        for tick in range(20):
            engine.process(background, now=tick / 10)
        moving = background.copy()
        cv2.rectangle(moving, (15, 10), (30, 25), 255, -1)
        self.assertEqual(engine.process(moving, now=2.0), [])
        for tick in (2.25, 2.5, 2.75):
            engine.process(moving, now=tick)
        starts = engine.process(moving, now=3.1)
        self.assertEqual(starts[0]["state"], "started")
        updates = engine.process(moving, now=8.2)
        self.assertEqual(updates[0]["state"], "updated")
        engine.process(background, now=9)
        ends = engine.process(background, now=14)
        self.assertEqual(ends[0]["state"], "ended")

    def test_global_scene_change_relearns_without_alarm(self):
        engine = MotionEngine(config(), width=64, height=36, warmup_seconds=.5, clock=lambda: 0)
        black = np.zeros((36, 64), np.uint8)
        for tick in range(20):
            engine.process(black, now=tick / 10)
        self.assertEqual(engine.process(np.full((36, 64), 255, np.uint8), now=3), [])
        self.assertTrue(engine.warmup_until >= 3.5)

    def test_ignore_mask_removes_motion(self):
        cfg = config()
        cfg["zones"].append(config(kind="ignore")["zones"][0] | {"id": "ignore"})
        engine = MotionEngine(cfg, width=64, height=36, warmup_seconds=.5, clock=lambda: 0)
        black = np.zeros((36, 64), np.uint8)
        for tick in range(20):
            engine.process(black, now=tick / 10)
        moving = black.copy()
        cv2.rectangle(moving, (15, 10), (30, 25), 255, -1)
        self.assertEqual(engine.process(moving, now=3), [])
        self.assertEqual(engine.process(moving, now=5), [])

    def test_motion_outside_polygon_is_ignored(self):
        cfg = config()
        cfg["zones"][0]["points"] = [
            {"x": 0.0, "y": 0.0}, {"x": 0.45, "y": 0.0},
            {"x": 0.45, "y": 1.0}, {"x": 0.0, "y": 1.0},
        ]
        engine = MotionEngine(cfg, width=64, height=36, warmup_seconds=.5, clock=lambda: 0)
        black = np.zeros((36, 64), np.uint8)
        for tick in range(20):
            engine.process(black, now=tick / 10)
        moving = black.copy()
        cv2.rectangle(moving, (45, 8), (60, 28), 255, -1)
        self.assertEqual(engine.process(moving, now=3), [])
        self.assertEqual(engine.process(moving, now=5), [])

    def test_cooldown_blocks_immediate_second_alarm(self):
        cfg = config(confirmationSeconds=.1, quietSeconds=.5, cooldownSeconds=10)
        engine = MotionEngine(cfg, width=64, height=36, warmup_seconds=.5, clock=lambda: 0)
        black = np.zeros((36, 64), np.uint8)
        for tick in range(20):
            engine.process(black, now=tick / 10)
        moving = black.copy()
        cv2.rectangle(moving, (15, 10), (30, 25), 255, -1)
        engine.process(moving, now=2)
        self.assertEqual(engine.process(moving, now=2.2)[0]["state"], "started")
        self.assertEqual(engine.process(black, now=3)[0]["state"], "ended")
        engine.process(moving, now=4)
        self.assertEqual(engine.process(moving, now=5), [])


if __name__ == "__main__":
    unittest.main()
