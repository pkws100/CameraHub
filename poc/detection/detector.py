from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import cv2
import numpy as np


@dataclass
class ZoneRuntime:
    config: dict[str, Any]
    mask: np.ndarray
    pixel_count: int
    candidate_since: float | None = None
    active_id: str | None = None
    last_motion: float | None = None
    last_update: float = 0
    cooldown_until: float = 0


class MotionEngine:
    """Stateful, CPU-only motion detector for one already-running stream."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        width: int = 640,
        height: int = 360,
        warmup_seconds: float = 10,
        scene_change_ratio: float = 0.60,
        clock=time.monotonic,
    ) -> None:
        self.width = width
        self.height = height
        self.warmup_seconds = warmup_seconds
        self.scene_change_ratio = scene_change_ratio
        self.clock = clock
        self.background = self._new_background()
        self.warmup_until = clock() + warmup_seconds
        self._was_learning = True
        self.ignore_mask = np.zeros((height, width), dtype=np.uint8)
        self.zones: list[ZoneRuntime] = []
        for zone in config.get("zones", []):
            mask = self._polygon_mask(zone.get("points", []))
            if zone.get("kind") == "ignore":
                self.ignore_mask = cv2.bitwise_or(self.ignore_mask, mask)
                continue
            pixels = int(cv2.countNonZero(mask))
            if pixels:
                self.zones.append(ZoneRuntime(zone, mask, pixels))

    @staticmethod
    def _new_background():
        return cv2.createBackgroundSubtractorMOG2(
            history=300, varThreshold=16, detectShadows=False
        )

    def _polygon_mask(self, points: list[dict[str, float]]) -> np.ndarray:
        mask = np.zeros((self.height, self.width), dtype=np.uint8)
        if len(points) < 3:
            return mask
        polygon = np.array(
            [
                [
                    max(0, min(self.width - 1, round(float(point["x"]) * (self.width - 1)))),
                    max(0, min(self.height - 1, round(float(point["y"]) * (self.height - 1)))),
                ]
                for point in points
            ],
            dtype=np.int32,
        )
        cv2.fillPoly(mask, [polygon], 255)
        return mask

    @property
    def learning(self) -> bool:
        return self.clock() < self.warmup_until

    def reset_background(self, now: float) -> list[dict[str, Any]]:
        actions = self.end_all(now, reason="scene-change")
        self.background = self._new_background()
        self.warmup_until = now + self.warmup_seconds
        self._was_learning = True
        return actions

    def process(self, frame: np.ndarray, now: float | None = None) -> list[dict[str, Any]]:
        now = self.clock() if now is None else now
        if frame.shape[:2] != (self.height, self.width):
            frame = cv2.resize(frame, (self.width, self.height))
        gray = frame if len(frame.shape) == 2 else cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        learning = now < self.warmup_until
        foreground = self.background.apply(gray, learningRate=-1 if learning else 0.002)
        foreground = cv2.medianBlur(foreground, 5)
        foreground = cv2.morphologyEx(
            foreground, cv2.MORPH_OPEN, np.ones((3, 3), dtype=np.uint8)
        )
        if learning:
            self._was_learning = True
            return []
        if self._was_learning:
            # Seal the warm-up with the latest complete frame. Otherwise a
            # repeatedly moving object seen during warm-up can become a second
            # background mode and remain invisible indefinitely.
            self.background = self._new_background()
            self.background.apply(gray, learningRate=1)
            self._was_learning = False
            return []
        scene_ratio = cv2.countNonZero(foreground) / float(self.width * self.height)
        if scene_ratio > self.scene_change_ratio:
            return self.reset_background(now)
        foreground[self.ignore_mask > 0] = 0
        actions: list[dict[str, Any]] = []
        for runtime in self.zones:
            changed = cv2.countNonZero(cv2.bitwise_and(foreground, runtime.mask))
            ratio = changed / float(runtime.pixel_count)
            sensitivity = float(runtime.config.get("sensitivity", 50))
            configured_ratio = float(runtime.config.get("minAreaRatio", 0.015))
            threshold = configured_ratio * max(0.5, 1.5 - sensitivity / 100)
            detected = ratio >= threshold
            confirmation = float(runtime.config.get("confirmationSeconds", 1))
            quiet = float(runtime.config.get("quietSeconds", 5))
            cooldown = float(runtime.config.get("cooldownSeconds", 30))
            strength = min(100.0, ratio / max(threshold, 0.0001) * 50)
            common = {
                "zoneId": runtime.config["id"],
                "motionPercent": ratio * 100,
                "strength": strength,
            }
            if runtime.active_id:
                if detected:
                    runtime.last_motion = now
                    if now - runtime.last_update >= 5:
                        runtime.last_update = now
                        actions.append(
                            {"state": "updated", "workerEventId": runtime.active_id, **common}
                        )
                elif runtime.last_motion is not None and now - runtime.last_motion >= quiet:
                    actions.append(
                        {"state": "ended", "workerEventId": runtime.active_id, **common}
                    )
                    runtime.active_id = None
                    runtime.last_motion = None
                    runtime.candidate_since = None
                    runtime.cooldown_until = now + cooldown
                continue
            if now < runtime.cooldown_until:
                runtime.candidate_since = None
                continue
            if not detected:
                runtime.candidate_since = None
                continue
            if runtime.candidate_since is None:
                runtime.candidate_since = now
            if now - runtime.candidate_since >= confirmation:
                runtime.active_id = uuid.uuid4().hex
                runtime.last_motion = now
                runtime.last_update = now
                actions.append(
                    {"state": "started", "workerEventId": runtime.active_id, **common}
                )
        return actions

    def end_all(self, now: float | None = None, reason: str = "stream-stopped") -> list[dict[str, Any]]:
        now = self.clock() if now is None else now
        actions = []
        for runtime in self.zones:
            if runtime.active_id:
                actions.append(
                    {
                        "state": "ended",
                        "workerEventId": runtime.active_id,
                        "zoneId": runtime.config["id"],
                        "motionPercent": 0,
                        "strength": 0,
                        "reason": reason,
                    }
                )
            runtime.active_id = None
            runtime.last_motion = None
            runtime.candidate_since = None
        return actions
