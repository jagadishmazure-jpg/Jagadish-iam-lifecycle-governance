"""A controllable clock so expiry, travel speed and "three months later" are deterministic in tests."""

from __future__ import annotations

from dataclasses import dataclass

MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * HOUR


@dataclass
class Clock:
    now: int = 1_800_000_000  # seconds; fixed start so every run gives the same output

    def advance(self, seconds: int) -> int:
        if seconds < 0:
            raise ValueError("time only moves forward")
        self.now += seconds
        return self.now
