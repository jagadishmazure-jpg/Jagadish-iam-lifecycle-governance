"""SIEM-style correlation over sign-in events: impossible travel, push floods and use of disabled or
break-glass accounts. Output is a risk level the zero-trust policy turns into allow / step-up / deny.

Impossible travel is a hint, not proof. A corporate VPN or a mobile carrier can place a user far away in
minutes. Known VPN egress addresses lower the risk to a recorded note instead of a challenge; unknown
jumps get a step-up, not a block, unless another signal agrees.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

MAX_KMH = 900  # faster than a commercial flight


@dataclass(frozen=True)
class SignIn:
    user: str
    ts: int
    lat: float
    lon: float
    ip: str
    outcome: str = "success"  # success | failure | disabled
    new_device: bool = False


def km_between(a: SignIn, b: SignIn) -> float:
    r = 6371.0
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dp, dl = p2 - p1, math.radians(b.lon - a.lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


@dataclass
class Siem:
    vpn_egress: set[str] = field(default_factory=set)
    last: dict[str, SignIn] = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def ingest(self, ev: SignIn, push_flagged: bool = False) -> str:
        """Returns the risk level for this sign-in: low | medium | high."""
        risk = "low"
        if ev.outcome == "disabled":
            self.alerts.append({"rule": "disabled-account-signin", "user": ev.user, "ts": ev.ts})
            return "high"
        prev = self.last.get(ev.user)
        if prev is not None and ev.outcome == "success":
            hours = max((ev.ts - prev.ts) / 3600, 1 / 3600)
            km = km_between(prev, ev)
            speed = km / hours
            if speed > MAX_KMH:
                if ev.ip in self.vpn_egress:
                    self.notes.append(f"{ev.user}: {km:.0f} km in {hours * 60:.0f} min via known VPN egress")
                else:
                    risk = "medium"
                    self.alerts.append(
                        {"rule": "impossible-travel", "user": ev.user, "km": round(km), "kmh": round(speed)}
                    )
        if push_flagged:
            self.alerts.append({"rule": "push-flood", "user": ev.user, "ts": ev.ts})
            risk = "high" if risk == "medium" else "medium"
        if risk == "medium" and ev.new_device:
            risk = "high"
        if ev.outcome == "success":
            self.last[ev.user] = ev
        return risk
