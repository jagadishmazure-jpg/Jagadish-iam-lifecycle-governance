"""Accounting: an append-only, hash-chained audit log. Every detail string is PII-masked on write."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .clock import Clock
from .pii import mask


@dataclass(frozen=True)
class Event:
    seq: int
    ts: int
    actor: str
    action: str
    target: str
    outcome: str
    detail: str
    prev_hash: str
    hash: str


@dataclass
class AuditLog:
    clock: Clock
    events: list[Event] = field(default_factory=list)

    def record(self, actor: str, action: str, target: str, outcome: str = "ok", detail: str = "") -> Event:
        prev = self.events[-1].hash if self.events else "0" * 64
        body = {
            "seq": len(self.events),
            "ts": self.clock.now,
            "actor": mask(actor),
            "action": action,
            "target": mask(target),
            "outcome": outcome,
            "detail": mask(detail),
            "prev_hash": prev,
        }
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        ev = Event(hash=digest, **body)
        self.events.append(ev)
        return ev

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for ev in self.events:
            body = {k: getattr(ev, k) for k in ("seq", "ts", "actor", "action", "target", "outcome", "detail")}
            body["prev_hash"] = prev
            if ev.prev_hash != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != ev.hash:
                return False
            prev = ev.hash
        return True

    def find(self, action: str | None = None, target: str | None = None, outcome: str | None = None) -> list[Event]:
        return [
            e
            for e in self.events
            if (action is None or e.action == action)
            and (target is None or e.target == target)
            and (outcome is None or e.outcome == outcome)
        ]

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e.__dict__, sort_keys=True) for e in self.events)
