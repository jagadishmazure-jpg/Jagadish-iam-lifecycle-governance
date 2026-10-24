"""Brief models of the identities outside the workforce, kept small on purpose.

* Customers (CIAM): self-service sign-up and recovery, scale over control. Not modelled beyond a policy.
* Partners and guests: sponsored, time-boxed accounts that expire with the contract.
* Machine identities: short-lived credentials from a secrets manager instead of keys in code. The deep
  treatment lives in Jagadish-agent-identity-security and Jagadish-machine-identity-security.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .clock import HOUR, Clock
from .pii import SafeError


class SecretError(SafeError):
    pass


CIAM_POLICY = {
    "signup": "self-service with email verification",
    "mfa": "offered, passkey preferred; risk-based step-up at checkout",
    "recovery": "self-service, rate limited, never by support agent override alone",
    "scale_target": "millions of accounts; no per-user manual approval",
}


@dataclass
class GuestAccount:
    user_id: str
    sponsor: str
    home_org: str
    expires: int
    scopes: frozenset[str]

    def usable(self, now: int) -> bool:
        return now < self.expires


@dataclass
class SecretsManager:
    """Hands out short-lived leases to named services only. Values never appear in reprs or logs."""

    clock: Clock
    acl: dict[str, set[str]] = field(default_factory=dict)  # secret name -> services allowed
    _values: dict[str, str] = field(default_factory=dict, repr=False)
    leases: dict[str, tuple[str, str, int]] = field(default_factory=dict, repr=False)
    ttl: int = HOUR

    def put(self, name: str, value: str, allowed: set[str]) -> None:
        self._values[name] = value
        self.acl[name] = set(allowed)

    def lease(self, service: str, name: str) -> str:
        if service not in self.acl.get(name, set()):
            raise SecretError(f"service {service} may not read {name}")
        lease_id = secrets.token_hex(8)
        self.leases[lease_id] = (service, name, self.clock.now + self.ttl)
        return lease_id

    def read(self, service: str, lease_id: str) -> str:
        rec = self.leases.get(lease_id)
        if rec is None or rec[0] != service or self.clock.now >= rec[2]:
            raise SecretError("lease invalid or expired")
        return self._values[rec[1]]

    def rotate(self, name: str) -> None:
        self._values[name] = secrets.token_urlsafe(24)
        for k in [k for k, v in self.leases.items() if v[1] == name]:
            del self.leases[k]
