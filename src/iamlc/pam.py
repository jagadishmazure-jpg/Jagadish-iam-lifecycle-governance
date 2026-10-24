"""Access requests with approval, just-in-time elevation that expires on its own, recorded privileged
sessions, and monitored break-glass accounts.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .audit import AuditLog
from .clock import HOUR, Clock
from .directory import Directory
from .pii import SafeError
from .sod import would_conflict

MAX_JIT = 8 * HOUR
ROLE_OWNERS = {
    "refund_investigator": "owner-support-tools",
    "payments_approver": "owner-payments",
    "vendor_admin": "owner-vendor-ops",
    "directory_admin": "owner-it",
}


class RequestError(SafeError):
    pass


@dataclass
class AccessRequest:
    req_id: str
    user_id: str
    role: str
    reason: str
    duration: int
    approvals: set[str] = field(default_factory=set)
    status: str = "pending"  # pending | active | denied | expired
    granted_at: int | None = None
    sod_exception: bool = False


@dataclass
class Pam:
    clock: Clock
    directory: Directory
    audit: AuditLog
    managers: dict[str, str] = field(default_factory=dict)  # user_id -> manager user_id
    requests: dict[str, AccessRequest] = field(default_factory=dict)
    recordings: dict[str, list[str]] = field(default_factory=dict)
    break_glass: set[str] = field(default_factory=set)
    alerts: list[str] = field(default_factory=list)

    # ---- requests -----------------------------------------------------------------------------------
    def roles_of(self, user_id: str) -> set[str]:
        return {g.removeprefix("grp-") for g in self.directory.groups_of(user_id)}

    def request(self, user_id: str, role: str, reason: str, duration: int) -> AccessRequest:
        if role not in ROLE_OWNERS:
            raise RequestError("role is not requestable")
        if len(reason.strip()) < 10:
            raise RequestError("a business reason is required")
        if not 0 < duration <= MAX_JIT:
            raise RequestError("duration must be between 1 second and 8 hours")
        u = self.directory.users.get(user_id)
        if u is None or not u.enabled:
            raise RequestError("requester not active")
        r = AccessRequest(f"req-{secrets.token_hex(4)}", user_id, role, reason, duration)
        self.requests[r.req_id] = r
        self.audit.record(user_id, "access.requested", role, "ok", reason)
        return r

    def approve(self, req_id: str, approver: str, sod_exception_by: str | None = None) -> AccessRequest:
        r = self.requests[req_id]
        if r.status != "pending":
            raise RequestError("request is not pending")
        if approver == r.user_id:
            raise RequestError("self-approval is not allowed")
        if approver not in {self.managers.get(r.user_id), ROLE_OWNERS[r.role]}:
            raise RequestError("approver is neither the manager nor the role owner")
        r.approvals.add(approver)
        self.audit.record(approver, "access.approved", r.req_id)
        need = {self.managers.get(r.user_id), ROLE_OWNERS[r.role]}
        if need <= r.approvals:
            clash = would_conflict(self.roles_of(r.user_id), r.role)
            if clash and not sod_exception_by:
                r.status = "denied"
                self.audit.record("pam", "access.sod_blocked", r.req_id, "denied", clash[0].rule_id)
                return r
            if clash:
                r.sod_exception = True
                self.audit.record(sod_exception_by, "sod.exception", r.req_id, "ok", clash[0].rule_id)
            r.status, r.granted_at = "active", self.clock.now
            self.directory.add_to_group(f"grp-{r.role}", r.user_id)
            self.recordings[r.req_id] = []
            self.audit.record("pam", "jit.granted", r.user_id, "ok", f"{r.role} for {r.duration}s")
        return r

    def sweep(self) -> int:
        """Remove elevations whose time is up. Run on a schedule; returns how many expired."""
        n = 0
        for r in self.requests.values():
            if r.status == "active" and self.clock.now >= (r.granted_at or 0) + r.duration:
                self.directory.remove_from_group(f"grp-{r.role}", r.user_id)
                r.status, n = "expired", n + 1
                self.audit.record("pam", "jit.expired", r.user_id, "ok", r.role)
        return n

    def record_command(self, req_id: str, command: str) -> None:
        r = self.requests[req_id]
        if r.status != "active" or self.clock.now >= (r.granted_at or 0) + r.duration:
            raise RequestError("no active elevation for this session")
        self.recordings[req_id].append(f"{self.clock.now} {command}")
        self.audit.record(r.user_id, "pam.command", req_id, "ok", command)

    # ---- break glass --------------------------------------------------------------------------------
    def register_break_glass(self, user_id: str) -> None:
        self.break_glass.add(user_id)

    def break_glass_signin(self, user_id: str, reason: str, idp_up: bool) -> str:
        if user_id not in self.break_glass:
            raise RequestError("not a break-glass account")
        alert = f"BREAK-GLASS used by {user_id} (idp_up={idp_up}): {reason}"
        self.alerts.append(alert)
        self.audit.record(user_id, "breakglass.signin", user_id, "alert", reason)
        if idp_up:
            self.alerts.append(f"BREAK-GLASS used while IdP healthy: investigate {user_id}")
        return alert
