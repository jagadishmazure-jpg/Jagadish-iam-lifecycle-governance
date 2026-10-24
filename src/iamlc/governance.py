"""Access reviews (certifications) and orphan-account detection against HR."""

from __future__ import annotations

from dataclasses import dataclass, field

from .apps import LocalAccountApp, ScimApp
from .audit import AuditLog
from .directory import Directory
from .hr import HrSystem
from .sod import conflicts

HIGH_RISK = {"payments_approver", "directory_admin", "vendor_admin", "refund_investigator"}


@dataclass
class ReviewItem:
    user_id: str
    role: str
    reviewer: str
    high_risk: bool
    decision: str = "pending"  # keep | revoke | pending


@dataclass
class Campaign:
    items: list[ReviewItem] = field(default_factory=list)

    @property
    def revoked(self) -> int:
        return sum(1 for i in self.items if i.decision == "revoke")


def build_campaign(directory: Directory, managers: dict[str, str]) -> Campaign:
    c = Campaign()
    for g, members in sorted(directory.groups.items()):
        role = g.removeprefix("grp-")
        if role == "employee_base":
            continue
        for uid in sorted(members):
            reviewer = managers.get(uid, "owner-unassigned")
            c.items.append(ReviewItem(uid, role, reviewer, role in HIGH_RISK))
    return c


def decide(c: Campaign, reviewer: str, user_id: str, role: str, decision: str, directory: Directory, audit: AuditLog):
    if decision not in {"keep", "revoke"}:
        raise ValueError("decision must be keep or revoke")
    for item in c.items:
        if item.user_id == user_id and item.role == role:
            if item.reviewer != reviewer:
                raise PermissionError("only the assigned reviewer may decide")
            if reviewer == user_id:
                raise PermissionError("cannot certify your own access")
            item.decision = decision
            if decision == "revoke":
                directory.remove_from_group(f"grp-{role}", user_id)
            audit.record(reviewer, f"review.{decision}", user_id, "ok", role)
            return item
    raise KeyError("no such review item")


def find_orphans(hr: HrSystem, apps: dict[str, ScimApp | LocalAccountApp], service_accounts: set[str]) -> list[str]:
    """Accounts in an app with no active HR worker behind them (excluding registered service accounts)."""
    active_usernames = {f"u{w.employee_id.lower()}" for w in hr.workers.values() if w.status == "active"}
    out = []
    for name, app in sorted(apps.items()):
        for uname in sorted(app.usernames()):
            if uname in service_accounts or not app.account_active(uname):
                continue
            if uname not in active_usernames:
                out.append(f"{name}:{uname}")
    return out


def sod_report(directory: Directory) -> list[tuple[str, str]]:
    out = []
    for uid in sorted(directory.users):
        roles = {g.removeprefix("grp-") for g in directory.groups_of(uid)}
        out.extend((uid, r.rule_id) for r in conflicts(roles))
    return out
