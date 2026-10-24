"""Joiner / mover / leaver driven by HR events.

* Joiner: directory user, birthright groups, accounts in every birthright app (SCIM or connector).
* Mover: compute the new birthright set, grant what is missing AND remove what the old job gave. Any
  extra grant from an access request is also dropped so it can be requested again for the new job.
* Leaver: disable the directory user, revoke IdP sessions and tokens, kill every app session, deactivate
  every account (SCIM or local connector), remove groups, then read every app back to verify. Failed
  writes are retried with backoff; anything still wrong is flagged as an open exception, never silently
  dropped.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .apps import PATCH_SCHEMA, USER_SCHEMA, AppError, LocalAccountApp, ScimApp
from .audit import AuditLog
from .directory import Directory, DirUser
from .hr import HrEvent, HrSystem
from .idp import IdentityProvider

BIRTHRIGHT: dict[str, dict[str, list[str]]] = {
    "Support": {"groups": ["grp-employee_base", "grp-support_agent"], "apps": ["mail", "chat", "orders", "helpdesk"]},
    "Payments": {"groups": ["grp-employee_base", "grp-payments_analyst"], "apps": ["mail", "chat", "payouts"]},
    "Vendor Ops": {"groups": ["grp-employee_base", "grp-vendor_admin"], "apps": ["mail", "chat", "vendors"]},
    "Finance": {"groups": ["grp-employee_base", "grp-payments_approver"], "apps": ["mail", "chat", "payouts"]},
    "IT": {"groups": ["grp-employee_base", "grp-directory_admin"], "apps": ["mail", "chat"]},
}

MAX_ATTEMPTS = 4


@dataclass
class StepResult:
    app: str
    action: str
    ok: bool
    attempts: int
    detail: str = ""


@dataclass
class Report:
    employee_id: str
    kind: str
    steps: list[StepResult] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    verified: bool = False

    @property
    def retried(self) -> int:
        return sum(1 for s in self.steps if s.attempts > 1)


def username_for(employee_id: str) -> str:
    return f"u{employee_id.lower()}"


@dataclass
class LifecycleEngine:
    hr: HrSystem
    directory: Directory
    idp: IdentityProvider
    apps: dict[str, ScimApp | LocalAccountApp]
    audit: AuditLog
    open_exceptions: list[str] = field(default_factory=list)
    issued_local_passwords: dict[str, str] = field(default_factory=dict)  # kept only for the demo scenario
    backoff_log: list[int] = field(default_factory=list)
    pending_leavers: set[str] = field(default_factory=set)

    # ---- dispatch -----------------------------------------------------------------------------------
    def process(self) -> list[Report]:
        out = []
        for ev in self.hr.drain():
            out.append({"hire": self.joiner, "transfer": self.mover, "terminate": self.leaver}[ev.kind](ev))
        return out

    # ---- helpers ------------------------------------------------------------------------------------
    def _retry(self, report: Report, app: str, action: str, fn) -> bool:
        detail = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                ok, detail = fn()
            except AppError as exc:
                ok, detail = False, str(exc)
            if ok:
                report.steps.append(StepResult(app, action, True, attempt, detail))
                if attempt > 1:
                    self.audit.record("lifecycle", f"{action}.retried", app, "ok", f"attempts={attempt}")
                return True
            self.backoff_log.append(2 ** (attempt - 1))  # seconds we would sleep; not slept in the lab
        report.steps.append(StepResult(app, action, False, MAX_ATTEMPTS, detail))
        msg = f"{report.kind}:{report.employee_id}:{app}:{action} failed after {MAX_ATTEMPTS} attempts"
        report.exceptions.append(msg)
        self.open_exceptions.append(msg)
        self.audit.record("lifecycle", f"{action}.failed", app, "flagged", detail)
        return False

    def _scim_ensure(self, app: ScimApp, username: str, employee_id: str, roles: list[str]) -> tuple[bool, str]:
        status, body = app.handle("GET", f'/Users?filter=userName eq "{username}"')
        if status != 200:
            return False, body.get("detail", "")
        if body["totalResults"]:
            uid = body["Resources"][0]["id"]
            ops = [
                {"op": "replace", "path": "active", "value": True},
                {"op": "replace", "path": "roles", "value": roles},
            ]
            status, body = app.handle("PATCH", f"/Users/{uid}", {"schemas": [PATCH_SCHEMA], "Operations": ops})
            return status == 200, body.get("detail", "")
        payload = {"schemas": [USER_SCHEMA], "userName": username, "externalId": employee_id, "roles": roles}
        status, body = app.handle("POST", "/Users", payload)
        return status == 201, body.get("detail", "")

    def _scim_deactivate(self, app: ScimApp, username: str) -> tuple[bool, str]:
        status, body = app.handle("GET", f'/Users?filter=userName eq "{username}"')
        if status != 200:
            return False, body.get("detail", "")
        if not body["totalResults"] or not body["Resources"][0]["active"]:
            return True, "nothing to do"
        uid = body["Resources"][0]["id"]
        ops = [{"op": "replace", "path": "active", "value": False}, {"op": "replace", "path": "roles", "value": []}]
        status, body = app.handle("PATCH", f"/Users/{uid}", {"schemas": [PATCH_SCHEMA], "Operations": ops})
        return status == 200, body.get("detail", "")

    def _ensure_account(self, report: Report, app_name: str, username: str, employee_id: str, roles: list[str]):
        app = self.apps[app_name]
        if isinstance(app, ScimApp):
            self._retry(report, app_name, "provision", lambda: self._scim_ensure(app, username, employee_id, roles))
        else:

            def create() -> tuple[bool, str]:
                if username in app.accounts:
                    app.accounts[username]["active"] = True
                    app.accounts[username]["roles"] = roles
                    return True, "reactivated"
                pw = secrets.token_urlsafe(12)
                app.create_local(username, pw, roles)
                self.issued_local_passwords[username] = pw
                return True, "local account created"

            self._retry(report, app_name, "provision", create)

    def _remove_account(self, report: Report, app_name: str, username: str):
        app = self.apps[app_name]
        killed = app.kill_sessions(username)
        if killed:
            self.audit.record("lifecycle", "app.sessions_killed", app_name, "ok", f"count={killed}")
        if isinstance(app, ScimApp):
            self._retry(report, app_name, "deprovision", lambda: self._scim_deactivate(app, username))
        else:

            def disable() -> tuple[bool, str]:
                if not app.account_active(username):
                    return True, "nothing to do"
                app.disable_local(username)
                return True, "local disabled"

            self._retry(report, app_name, "deprovision", disable)

    # ---- joiner -------------------------------------------------------------------------------------
    def joiner(self, ev: HrEvent) -> Report:
        w = self.hr.workers[ev.employee_id]
        rep = Report(ev.employee_id, "joiner")
        uname = username_for(w.employee_id)
        u = self.directory.upsert(DirUser(f"usr-{w.employee_id}", w.employee_id, uname, w.department, w.country))
        plan = BIRTHRIGHT.get(w.department, {"groups": ["grp-employee_base"], "apps": ["mail", "chat"]})
        for g in plan["groups"]:
            self.directory.add_to_group(g, u.user_id)
        roles = [g.removeprefix("grp-") for g in plan["groups"]]
        for a in plan["apps"]:
            self._ensure_account(rep, a, uname, w.employee_id, roles)
        self.audit.record("lifecycle", "joiner", u.user_id, "ok" if not rep.exceptions else "flagged")
        rep.verified = self.verify_access(u.user_id, set(plan["apps"])) == []
        return rep

    # ---- mover --------------------------------------------------------------------------------------
    def mover(self, ev: HrEvent) -> Report:
        w = self.hr.workers[ev.employee_id]
        rep = Report(ev.employee_id, "mover")
        u = self.directory.by_employee(ev.employee_id)
        if u is None:
            raise AppError("mover for unknown identity")
        u.department = w.department
        plan = BIRTHRIGHT.get(w.department, {"groups": ["grp-employee_base"], "apps": ["mail", "chat"]})
        keep_groups = set(plan["groups"])
        for g in self.directory.groups_of(u.user_id) - keep_groups:
            self.directory.remove_from_group(g, u.user_id)
            self.audit.record("lifecycle", "group.removed", u.user_id, "ok", g)
        for g in keep_groups:
            self.directory.add_to_group(g, u.user_id)
        roles = [g.removeprefix("grp-") for g in plan["groups"]]
        new_apps = set(plan["apps"])
        for name, app in self.apps.items():
            has = app.account_active(u.username)
            if name in new_apps:
                self._ensure_account(rep, name, u.username, w.employee_id, roles)
            elif has:
                self._remove_account(rep, name, u.username)
        self.audit.record("lifecycle", "mover", u.user_id, "ok" if not rep.exceptions else "flagged", w.department)
        rep.verified = self.verify_access(u.user_id, new_apps) == []
        return rep

    # ---- leaver -------------------------------------------------------------------------------------
    def leaver(self, ev: HrEvent) -> Report:
        rep = Report(ev.employee_id, "leaver")
        u = self.directory.by_employee(ev.employee_id)
        if u is None:
            rep.exceptions.append(f"leaver:{ev.employee_id}: no directory identity")
            return rep
        self.directory.disable(u.user_id)
        self.audit.record("lifecycle", "identity.disabled", u.user_id)
        revoked = self.idp.revoke_user(u.user_id)
        self.audit.record("lifecycle", "idp.revoked", u.user_id, "ok", f"count={revoked}")
        for g in list(self.directory.groups_of(u.user_id)):
            self.directory.remove_from_group(g, u.user_id)
        return self._finish_leaver(rep, u)

    def _finish_leaver(self, rep: Report, u: DirUser) -> Report:
        for name in self.apps:
            self._remove_account(rep, name, u.username)
        problems = self.verify_access(u.user_id, set())
        rep.verified = not problems
        for p in problems:
            msg = f"leaver:{rep.employee_id}: verification failed: {p}"
            if msg not in rep.exceptions:
                rep.exceptions.append(msg)
                self.open_exceptions.append(msg)
        self.audit.record("lifecycle", "leaver", u.user_id, "ok" if rep.verified else "flagged")
        if rep.verified:
            self.pending_leavers.discard(rep.employee_id)
        else:
            self.pending_leavers.add(rep.employee_id)
        return rep

    def reconcile(self) -> list[Report]:
        """Re-run unfinished leavers (for example after an app outage). Clears their exceptions on success."""
        out = []
        for eid in sorted(self.pending_leavers):
            u = self.directory.by_employee(eid)
            rep = self._finish_leaver(Report(eid, "leaver-reconcile"), u)
            if rep.verified:
                tag = f"leaver:{eid}:"
                self.open_exceptions = [e for e in self.open_exceptions if not e.startswith(tag)]
                self.audit.record("lifecycle", "leaver.reconciled", u.user_id)
            out.append(rep)
        return out

    # ---- read-back verification ---------------------------------------------------------------------
    def verify_access(self, user_id: str, expected_apps: set[str]) -> list[str]:
        """Read every app back. Returns a list of mismatches (empty = verified)."""
        u = self.directory.users[user_id]
        problems = []
        for name, app in self.apps.items():
            if isinstance(app, ScimApp) and app.down:
                if name in expected_apps or not expected_apps:
                    problems.append(f"{name}: could not read back")
                continue
            active = app.account_active(u.username)
            if name in expected_apps and not active:
                problems.append(f"{name}: expected active account missing")
            if name not in expected_apps and active:
                problems.append(f"{name}: account still active")
            if not expected_apps and app.live_sessions(u.username):
                problems.append(f"{name}: live sessions remain")
        return problems
