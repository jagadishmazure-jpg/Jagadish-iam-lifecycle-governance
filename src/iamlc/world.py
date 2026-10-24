"""Builds the fictional company: Zestlane, a food-delivery platform. All people are invented."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .apps import LocalAccountApp, ScimApp
from .audit import AuditLog
from .clock import Clock
from .directory import Directory, DirUser
from .hr import HrSystem, Worker
from .idp import IdentityProvider
from .lifecycle import LifecycleEngine
from .pam import Pam
from .siem import Siem

FIRST = ["Mira", "Tomas", "Ines", "Kofi", "Lena", "Arjun", "Yuki", "Rafa", "Noor", "Elif", "Bram", "Zara"]
LAST = ["Okafor", "Lind", "Varga", "Mensah", "Duarte", "Iyer", "Sato", "Quinn", "Haddad", "Kaya", "Vos", "Reyes"]
DEPTS = ["Support", "Support", "Support", "Payments", "Vendor Ops", "Finance", "IT"]
COUNTRIES = ["CA", "IN", "GB", "DE"]
ORIGIN = "https://login.zestlane.example"
ORDERS_REDIRECT = "https://orders.zestlane.example/callback"


@dataclass
class World:
    clock: Clock
    hr: HrSystem
    directory: Directory
    idp: IdentityProvider
    apps: dict
    audit: AuditLog
    engine: LifecycleEngine
    pam: Pam
    siem: Siem
    service_accounts: set[str] = field(default_factory=set)
    provisioned_at_hire: int = 0


def build(seed: int = 7, headcount: int = 40) -> World:
    rng = random.Random(seed)
    clock = Clock()
    hr, directory, audit = HrSystem(), Directory(), AuditLog(clock)
    idp = IdentityProvider(clock, directory)
    idp.register("orders", "orders-secret", (ORDERS_REDIRECT,), allowed_scopes=frozenset({"openid", "profile"}))
    idp.register("payroll-saml", "unused", (), kind="saml")
    apps = {
        "mail": ScimApp("mail", clock),
        "chat": ScimApp("chat", clock),
        "orders": ScimApp("orders", clock),
        "payouts": ScimApp("payouts", clock),
        "vendors": ScimApp("vendors", clock),
        "helpdesk": LocalAccountApp("helpdesk", clock),
    }
    engine = LifecycleEngine(hr, directory, idp, apps, audit)
    pam = Pam(clock, directory, audit)
    w = World(clock, hr, directory, idp, apps, audit, engine, pam, Siem(vpn_egress={"203.0.113.10"}))
    for i in range(headcount):
        eid = f"E{1001 + i}"
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        dept = "Support" if i == 0 else rng.choice(DEPTS)
        hr.hire(
            Worker(eid, name, f"{eid.lower()}@zestlane.example", dept, f"{dept} staff", "E1040", rng.choice(COUNTRIES))
        )
    joiner_reports = engine.process()
    w.provisioned_at_hire = sum(1 for r in joiner_reports for s in r.steps if s.action == "provision" and s.ok)
    for wk in hr.workers.values():
        u = directory.by_employee(wk.employee_id)
        mgr = directory.by_employee(wk.manager_id or "")
        if u and mgr and mgr.user_id != u.user_id:
            pam.managers[u.user_id] = mgr.user_id
    # a registered service account (not an orphan) and two leftovers from before this system existed
    apps["vendors"].handle(
        "POST", "/Users", {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "svc-reporting"}
    )
    w.service_accounts.add("svc-reporting")
    apps["vendors"].handle(
        "POST", "/Users", {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "ue0777"}
    )
    apps["helpdesk"].create_local("ue0778", "legacy-temp-pass", ["support_agent"])
    # break-glass: two cloud-only admin accounts outside normal SSO
    for bg in ("bg-admin-1", "bg-admin-2"):
        directory.upsert(DirUser(bg, "-", bg, "IT", "CA", kind="break_glass"))
        pam.register_break_glass(bg)
    return w
