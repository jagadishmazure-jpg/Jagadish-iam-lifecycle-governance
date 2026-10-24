"""End-to-end story and the numbers the demo prints. Everything here runs offline and deterministically
(token values are random, counts are not).

Mira (E1001) joins Support, moves to Payments, borrows a refund-archive role for two hours, then leaves.
Run twice: once with a naive offboarding (mailbox and directory only) and once with the full lifecycle.
"""

from __future__ import annotations

from .apps import AppError
from .authn import RECOVERY_METHODS, Passkey, PushFatigueDetector, RecoveryPolicy
from .authz import RequestContext, decide
from .clock import DAY, HOUR, MINUTE
from .directory import DirUser
from .governance import build_campaign, find_orphans, sod_report
from .governance import decide as review
from .idp import IdpError
from .oauth import PLATFORM_API, PartnerApi, login_with_access_token
from .other_identities import SecretError, SecretsManager
from .siem import SignIn
from .tokens import TokenError, verify
from .world import ORDERS_REDIRECT, ORIGIN, World, build

LEAKED_ROWS = 4200  # rows a stolen session would try to export


def _first(w: World, dept: str, skip: set[str]) -> str:
    return next(
        e for e, wk in sorted(w.hr.workers.items()) if wk.department == dept and wk.status == "active" and e not in skip
    )


def oidc_login(w: World, user_id: str) -> tuple[str, dict]:
    """Password + passkey at the IdP, code flow to the orders app, app session opened."""
    pk = Passkey(ORIGIN)
    proof = pk.sign(ORIGIN, "chal-1")
    if not pk.verify(ORIGIN, "chal-1", proof):
        raise IdpError("passkey check failed")
    s = w.idp.authenticate(user_id, ["password", "passkey"])
    code = w.idp.authorize("orders", ORDERS_REDIRECT, s.sid, {"openid", "profile"}, "st", "n1")
    toks = w.idp.exchange(code, "orders", "orders-secret", ORDERS_REDIRECT)
    claims = verify(
        toks["id_token"], w.idp.key, now=w.clock.now, audience="orders", issuer="https://idp.zestlane.example"
    )
    if claims["nonce"] != "n1":
        raise IdpError("nonce mismatch")
    uname = w.directory.users[user_id].username
    return w.apps["orders"].sso_login(uname), toks


def naive_offboarding(w: World, eid: str) -> None:
    """What the story's company did: disable the directory user and the mailbox. Nothing else."""
    u = w.directory.by_employee(eid)
    w.directory.disable(u.user_id)
    mail = w.apps["mail"].find(u.username)
    if mail:
        mail["active"] = False


def attacker_three_months_later(w: World, eid: str, password: str) -> tuple[bool, int]:
    w.clock.advance(90 * DAY)
    uname = w.directory.by_employee(eid).username
    try:
        sid = w.apps["helpdesk"].local_login(uname, password)
    except AppError:
        w.siem.ingest(SignIn(uname, w.clock.now, 52.5, 13.4, "198.51.100.7", outcome="disabled"))
        w.audit.record(uname, "helpdesk.local_login", "helpdesk", "denied", "account disabled")
        return False, 0
    rows = w.apps["helpdesk"].export_customers(sid, LEAKED_ROWS)
    w.audit.record(uname, "helpdesk.export", "helpdesk", "ok", f"rows={rows}")
    return True, rows


def run(naive: bool = False) -> dict:
    w = build()
    m: dict = {"mode": "naive" if naive else "full"}
    m["workers_hired"] = len(w.hr.workers)
    m["accounts_provisioned"] = w.provisioned_at_hire
    mira = "E1001"
    mira_uid = w.directory.by_employee(mira).user_id
    mira_pw = w.engine.issued_local_passwords[w.directory.users[mira_uid].username]

    # --- sign-in, SSO, federation ---------------------------------------------------------------------
    sid, toks = oidc_login(w, mira_uid)
    saml = w.idp.saml_assertion("payroll-saml", w.idp.authenticate(mira_uid, ["password", "totp"]).sid)
    m["saml_subject_ok"] = w.idp.verify_saml("payroll-saml", saml) == mira_uid

    # --- zero-trust checks on Mira's requests ---------------------------------------------------------
    roles = w.pam.roles_of(mira_uid)
    country = w.directory.users[mira_uid].country
    base = {"account_enabled": True, "session_valid": True, "assurance": 4}
    checks = [
        ("customer_address:read", {"country": country}, {**base, "device_managed": True}),
        ("customer_address:read", {"country": "ZZ"}, {**base, "device_managed": True}),
        ("customer_address:read", {"country": country}, {**base, "device_managed": False}),
        ("refunds:issue", {"amount": 30}, base),
        ("refunds:issue", {"amount": 80}, base),
        ("payment:approve", {}, {**base, "device_managed": True}),
    ]
    effects = [decide(RequestContext(mira_uid, a, roles, {"country": country}, r, e)).effect for a, r, e in checks]
    m["zero_trust_decisions"] = dict(
        zip(
            ["addr_same", "addr_other", "addr_unmanaged", "refund30", "refund80", "approve_payment"],
            effects,
            strict=True,
        )
    )

    # --- push fatigue and recovery -------------------------------------------------------------------
    pf = PushFatigueDetector(w.clock)
    for outcome in ["ignored", "denied", "ignored", "approved"]:
        trusted = pf.record("usr-E1005", outcome)
        w.clock.advance(MINUTE)
    m["push_flood_flagged"] = "usr-E1005" in pf.flagged
    m["push_flood_late_approval_trusted"] = trusted
    rp = RecoveryPolicy()
    m["recovery_allowed"] = {k: rp.allowed(["password", "passkey"], v)[0] for k, v in RECOVERY_METHODS.items()}

    # --- mover (with a flaky payouts app) ------------------------------------------------------------
    w.apps["payouts"].fail_next = 2
    if naive:
        w.hr.transfer(mira, "Payments", "Payments analyst")
        w.hr.drain()
        w.directory.add_to_group("grp-payments_analyst", mira_uid)
    else:
        w.hr.transfer(mira, "Payments", "Payments analyst")
        mover_rep = w.engine.process()[0]
        m["mover_retries"] = mover_rep.retried
    roles_after = w.pam.roles_of(mira_uid)
    m["mira_roles_after_move"] = sorted(roles_after)
    m["privilege_creep"] = "support_agent" in roles_after or w.apps["helpdesk"].account_active(
        w.directory.users[mira_uid].username
    )

    # --- JIT elevation with recording ----------------------------------------------------------------
    req = w.pam.request(mira_uid, "refund_investigator", "check an old refund on order 55120", 2 * HOUR)
    w.pam.approve(req.req_id, w.pam.managers[mira_uid])
    w.pam.approve(req.req_id, "owner-support-tools")
    m["jit_status"] = req.status
    if req.status == "active":
        w.pam.record_command(req.req_id, "open refund 55120")
        w.clock.advance(2 * HOUR)
        m["jit_expired"] = w.pam.sweep()
    m["recorded_commands"] = sum(len(v) for v in w.pam.recordings.values())

    # --- SoD: a Vendor Ops user asks for payment approval --------------------------------------------
    vend = w.directory.by_employee(_first(w, "Vendor Ops", set())).user_id
    r1 = w.pam.request(vend, "payments_approver", "cover month-end approvals", 4 * HOUR)
    w.pam.approve(r1.req_id, w.pam.managers[vend])
    w.pam.approve(r1.req_id, "owner-payments")
    it = w.directory.by_employee(_first(w, "IT", set())).user_id
    r2 = w.pam.request(it, "payments_approver", "backfill during audit week", 4 * HOUR)
    w.pam.approve(r2.req_id, w.pam.managers[it])
    w.pam.approve(r2.req_id, "owner-payments", sod_exception_by="ciso-office")
    m["sod_blocked_requests"] = sum(1 for r in w.pam.requests.values() if r.status == "denied")
    m["sod_conflicts_live"] = len(sod_report(w.directory))

    # --- access review -------------------------------------------------------------------------------
    camp = build_campaign(w.directory, w.pam.managers)
    for item in camp.items:
        if item.role == "payments_approver" and item.user_id == it:
            review(camp, item.reviewer, it, "payments_approver", "revoke", w.directory, w.audit)
    m["review_items"] = len(camp.items)
    m["review_high_risk"] = sum(1 for i in camp.items if i.high_risk)
    m["review_revoked"] = camp.revoked
    m["sod_conflicts_after_review"] = len(sod_report(w.directory))

    # --- SIEM ----------------------------------------------------------------------------------------
    t = w.clock.now
    w.siem.ingest(SignIn("usr-E1001", t, 43.65, -79.38, "192.0.2.1"))
    risk_travel = w.siem.ingest(SignIn("usr-E1001", t + 20 * MINUTE, 50.11, 8.68, "198.51.100.9"))
    w.siem.ingest(SignIn("usr-E1002", t, 43.65, -79.38, "192.0.2.2"))
    risk_vpn = w.siem.ingest(SignIn("usr-E1002", t + 15 * MINUTE, 51.51, -0.13, "203.0.113.10"))
    m["impossible_travel_risk"] = risk_travel
    m["impossible_travel_decision"] = decide(
        RequestContext(
            mira_uid, "payouts:view", w.pam.roles_of(mira_uid), env={**base, "assurance": 1, "risk": risk_travel}
        )
    ).effect
    m["vpn_jump_risk"] = risk_vpn

    # --- the IdP-disable-is-not-enough check, on a second Support worker ------------------------------
    kofi_eid = _first(w, "Support", {mira})
    kofi = w.directory.by_employee(kofi_eid).user_id
    k_sid, k_toks = oidc_login(w, kofi)
    w.directory.disable(kofi)
    m["after_idp_disable_app_session_alive"] = w.apps["orders"].session_user(k_sid) is not None
    try:
        verify(
            k_toks["access_token"], w.idp.key, now=w.clock.now, audience="orders", issuer="https://idp.zestlane.example"
        )
        m["after_idp_disable_access_token_accepted"] = True
    except TokenError:
        m["after_idp_disable_access_token_accepted"] = False
    try:
        w.idp.authenticate(kofi, ["password", "passkey"])
        m["after_idp_disable_new_signin"] = "allowed"
    except IdpError:
        m["after_idp_disable_new_signin"] = "refused"
    w.directory.users[kofi].enabled = True  # undo; the full leaver below does it properly

    # --- leavers -------------------------------------------------------------------------------------
    vendor_leaver = _first(w, "Vendor Ops", {mira})
    leavers = [mira, kofi_eid, vendor_leaver]
    tokens_before = sum(1 for r in w.idp.refresh.values() if not r["revoked"])
    if naive:
        for e in leavers:
            w.hr.terminate(e)
            naive_offboarding(w, e)
        w.hr.drain()
    else:
        w.apps["vendors"].down = True  # this app stays down: the leaver must flag it, not pretend
        for e in leavers:
            w.hr.terminate(e)
        reps = w.engine.process()
        m["leavers_flagged_during_outage"] = sum(1 for r in reps if not r.verified)
        m["exceptions_during_outage"] = len(w.engine.open_exceptions)
        m["orphans_during_outage"] = len(find_orphans(w.hr, w.apps, w.service_accounts))
        w.apps["vendors"].down = False
        recon = w.engine.reconcile()
        m["leavers_verified_after_reconcile"] = sum(1 for r in recon if r.verified)
        m["accounts_deprovisioned"] = sum(
            1
            for r in reps + recon
            for st in r.steps
            if st.action == "deprovision" and st.ok and st.detail != "nothing to do"
        )
    m["leavers"] = len(leavers)
    m["refresh_tokens_revoked"] = tokens_before - sum(1 for r in w.idp.refresh.values() if not r["revoked"])
    m["kofi_session_after_leaver"] = w.apps["orders"].session_user(k_sid) is not None
    m["kofi_token_revoked_flag"] = w.idp.is_revoked({"sub": kofi, "iat": w.clock.now - 1})
    m["open_exceptions"] = len(w.engine.open_exceptions)
    m["retries_logged"] = len(w.audit.find(action="provision.retried")) + len(
        w.audit.find(action="deprovision.retried")
    )

    # --- orphans -------------------------------------------------------------------------------------
    orphans = find_orphans(w.hr, w.apps, w.service_accounts)
    m["orphans"] = orphans

    # --- break glass ---------------------------------------------------------------------------------
    w.pam.break_glass_signin("bg-admin-1", "IdP outage drill", idp_up=False)
    w.pam.break_glass_signin("bg-admin-2", "unplanned use", idp_up=True)
    m["break_glass_alerts"] = len(w.pam.alerts)

    # --- partner delegated access ---------------------------------------------------------------------
    w.directory.upsert(DirUser("own-501", "-", "owner501", "Partner", "CA", kind="guest"))
    w.idp.register(
        "bookkeeper",
        "bk-secret",
        ("https://books.example/cb",),
        kind="oauth_partner",
        allowed_scopes=frozenset({"sales:read"}),
        resource=PLATFORM_API,
    )
    api = PartnerApi(w.idp, {"own-501": [812, 790, 905]})
    s = w.idp.authenticate("own-501", ["password", "totp"])
    code = w.idp.authorize("bookkeeper", "https://books.example/cb", s.sid, {"sales:read"}, "s", "n")
    ptoks = w.idp.exchange(code, "bookkeeper", "bk-secret", "https://books.example/cb")
    m["partner_sales_rows"] = len(api.read_sales(ptoks["access_token"]))
    m["partner_got_id_token"] = "id_token" in ptoks
    try:
        api.write_menu(ptoks["access_token"])
        m["partner_menu_write"] = "allowed"
    except TokenError:
        m["partner_menu_write"] = "denied"
    try:
        login_with_access_token(ptoks["access_token"])
    except IdpError:
        m["access_token_as_login"] = "refused"

    # --- machine identity ----------------------------------------------------------------------------
    sm = SecretsManager(w.clock)
    sm.put("payments-db", "not-a-real-secret", {"svc-payouts"})
    lease = sm.lease("svc-payouts", "payments-db")
    m["machine_lease_ok"] = sm.read("svc-payouts", lease) == "not-a-real-secret"
    try:
        sm.lease("svc-reports", "payments-db")
        m["machine_other_service"] = "allowed"
    except SecretError:
        m["machine_other_service"] = "denied"

    # --- headline: three months later ----------------------------------------------------------------
    ok, rows = attacker_three_months_later(w, mira, mira_pw)
    m["headline_local_login_succeeded"] = ok
    m["headline_rows_exported"] = rows
    m["siem_alerts"] = len(w.siem.alerts)
    m["siem_vpn_notes"] = len(w.siem.notes)
    m["audit_events"] = len(w.audit.events)
    m["audit_chain_valid"] = w.audit.verify_chain()
    return m
