import pytest

from iamlc.clock import HOUR
from iamlc.pam import MAX_JIT, RequestError
from iamlc.sod import RULES, conflicts, would_conflict


def mira(w):
    return w.directory.by_employee("E1001").user_id


def move_mira(w):
    w.hr.transfer("E1001", "Payments", "Analyst")
    w.engine.process()


def approve_both(w, r, **kw):
    w.pam.approve(r.req_id, w.pam.managers[r.user_id])
    return w.pam.approve(
        r.req_id, {"refund_investigator": "owner-support-tools", "payments_approver": "owner-payments"}[r.role], **kw
    )


def test_jit_grant_and_expiry(world):
    move_mira(world)
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", 2 * HOUR)
    approve_both(world, r)
    assert r.status == "active"
    assert "refund_investigator" in world.pam.roles_of(mira(world))
    world.clock.advance(2 * HOUR)
    assert world.pam.sweep() == 1
    assert "refund_investigator" not in world.pam.roles_of(mira(world))


def test_needs_both_approvals(world):
    move_mira(world)
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    world.pam.approve(r.req_id, "owner-support-tools")
    assert r.status == "pending"


def test_self_and_stranger_approval_refused(world):
    move_mira(world)
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    with pytest.raises(RequestError):
        world.pam.approve(r.req_id, mira(world))
    with pytest.raises(RequestError):
        world.pam.approve(r.req_id, "usr-E1010")


@pytest.mark.parametrize(
    "role,reason,dur",
    [
        ("support_agent", "a fine long reason", HOUR),
        ("refund_investigator", "short", HOUR),
        ("refund_investigator", "a fine long reason", 0),
        ("refund_investigator", "a fine long reason", MAX_JIT + 1),
    ],
)
def test_request_validation(world, role, reason, dur):
    with pytest.raises(RequestError):
        world.pam.request(mira(world), role, reason, dur)


def test_disabled_user_cannot_request(world):
    world.directory.disable(mira(world))
    with pytest.raises(RequestError):
        world.pam.request(mira(world), "refund_investigator", "a fine long reason", HOUR)


def test_session_recording_and_expired_session(world):
    move_mira(world)
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    approve_both(world, r)
    world.pam.record_command(r.req_id, "open refund 55120")
    assert len(world.pam.recordings[r.req_id]) == 1
    assert world.audit.find(action="pam.command")
    world.clock.advance(HOUR)
    with pytest.raises(RequestError):
        world.pam.record_command(r.req_id, "export all")


def test_privilege_creep_causes_sod_block(world):
    # Mira still in Support (never moved): refund issue + archive read conflict
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    approve_both(world, r)
    assert r.status == "denied"
    assert world.audit.find(action="access.sod_blocked")


def test_sod_exception_is_logged(world):
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    approve_both(world, r, sod_exception_by="risk-office")
    assert r.status == "active" and r.sod_exception
    assert world.audit.find(action="sod.exception")


def test_not_pending_cannot_be_approved_again(world):
    move_mira(world)
    r = world.pam.request(mira(world), "refund_investigator", "check old refund 55120", HOUR)
    approve_both(world, r)
    with pytest.raises(RequestError):
        world.pam.approve(r.req_id, "owner-support-tools")


@pytest.mark.parametrize(
    "roles,ids",
    [
        ({"vendor_admin", "payments_approver"}, {"SOD-1"}),
        ({"support_agent", "refund_investigator"}, {"SOD-2"}),
        ({"directory_admin", "payments_approver"}, {"SOD-3"}),
        ({"vendor_admin", "payments_approver", "directory_admin"}, {"SOD-1", "SOD-3"}),
        ({"support_agent", "payments_analyst"}, set()),
    ],
)
def test_sod_rules(roles, ids):
    assert {r.rule_id for r in conflicts(roles)} == ids


def test_would_conflict_only_new():
    assert [r.rule_id for r in would_conflict({"vendor_admin"}, "payments_approver")] == ["SOD-1"]
    assert would_conflict({"vendor_admin", "payments_approver"}, "employee_base") == []


def test_rules_have_reasons():
    assert all(r.why for r in RULES) and len(RULES) >= 3


def test_break_glass_alerts(world):
    world.pam.break_glass_signin("bg-admin-1", "IdP outage", idp_up=False)
    assert len(world.pam.alerts) == 1
    world.pam.break_glass_signin("bg-admin-2", "testing", idp_up=True)
    assert len(world.pam.alerts) == 3
    assert world.audit.find(action="breakglass.signin", outcome="alert")


def test_break_glass_only_registered(world):
    with pytest.raises(RequestError):
        world.pam.break_glass_signin(mira(world), "x", idp_up=False)


def test_break_glass_outside_sso(world):
    assert world.directory.users["bg-admin-1"].kind == "break_glass"
