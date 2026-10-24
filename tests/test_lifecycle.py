import pytest

from iamlc.apps import AppError
from iamlc.hr import HrEvent, Worker
from iamlc.lifecycle import BIRTHRIGHT, MAX_ATTEMPTS


def uname(w, eid):
    return w.directory.by_employee(eid).username


def support_ids(w):
    return [e for e, k in sorted(w.hr.workers.items()) if k.department == "Support"]


def test_joiner_gets_birthright_accounts(world):
    eid = "E1001"
    for app in BIRTHRIGHT["Support"]["apps"]:
        assert world.apps[app].account_active(uname(world, eid))
    assert not world.apps["payouts"].account_active(uname(world, eid))


def test_joiner_groups(world):
    u = world.directory.by_employee("E1001")
    assert world.directory.groups_of(u.user_id) == {"grp-employee_base", "grp-support_agent"}


def test_every_worker_has_directory_identity(world):
    assert all(world.directory.by_employee(e) for e in world.hr.workers)


def test_hr_rejects_duplicate_and_bad_transfer(world):
    with pytest.raises(ValueError):
        world.hr.hire(Worker("E1001", "x", "x@zestlane.example", "IT", "t", None, "CA"))
    world.hr.terminate("E1002")
    with pytest.raises(ValueError):
        world.hr.transfer("E1002", "IT", "t")


def test_mover_removes_old_access_no_privilege_creep(world):
    eid = "E1001"
    world.hr.transfer(eid, "Payments", "Analyst")
    rep = world.engine.process()[0]
    u = world.directory.by_employee(eid)
    assert rep.verified
    assert "grp-support_agent" not in world.directory.groups_of(u.user_id)
    assert not world.apps["orders"].account_active(u.username)
    assert not world.apps["helpdesk"].account_active(u.username)
    assert world.apps["payouts"].account_active(u.username)


def test_mover_kills_sessions_in_removed_apps(world):
    u = world.directory.by_employee("E1001")
    sid = world.apps["orders"].sso_login(u.username)
    world.hr.transfer("E1001", "Payments", "Analyst")
    world.engine.process()
    assert world.apps["orders"].session_user(sid) is None


def test_mover_drops_jit_extra_group(world):
    u = world.directory.by_employee("E1001")
    world.directory.add_to_group("grp-refund_investigator", u.user_id)
    world.hr.transfer("E1001", "Payments", "Analyst")
    world.engine.process()
    assert "grp-refund_investigator" not in world.directory.groups_of(u.user_id)


def test_mover_back_reactivates(world):
    world.hr.transfer("E1001", "Payments", "Analyst")
    world.engine.process()
    world.hr.transfer("E1001", "Support", "Agent")
    rep = world.engine.process()[0]
    assert rep.verified and world.apps["helpdesk"].account_active(uname(world, "E1001"))


def test_mover_unknown_identity(world):
    world.hr.outbox.append(HrEvent("transfer", "E9999"))
    world.hr.workers["E9999"] = world.hr.workers["E1001"]
    with pytest.raises(AppError):
        world.engine.process()


def test_leaver_disables_everything(world):
    eid = support_ids(world)[0]
    world.hr.terminate(eid)
    rep = world.engine.process()[0]
    u = world.directory.by_employee(eid)
    assert rep.verified and not u.enabled
    assert all(not a.account_active(u.username) for a in world.apps.values())
    assert world.directory.groups_of(u.user_id) == set()


def test_leaver_disables_non_scim_local_account(world):
    eid = support_ids(world)[0]
    world.hr.terminate(eid)
    world.engine.process()
    assert world.apps["helpdesk"].accounts[uname(world, eid)]["active"] is False


def test_transient_failure_retried(world):
    world.apps["mail"].fail_next = 2
    world.hr.terminate("E1001")
    rep = world.engine.process()[0]
    assert rep.verified and rep.retried == 1
    assert world.audit.find(action="deprovision.retried")


def test_permanent_failure_flagged_not_dropped(world):
    world.apps["mail"].fail_next = MAX_ATTEMPTS
    world.hr.terminate("E1001")
    rep = world.engine.process()[0]
    assert not rep.verified
    assert any("mail" in e for e in world.engine.open_exceptions)
    assert world.audit.find(action="deprovision.failed", outcome="flagged")
    assert world.apps["mail"].account_active(uname(world, "E1001"))


def test_reconcile_clears_after_recovery(world):
    world.apps["mail"].down = True
    world.hr.terminate("E1001")
    world.engine.process()
    assert "E1001" in world.engine.pending_leavers
    world.apps["mail"].down = False
    recon = world.engine.reconcile()
    assert recon[0].verified and world.engine.open_exceptions == []
    assert not world.engine.pending_leavers


def test_local_connector_down_flags_leaver(world):
    world.apps["helpdesk"].connector_enabled = False
    world.hr.terminate("E1001")
    rep = world.engine.process()[0]
    assert not rep.verified
    assert any("helpdesk" in e for e in rep.exceptions)


def test_leaver_without_identity_reported(world):
    world.hr.outbox.append(HrEvent("terminate", "E7777"))
    rep = world.engine.process()[0]
    assert rep.exceptions and not rep.verified


def test_backoff_is_exponential(world):
    world.apps["mail"].fail_next = 3
    world.hr.terminate("E1001")
    world.engine.process()
    assert world.engine.backoff_log[:3] == [1, 2, 4]


def test_joiner_flaky_app_retried(world):
    world.apps["chat"].fail_next = 1
    world.hr.hire(Worker("E2001", "New Person", "e2001@zestlane.example", "IT", "Admin", None, "CA"))
    rep = world.engine.process()[0]
    assert rep.verified and rep.retried == 1
