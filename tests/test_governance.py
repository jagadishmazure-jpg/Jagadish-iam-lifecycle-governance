import pytest

from iamlc.governance import build_campaign, decide, find_orphans, sod_report


def test_campaign_skips_base_and_flags_high_risk(world):
    c = build_campaign(world.directory, world.pam.managers)
    assert all(i.role != "employee_base" for i in c.items)
    assert any(i.high_risk for i in c.items) and any(not i.high_risk for i in c.items)


def test_reviewer_rules(world):
    c = build_campaign(world.directory, world.pam.managers)
    item = c.items[0]
    with pytest.raises(PermissionError):
        decide(c, "someone-else", item.user_id, item.role, "keep", world.directory, world.audit)
    with pytest.raises(ValueError):
        decide(c, item.reviewer, item.user_id, item.role, "maybe", world.directory, world.audit)
    with pytest.raises(KeyError):
        decide(c, item.reviewer, "nobody", item.role, "keep", world.directory, world.audit)


def test_revoke_removes_group(world):
    c = build_campaign(world.directory, world.pam.managers)
    item = next(i for i in c.items if i.reviewer != i.user_id)
    decide(c, item.reviewer, item.user_id, item.role, "revoke", world.directory, world.audit)
    assert f"grp-{item.role}" not in world.directory.groups_of(item.user_id)
    assert c.revoked == 1


def test_self_certification_blocked(world):
    c = build_campaign(world.directory, {"usr-E1001": "usr-E1001"})
    item = next(i for i in c.items if i.user_id == "usr-E1001")
    with pytest.raises(PermissionError):
        decide(c, "usr-E1001", "usr-E1001", item.role, "keep", world.directory, world.audit)


def test_orphans_seeded(world):
    assert find_orphans(world.hr, world.apps, world.service_accounts) == ["helpdesk:ue0778", "vendors:ue0777"]


def test_service_account_not_orphan(world):
    assert all("svc-reporting" not in o for o in find_orphans(world.hr, world.apps, world.service_accounts))
    assert any("svc-reporting" in o for o in find_orphans(world.hr, world.apps, set()))


def test_naive_leaver_creates_orphans(world):
    from iamlc.scenario import naive_offboarding

    world.hr.terminate("E1001")
    naive_offboarding(world, "E1001")
    found = find_orphans(world.hr, world.apps, world.service_accounts)
    assert "helpdesk:ue1001" in found and "orders:ue1001" in found


def test_sod_report_clean_at_start(world):
    assert sod_report(world.directory) == []
