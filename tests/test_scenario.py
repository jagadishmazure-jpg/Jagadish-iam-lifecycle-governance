"""The headline story and the demo numbers."""

from iamlc.cli import main, table


def test_headline_full_lifecycle_blocks_forgotten_local_account(demo):
    assert demo["full"]["headline_local_login_succeeded"] is False
    assert demo["full"]["headline_rows_exported"] == 0


def test_headline_naive_offboarding_leaks(demo):
    assert demo["naive"]["headline_local_login_succeeded"] is True
    assert demo["naive"]["headline_rows_exported"] == 4200


def test_privilege_creep_only_in_naive(demo):
    assert demo["naive"]["privilege_creep"] and not demo["full"]["privilege_creep"]


def test_idp_disable_alone_is_not_enough(demo):
    for mode in ("full", "naive"):
        assert demo[mode]["after_idp_disable_app_session_alive"]
        assert demo[mode]["after_idp_disable_access_token_accepted"]
        assert demo[mode]["after_idp_disable_new_signin"] == "refused"
    assert demo["full"]["kofi_session_after_leaver"] is False
    assert demo["naive"]["kofi_session_after_leaver"] is True


def test_outage_flagged_then_reconciled(demo):
    f = demo["full"]
    assert f["leavers_flagged_during_outage"] == 3
    assert f["leavers_verified_after_reconcile"] == 3
    assert f["open_exceptions"] == 0


def test_orphans(demo):
    assert len(demo["full"]["orphans"]) == 2
    assert len(demo["naive"]["orphans"]) > len(demo["full"]["orphans"])


def test_sod_and_review(demo):
    f = demo["full"]
    assert f["sod_blocked_requests"] == 1 and f["sod_conflicts_live"] == 1 and f["sod_conflicts_after_review"] == 0


def test_misc_numbers(demo):
    f = demo["full"]
    assert f["workers_hired"] == 40 and f["accounts_provisioned"] > 100
    assert f["jit_expired"] == 1 and f["recorded_commands"] == 1
    assert f["impossible_travel_decision"] == "step_up" and f["vpn_jump_risk"] == "low"
    assert f["break_glass_alerts"] == 3 and f["audit_chain_valid"]
    assert f["partner_menu_write"] == "denied" and f["access_token_as_login"] == "refused"
    assert f["machine_other_service"] == "denied"


def test_zero_trust_decisions(demo):
    assert demo["full"]["zero_trust_decisions"] == {
        "addr_same": "allow",
        "addr_other": "deny",
        "addr_unmanaged": "deny",
        "refund30": "allow",
        "refund80": "deny",
        "approve_payment": "deny",
    }


def test_demo_deterministic():
    from iamlc.scenario import run

    a, b = run(), run()
    assert a == b


def test_table_and_cli(demo, capsys):
    t = table(demo["full"], demo["naive"])
    assert t.startswith("| Measure")
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "Forgotten helpdesk login works 90 days later | true | false" in out


def test_cli_json(capsys):
    import json

    assert main(["demo", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"full", "naive"}


def test_audit_has_no_raw_emails(demo):
    from iamlc.world import build

    w = build()
    assert "@" not in w.audit.to_jsonl()
