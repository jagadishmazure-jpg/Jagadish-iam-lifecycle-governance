"""Command line: `iamlc demo` prints the numbers from a real run, naive offboarding vs full lifecycle."""

from __future__ import annotations

import argparse
import json
import sys

from .scenario import run

ROWS = [
    ("workers_hired", "Workers hired from HR"),
    ("accounts_provisioned", "Accounts provisioned at hire (SCIM + connector)"),
    ("privilege_creep", "Privilege creep after the move"),
    ("mover_retries", "Provisioning calls that needed a retry"),
    ("jit_status", "Mira's 2-hour refund-archive request"),
    ("jit_expired", "Elevations removed by the expiry sweep"),
    ("recorded_commands", "Privileged commands recorded"),
    ("sod_blocked_requests", "Requests blocked by segregation of duties"),
    ("sod_conflicts_live", "SoD conflicts live before the review"),
    ("sod_conflicts_after_review", "SoD conflicts live after the review"),
    ("review_items", "Access review items"),
    ("review_revoked", "Access revoked in the review"),
    ("after_idp_disable_app_session_alive", "App session alive after IdP disable only"),
    ("after_idp_disable_access_token_accepted", "Access token accepted after IdP disable only"),
    ("after_idp_disable_new_signin", "New sign-in after IdP disable"),
    ("leavers", "Leavers"),
    ("leavers_flagged_during_outage", "Leavers flagged while one app was down"),
    ("leavers_verified_after_reconcile", "Leavers verified after reconcile"),
    ("accounts_deprovisioned", "Accounts deactivated for leavers"),
    ("refresh_tokens_revoked", "Refresh tokens revoked"),
    ("kofi_session_after_leaver", "Leaver's app session alive after offboarding"),
    ("open_exceptions", "Open exceptions at the end"),
    ("orphans", "Orphan accounts found against HR"),
    ("impossible_travel_decision", "Impossible travel (unknown IP) decision"),
    ("vpn_jump_risk", "Same jump via known VPN egress, risk"),
    ("break_glass_alerts", "Break-glass alerts"),
    ("partner_menu_write", "Partner token used outside its scope"),
    ("headline_local_login_succeeded", "Forgotten helpdesk login works 90 days later"),
    ("headline_rows_exported", "Customer rows exported by that login"),
    ("audit_events", "Audit events written"),
    ("audit_chain_valid", "Audit hash chain intact"),
]


def _fmt(v) -> str:
    if isinstance(v, list):
        return str(len(v))
    if v is None:
        return "n/a"
    return str(v).lower() if isinstance(v, bool) else str(v)


def table(full: dict, naive: dict) -> str:
    lines = ["| Measure | Naive offboarding | Full lifecycle |", "|---|---|---|"]
    for key, label in ROWS:
        lines.append(f"| {label} | {_fmt(naive.get(key))} | {_fmt(full.get(key))} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="iamlc")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the Zestlane scenario both ways and print real numbers")
    d.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "demo":
        full, naive = run(naive=False), run(naive=True)
        if a.json:
            print(json.dumps({"full": full, "naive": naive}, indent=2, sort_keys=True))
        else:
            print(table(full, naive))
            print(f"\nOrphans (full run): {', '.join(full['orphans'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
