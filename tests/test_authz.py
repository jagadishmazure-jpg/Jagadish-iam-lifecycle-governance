import pytest

from iamlc.authz import ROLES, RequestContext, abac, decide, permissions_for, rbac

BASE = {"account_enabled": True, "session_valid": True, "assurance": 4, "device_managed": True}


def ctx(action, roles=("support_agent",), resource=None, **env):
    return RequestContext(
        "u1",
        action,
        set(roles),
        {"country": "CA"},
        resource if resource is not None else {"country": "CA"},
        {**BASE, **env},
    )


def test_least_privilege_support_cannot_approve_or_admin():
    perms = permissions_for({"employee_base", "support_agent"})
    assert "payment:approve" not in perms and "directory:admin" not in perms


def test_every_role_is_small():
    assert all(1 <= len(p) <= 3 for p in ROLES.values())


def test_rbac_unknown_role_denies():
    assert not rbac({"ghost"}, "orders:read").allowed


@pytest.mark.parametrize(
    "action,resource,env,effect",
    [
        ("orders:read", {}, {}, "allow"),
        ("customer_address:read", {"country": "CA"}, {}, "allow"),
        ("customer_address:read", {"country": "IN"}, {}, "deny"),
        ("customer_address:read", {}, {}, "deny"),
        ("customer_address:read", {"country": "CA"}, {"device_managed": False}, "deny"),
        ("customer_address:read", {"country": "CA"}, {"device_managed": None}, "deny"),
        ("refunds:issue", {"amount": 50}, {}, "allow"),
        ("refunds:issue", {"amount": 50.01}, {}, "deny"),
        ("refunds:issue", {"amount": -5}, {}, "deny"),
        ("refunds:issue", {"amount": float("nan")}, {}, "deny"),
        ("refunds:issue", {"amount": "10"}, {}, "deny"),
        ("payment:approve", {}, {}, "deny"),
    ],
)
def test_rbac_plus_abac(action, resource, env, effect):
    assert decide(ctx(action, resource=resource, **env)).effect == effect


@pytest.mark.parametrize(
    "env,effect",
    [
        ({"account_enabled": False}, "deny"),
        ({"account_enabled": None}, "deny"),
        ({"session_valid": False}, "deny"),
        ({"risk": "high"}, "deny"),
        ({"risk": "medium", "assurance": 2}, "step_up"),
        ({"risk": "medium", "assurance": 3}, "allow"),
        ({"assurance": 1}, "step_up"),
    ],
)
def test_zero_trust_per_request(env, effect):
    assert decide(ctx("customer_address:read", **env)).effect == effect


def test_non_sensitive_action_low_assurance_ok():
    assert decide(ctx("orders:read", assurance=1)).allowed


def test_abac_direct_passthrough():
    assert abac("orders:read", {}, {}, {}).allowed
