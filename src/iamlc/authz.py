"""Authorization: role-based grants plus attribute conditions, evaluated per request (zero trust).

RBAC answers "may this role ever do this action". ABAC narrows it with the order's country, the
device's management state and the refund amount. The zero-trust wrapper re-checks the account, the
session, the device and the current sign-in risk on every request instead of trusting an earlier login.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ROLES: dict[str, frozenset[str]] = {
    "employee_base": frozenset({"email:use", "chat:use"}),
    "support_agent": frozenset({"orders:read", "refunds:issue", "customer_address:read"}),
    "payments_analyst": frozenset({"payments:read", "payouts:view"}),
    "vendor_admin": frozenset({"vendor:create"}),
    "payments_approver": frozenset({"payment:approve"}),
    "refund_investigator": frozenset({"refunds:read_archive"}),
    "directory_admin": frozenset({"directory:admin"}),
    "guest_partner": frozenset({"partner_menu:edit"}),
}

# Group name in the directory -> role. Membership in a group is the only way to hold a role.
GROUP_ROLE = {f"grp-{r}": r for r in ROLES}

REFUND_LIMIT = 50  # support agents may refund up to this amount without approval

# Actions that need a managed device and a recent strong sign-in
SENSITIVE = frozenset({"customer_address:read", "payment:approve", "directory:admin", "refunds:read_archive"})


@dataclass(frozen=True)
class Decision:
    effect: str  # allow | deny | step_up
    reason: str

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"


def permissions_for(roles: set[str]) -> set[str]:
    out: set[str] = set()
    for r in roles:
        out |= ROLES.get(r, frozenset())
    return out


def rbac(roles: set[str], action: str) -> Decision:
    if action in permissions_for(roles):
        return Decision("allow", "role grants action")
    return Decision("deny", f"no role grants {action}")


def abac(action: str, subject: dict, resource: dict, env: dict) -> Decision:
    """Attribute conditions on top of RBAC. Unknown attributes fail closed."""
    if action == "customer_address:read":
        if resource.get("country") is None or subject.get("country") != resource.get("country"):
            return Decision("deny", "order country differs from agent country")
    if action in SENSITIVE and env.get("device_managed") is not True:
        return Decision("deny", "sensitive action needs a managed device")
    if action == "refunds:issue":
        amount = resource.get("amount")
        if not isinstance(amount, (int, float)) or amount != amount or amount <= 0:
            return Decision("deny", "refund amount missing or invalid")
        if amount > REFUND_LIMIT:
            return Decision("deny", f"refund above limit {REFUND_LIMIT} needs approval")
    return Decision("allow", "attributes satisfied")


@dataclass
class RequestContext:
    user_id: str
    action: str
    roles: set[str]
    subject: dict = field(default_factory=dict)
    resource: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)  # device_managed, session_valid, account_enabled, risk, assurance


def decide(ctx: RequestContext) -> Decision:
    """Zero-trust evaluation, run on every request. Order: account, session, risk, role, attributes."""
    if ctx.env.get("account_enabled") is not True:
        return Decision("deny", "account disabled or unknown")
    if ctx.env.get("session_valid") is not True:
        return Decision("deny", "session missing, expired or revoked")
    risk = ctx.env.get("risk", "low")
    if risk == "high":
        return Decision("deny", "sign-in risk high")
    assurance = ctx.env.get("assurance", -1)
    if risk == "medium" and assurance < 3:
        return Decision("step_up", "medium risk needs a fresh TOTP or passkey")
    if ctx.action in SENSITIVE and assurance < 3:
        return Decision("step_up", "sensitive action needs TOTP or passkey")
    r = rbac(ctx.roles, ctx.action)
    if not r.allowed:
        return r
    return abac(ctx.action, ctx.subject, ctx.resource, ctx.env)
