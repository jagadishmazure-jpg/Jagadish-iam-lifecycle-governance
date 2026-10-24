# How it works

The story follows Mira (employee E1001) at Zestlane. All names and data are invented.

## 1. HR is the source of truth
`HrSystem.hire()` stores the worker and queues an event. Nothing is created in any app until the
lifecycle engine drains that queue, so every account traces back to an HR record.

## 2. Joiner and birthright access
`LifecycleEngine.joiner()` creates the directory user, adds the department's birthright groups and
provisions each birthright app. For SCIM apps it first searches by `userName` and then creates or
re-activates, so a retry never makes a duplicate:

```python
status, body = app.handle("GET", f'/Users?filter=userName eq "{username}"')
...
payload = {"schemas": [USER_SCHEMA], "userName": username, "externalId": employee_id, "roles": roles}
status, body = app.handle("POST", "/Users", payload)
```

The helpdesk has no SCIM, so the engine uses its connector to create a local password account. Real run:
40 workers hired, 137 accounts provisioned.

## 3. Signing in
* **Factors.** `is_mfa()` counts categories (know / have / are), so SMS plus TOTP is still one category
  and is refused. Second factors are ranked `sms_otp < push_number_match < totp < passkey`.
* **Passkey.** The device signs the origin it actually sees. A proof made on a look-alike domain does
  not verify for the real one (`test_passkey_bound_to_origin`).
* **Push floods.** Three denied or ignored prompts within 10 minutes flag the user; a later approval is
  not trusted and plain push is refused until cleared.
* **Recovery.** `RecoveryPolicy` refuses any recovery method weaker than the user's sign-in. For a
  passkey user, security questions, an SMS link and even TOTP are refused; only a verified re-enrolment
  with a new passkey passes.

## 4. SSO and federation
The orders app uses the OIDC authorization-code flow: the IdP issues a one-time code bound to the client
and redirect URI, and the app exchanges it (with its secret) for an ID token, an access token and a
refresh token. The app checks issuer, audience, expiry and nonce before opening its own session. A
payroll app uses a SAML-style signed assertion with audience and validity window.

**Delegated access is not identity.** A restaurant owner lets a bookkeeping app read sales. The app
gets an access token with `sales:read` only, no ID token, and `login_with_access_token()` refuses to
treat it as a login.

## 5. Authorization on every request
`decide()` re-checks, in order: account enabled, session valid, sign-in risk, role, then attributes.
Real decisions for Mira while in Support:

| Request | Result |
|---|---|
| Read a customer address, same country, managed laptop | allow |
| Same, order from another country | deny |
| Same country, unmanaged device | deny |
| Refund 30 | allow |
| Refund 80 (limit 50) | deny |
| Approve a payment | deny (no role) |

## 6. Mover
On transfer to Payments the engine removes every group and app account the old job gave, kills sessions
in those apps, and grants the new birthright. The payouts app was set to fail twice; the engine retried
and succeeded on the third call. Naive run: Mira keeps `support_agent` and her helpdesk login
(privilege creep). Full run: she holds only `employee_base` and `payments_analyst`.

## 7. Just-in-time elevation and SoD
Mira asks for `refund_investigator` for two hours. Her manager and the role owner both approve; the role
is added, one command is recorded, and the expiry sweep removes it after two hours. In the naive run
the same request is **denied by SoD rule SOD-2**, because creep left her able to issue refunds too.
A Vendor Ops user asking for payment approval is blocked by SOD-1; an IT user gets it only with a logged
exception, which the access review then revokes.

## 8. Leaver
```text
disable directory user -> revoke IdP sessions + refresh tokens + publish not-before
-> remove groups -> per app: kill sessions, deactivate (SCIM PATCH active=false or local disable)
-> read every app back -> flag anything still active or unreadable
```
In the demo the vendors app is down during offboarding. All three leavers are flagged (6 exceptions),
nothing is marked done, and after the app returns `reconcile()` finishes them: 3 verified, 0 open.

## 9. Disabling the IdP is not enough
Kofi signs in to orders, then only his directory account is disabled. Real result: his app session is
still alive and his access token still verifies; only *new* sign-ins are refused. After the full leaver
runs, the session is gone and his tokens are on the revocation list.

## 10. Governance and monitoring
* The review campaign lists 41 role assignments (15 high-risk) with the manager as reviewer; self
  certification is refused.
* Orphan detection compares every active app account with active HR workers.
* The SIEM flags a Toronto-to-Frankfurt jump in 20 minutes as medium risk, so `decide()` asks for step-up.
  The same kind of jump through the company VPN egress address is only noted, because VPNs produce false
  positives.
* Break-glass sign-ins always alert; use while the IdP is healthy raises a second alert.

## 11. Three months later
The attacker tries Mira's old helpdesk password. Naive: sign-in works and 4200 rows are exported. Full:
`AppError: helpdesk: account disabled`, a `disabled-account-signin` SIEM alert and a denied audit event.
