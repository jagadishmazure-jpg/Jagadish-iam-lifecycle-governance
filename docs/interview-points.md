# Interview points

* **AAA in one line each:** authentication proves who, authorization limits what, accounting records
  what happened. Here: `authn.py`, `authz.py`, `audit.py`.
* **Disabling the identity is not offboarding.** Measured: after IdP disable only, the app session and
  access token both still work. Revocation and app session kill are separate steps.
* **The forgotten local account.** Naive offboarding: 4200 customer rows exported 90 days later. Full
  lifecycle: refused, alerted, audited.
* **Movers cause creep.** Naive transfer left Mira with support rights, which then triggered an SoD
  denial on a legitimate request. Removing old access is a security and a usability fix.
* **Verify by reading back, retry, flag.** One app outage flagged all 3 leavers; reconcile cleared them.
* **MFA is about categories.** SMS plus TOTP is not MFA. Ranking: SMS < number-match push < TOTP <
  passkey; only passkeys resist phishing. Recovery must meet the same bar.
* **OAuth vs OIDC vs SAML:** delegated API access vs sign-in with an ID token vs enterprise assertions.
  A JWT is a token format, not a protocol.
* **Zero trust here means `decide()` runs on every request** with account, session, risk, role and
  attributes; risk can produce step-up rather than deny.
* **Impossible travel is a signal, not proof** (VPNs). Known egress gets a note, unknown gets step-up.
* **Trade-off:** fail-closed attribute checks reduce leaks but need good data quality (country on every
  order, device posture on every request).
* **Numbers:** <!-- BEGIN:tests -->200<!-- END:tests --> tests; all figures regenerated from a run in CI.
