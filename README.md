# IAM lifecycle and governance lab

[![ci](https://github.com/jagadishmazure-jpg/Jagadish-iam-lifecycle-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-iam-lifecycle-governance/actions/workflows/ci.yml)
[![codeql](https://github.com/jagadishmazure-jpg/Jagadish-iam-lifecycle-governance/actions/workflows/codeql.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-iam-lifecycle-governance/actions/workflows/codeql.yml)

A working model of **workforce identity and access management** for **Zestlane, a fictional
food-delivery company**: HR events drive joiner, mover and leaver changes into a directory, a mock
identity provider and six apps (five speak a SCIM 2.0-style API, one only has local accounts). On top
sit MFA strength rules, RBAC with attribute conditions, SSO and federation, token and session
revocation, just-in-time elevation, segregation of duties, access reviews, orphan detection and
SIEM-style sign-in correlation. Pure Python standard library, runs offline in seconds, costs nothing.

## At a glance (for recruiters)

* **Problem:** most access leaks are process gaps, not clever attacks. A leaver whose mailbox is
  switched off can still have a live app session, a valid token and a forgotten local account.
* **Approach:** model the whole lifecycle end to end, then run the same story twice: a naive offboarding
  (directory and mailbox only) and the full process, and measure the difference.
* **Proof (real run, `iamlc demo`):** with naive offboarding the departed employee's forgotten helpdesk
  account still signs in 90 days later and exports 4200 customer rows; with the full lifecycle it is
  refused and 0 rows leave. Orphan accounts against HR drop from 10 to 2 (the two seeded legacy ones).
* **Size:** <!-- BEGIN:tests -->200<!-- END:tests --> automated tests (pytest), lint, brand and overlap checks, gitleaks, CodeQL.
* **Honest limits:** everything is simulated in-process; tokens use HMAC, not real key pairs; numbers
  are regression checks on a 40-person synthetic company, not field measurements.
  See [limitations](docs/limitations.md).

## Status: built vs planned

| Part | Status |
|---|---|
| HR source of truth, directory with groups, birthright rules | Built |
| Factor model, MFA ranking (SMS < number-match push < TOTP < passkey), push-flood detector, recovery bar | Built |
| RBAC + ABAC (country, managed device, refund limit), zero-trust per-request decision | Built |
| Mock IdP: OIDC code flow, SAML-style signed assertion, refresh rotation with reuse detection | Built (HMAC signing, simulated) |
| OAuth delegated access for a partner bookkeeping app, kept separate from login | Built |
| SCIM 2.0-style provisioning API (local mock) and a non-SCIM local-account app via connector | Built |
| Joiner / mover / leaver with retries, flagged exceptions, read-back verification, reconcile | Built |
| Session and token revocation; proof that IdP disable alone is not enough | Built |
| Access requests, JIT elevation with expiry sweep, recorded privileged commands | Built |
| Break-glass accounts with alert on every use | Built |
| Segregation-of-duties rules, access review campaign, orphan detection | Built |
| Hash-chained audit log with PII masking; SIEM-style impossible travel with VPN allowance | Built |
| Customer IAM, partner guests, machine identities via a secrets-manager pattern | Built, deliberately brief (see related repos) |
| Real SCIM HTTP server, real WebAuthn, real SAML XML signatures | Planned |
| Connecting to a real identity provider tenant | Planned, not started (would stay on free tiers) |

## Real output

`iamlc demo` runs the Zestlane story twice and prints this table (regenerated in CI by
`scripts/render_docs.py --check`, so it cannot drift from the code):

<!-- BEGIN:demo -->
| Measure | Naive offboarding | Full lifecycle |
|---|---|---|
| Workers hired from HR | 40 | 40 |
| Accounts provisioned at hire (SCIM + connector) | 137 | 137 |
| Privilege creep after the move | true | false |
| Provisioning calls that needed a retry | n/a | 1 |
| Mira's 2-hour refund-archive request | denied | active |
| Elevations removed by the expiry sweep | n/a | 1 |
| Privileged commands recorded | 0 | 1 |
| Requests blocked by segregation of duties | 2 | 1 |
| SoD conflicts live before the review | 1 | 1 |
| SoD conflicts live after the review | 0 | 0 |
| Access review items | 42 | 41 |
| Access revoked in the review | 1 | 1 |
| App session alive after IdP disable only | true | true |
| Access token accepted after IdP disable only | true | true |
| New sign-in after IdP disable | refused | refused |
| Leavers | 3 | 3 |
| Leavers flagged while one app was down | n/a | 3 |
| Leavers verified after reconcile | n/a | 3 |
| Accounts deactivated for leavers | n/a | 10 |
| Refresh tokens revoked | 0 | 2 |
| Leaver's app session alive after offboarding | true | false |
| Open exceptions at the end | 0 | 0 |
| Orphan accounts found against HR | 10 | 2 |
| Impossible travel (unknown IP) decision | step_up | step_up |
| Same jump via known VPN egress, risk | low | low |
| Break-glass alerts | 3 | 3 |
| Partner token used outside its scope | denied | denied |
| Forgotten helpdesk login works 90 days later | true | false |
| Customer rows exported by that login | 4200 | 0 |
| Audit events written | 57 | 82 |
| Audit hash chain intact | true | true |
<!-- END:demo -->

Orphans left after the full run: <!-- BEGIN:orphans -->helpdesk:ue0778, vendors:ue0777<!-- END:orphans -->. Both were seeded on purpose as
accounts that existed before the lifecycle process; a review would remove them.

## Quick start (offline, free)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
iamlc demo            # the table above
iamlc demo --json     # every number
pytest -q             # the full suite
```

No cloud account, API key or network access is needed.

## Documentation

| Doc | What it covers |
|---|---|
| [Purpose](docs/purpose.md) | Why this exists and who it is for |
| [Architecture](docs/architecture.md) | Components and a diagram |
| [How it works](docs/how-it-works.md) | The lifecycle step by step, with real code and output |
| [Running](docs/running.md) | Commands, CI, regeneration of numbers |
| [Results](docs/results.md) | Every measured number and where it comes from |
| [Guardrails](docs/guardrails.md) | Security controls built into the code |
| [Threat model](docs/threat-model.md) | STRIDE walk through the lifecycle |
| [Limitations](docs/limitations.md) | What is simulated and known misses |
| [Implementation guide](docs/implementation-guide.md) | How to apply this in a real company |
| [Interview points](docs/interview-points.md) | Talking points and trade-offs |
| [ADRs](docs/adr/) | Key design decisions |

## Related repos

* [Jagadish-agent-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-identity-security):
  identity *posture* scanning across people, workload identities and AI agents. This repo is the
  *process* side for employees; machine and agent identity are only sketched here and linked there.
* [Jagadish-machine-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-machine-identity-security):
  non-human identities and secrets in depth.
* [Jagadish-agent-auth-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security):
  how a request proves who it is (JWT, sessions, on-behalf-of flows).

## Credit

The scenario idea (a leaver whose separate support-tool login was missed) comes from a public video
explainer on identity and access management. All text and code here are written independently; an
8-word overlap check against the transcript is run before publishing and reports 0 shared runs.

MIT licensed. Security issues: see [SECURITY.md](SECURITY.md).
