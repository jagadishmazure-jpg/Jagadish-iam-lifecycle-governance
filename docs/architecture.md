# Architecture

```mermaid
flowchart LR
  HR[HR system<br/>source of truth] -- hire / transfer / terminate --> LC[Lifecycle engine<br/>joiner · mover · leaver]
  LC --> DIR[Directory<br/>users + groups]
  LC -- SCIM 2.0-style API --> SCIM[(mail · chat · orders · payouts · vendors)]
  LC -- custom connector --> LOCAL[(helpdesk<br/>local accounts)]
  LC -- revoke --> IDP[Mock IdP<br/>OIDC · SAML · refresh]
  DIR --> IDP
  IDP -- ID token / assertion --> SCIM
  IDP -- delegated token --> PAPI[Partner API<br/>sales:read]
  PAM[Access requests · JIT · break-glass] --> DIR
  SOD[SoD rules] --> PAM
  GOV[Reviews · orphan detection] --> DIR
  GOV -. compares .-> HR
  Z[Zero-trust decide()<br/>RBAC + ABAC + risk] --> SCIM
  SIEM[SIEM correlation<br/>travel · push floods · disabled use] --> Z
  LC & PAM & GOV & IDP --> AUD[(Audit log<br/>hash chain, PII masked)]
```

## Components

| Module | Responsibility |
|---|---|
| `hr.py` | Workers and an outbox of hire / transfer / terminate events |
| `directory.py` | User objects and group membership (groups map 1:1 to roles) |
| `authn.py` | Factor categories, strength ranking, MFA rule, passkey origin binding, push-flood detector, recovery policy |
| `authz.py` | Roles, attribute conditions and the per-request `decide()` |
| `tokens.py` | Compact signed tokens (JWT layout, HS256) with strict verification |
| `idp.py` | Sign-in, authorization-code flow, SAML-style assertions, refresh rotation, revocation |
| `apps.py` | `ScimApp` (SCIM 2.0-style endpoint) and `LocalAccountApp` (no SCIM, own passwords) |
| `lifecycle.py` | Joiner, mover, leaver, retries with backoff, read-back verification, reconcile |
| `pam.py` | Access requests, dual approval, JIT with expiry sweep, recorded commands, break-glass alerts |
| `sod.py` | Conflicting permission pairs |
| `governance.py` | Review campaigns, orphan detection, SoD report |
| `siem.py` | Impossible travel, push-flood and disabled-account correlation to a risk level |
| `oauth.py` | Partner delegated access, separate from identity |
| `other_identities.py` | Brief CIAM policy, guest accounts, secrets-manager leases |
| `audit.py`, `pii.py` | Hash-chained audit log; masking for emails, phones, cards and SSNs |
| `scenario.py`, `cli.py` | The end-to-end story and the demo table |

## Design choices
* **Standard library only.** No runtime dependencies, so the lab runs anywhere and supply-chain risk is
  near zero. See [ADR 0001](adr/0001-stdlib-only-simulation.md).
* **Apps keep their own sessions.** They do not call the IdP on each request. That is how most real apps
  behave and is the reason revocation must be explicit. See [ADR 0002](adr/0002-explicit-revocation.md).
* **Verify by reading back.** A write that returned 200 is not proof; the leaver reads every app again.
  See [ADR 0003](adr/0003-read-back-verification.md).
