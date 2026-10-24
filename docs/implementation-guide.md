# Implementation guide (for adopters)

How to turn each module into a control in a real identity stack. Product names are left out on purpose;
use the category.

## 1. Make HR authoritative
* Feed hires, transfers and terminations from the HR system into an identity lifecycle tool (an
  IGA platform or your own job). No account is created by hand.
* Key every account on an immutable employee id (`externalId` in SCIM), never on the email address.

## 2. Inventory every app and its integration type
| Integration | Example here | What you need |
|---|---|---|
| SSO + SCIM provisioning | mail, chat, orders, payouts, vendors | Enable deprovisioning, not just provisioning |
| SSO only, no SCIM | — | A connector or a ticket with read-back |
| Local accounts only | helpdesk | Connector or scripted admin API; add to orphan scans |

## 3. Birthright and roles
* Define birthright per department as groups, then map groups to app roles (`BIRTHRIGHT`, `GROUP_ROLE`).
* Keep each role small; add attribute conditions (country, device state, amount limits) in the app or
  a policy engine.

## 4. Movers
* Compute the new target set and remove everything outside it. Treat access-request grants as
  job-scoped and drop them on transfer.

## 5. Leavers
1. Disable the identity at the identity provider.
2. Revoke refresh tokens and sign-in sessions; publish a revocation time to resource servers.
3. Kill sessions inside each app (most apps do not check back with the identity provider).
4. Deactivate accounts everywhere, including local ones.
5. Read every app back and alert on anything left. Retry transient failures with backoff.
6. Reconcile flagged leavers until zero remain.

## 6. Privileged access
* Make admin roles requestable only, with manager plus owner approval, a time limit and recorded
  sessions. Run the expiry sweep on a schedule and alert if it stops.
* Keep two break-glass accounts outside SSO, with long random credentials in a safe, and alert on any use.

## 7. Governance
* Quarterly reviews for normal roles, monthly for high-risk ones. Reviewers cannot certify themselves.
* Weekly orphan scan: app accounts with no active HR worker, minus registered service accounts.
* SoD rules checked at request time and in reviews.

## 8. Monitoring
* Send sign-in, provisioning and privileged events to your SIEM. Correlate impossible travel, push floods
  and sign-ins by disabled accounts. Keep VPN egress lists current to cut false positives.
* Use the risk result for step-up, not only for blocking.

## 9. Mapping table
| This repo | Real-world category |
|---|---|
| `HrSystem` | HR information system |
| `Directory` | Directory service / cloud identity platform |
| `IdentityProvider` | Identity provider with OIDC and SAML |
| `ScimApp` | SaaS app with SCIM 2.0 |
| `LifecycleEngine` | Identity lifecycle / IGA |
| `Pam` | Privileged access management |
| `governance.py` | Access certification in IGA |
| `Siem` | SIEM with identity analytics |
| `SecretsManager` | Cloud secrets manager |

## 10. Staying free
Developer tenants of most identity providers and SIEM free tiers are enough to reproduce the flows. Do
not connect production HR data to a lab.
