# Results (real run)

All numbers come from `iamlc demo` on the synthetic 40-person company (seed 7) and are rewritten by
`scripts/render_docs.py`. Test count: <!-- BEGIN:tests -->200<!-- END:tests -->.

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

Orphans after the full run: <!-- BEGIN:orphans -->helpdesk:ue0778, vendors:ue0777<!-- END:orphans -->.

## Reading the table
* **Naive offboarding** disables the directory user and the mailbox only, and the mover only adds
  access. **Full lifecycle** is the engine in `lifecycle.py`.
* "App session alive after IdP disable only" is `true` in both columns on purpose: it is measured before
  the leaver runs and proves that disabling the identity alone does not end sessions.
* Leavers are flagged during the outage because the vendors app cannot be read back; nothing is marked
  complete until `reconcile()` verifies it.
* In the naive column the JIT request is denied because privilege creep created an SoD conflict.
* These are regression checks on a small synthetic model, not quality claims about real systems.
