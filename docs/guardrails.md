# Guardrails and security controls

| Control | Where | Test |
|---|---|---|
| MFA means two categories, not two codes | `authn.is_mfa` | `test_mfa_needs_two_categories` |
| Phishing-resistant passkey bound to origin | `authn.Passkey` | `test_passkey_bound_to_origin` |
| Push-flood lockout, late approvals not trusted | `authn.PushFatigueDetector` | `test_push_flood_*` |
| Recovery at least as strong as sign-in | `authn.RecoveryPolicy` | `test_recovery_*` |
| Fail-closed attribute checks (missing country, NaN amount, unmanaged device) | `authz.abac` | `test_rbac_plus_abac` |
| Per-request zero-trust decision | `authz.decide` | `test_zero_trust_per_request` |
| Token checks: algorithm pinned, issuer, audience, expiry | `tokens.verify` | `test_rejections`, `test_bad_signature_and_alg_none` |
| One-time codes bound to client + redirect, 60 s life | `idp.exchange` | `test_code_*` |
| Refresh rotation with reuse detection (family revoke) | `idp.refresh_tokens` | `test_refresh_rotation_and_reuse_detection` |
| Explicit revocation and app session kill on leave | `lifecycle.leaver` | `test_revocation.py` |
| Retries with backoff; failures flagged and audited, never dropped | `lifecycle._retry` | `test_permanent_failure_flagged_not_dropped` |
| Read-back verification of every app | `lifecycle.verify_access` | `test_leaver_disables_everything` |
| No self-approval; manager and role owner both required | `pam.approve` | `test_self_and_stranger_approval_refused` |
| JIT max 8 h, auto expiry | `pam.sweep` | `test_jit_grant_and_expiry` |
| SoD block unless a logged exception | `pam.approve`, `sod.py` | `test_privilege_creep_causes_sod_block` |
| Break-glass alerts on every use | `pam.break_glass_signin` | `test_break_glass_alerts` |
| No self-certification in reviews | `governance.decide` | `test_self_certification_blocked` |
| Tamper-evident audit log | `audit.AuditLog` | `test_tamper_detected` |
| PII masked in audit, errors and alerts (email, phone, card with Luhn, SSN) | `pii.mask`, `SafeError` | `test_pii.py` |
| Local passwords hashed (PBKDF2, salted) | `apps.LocalAccountApp` | `test_local_app_password_and_disable` |
| Secrets only by lease to named services; values never in repr | `other_identities.SecretsManager` | `test_secrets_manager_acl_lease_rotate` |
| Brand blocklist stored as hashes, non-empty | `scripts/check_brands.py` | `test_brand_blocklist_non_empty` |
| Actions pinned to full commit SHAs | workflows | `test_actions_pinned_to_sha` |
