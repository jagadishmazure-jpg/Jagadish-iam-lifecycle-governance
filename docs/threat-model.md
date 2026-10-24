# Threat model (STRIDE)

Assets: customer records in the helpdesk and orders apps, payment approval, directory admin rights.

| STRIDE | Threat in the lifecycle | Control here | Residual risk |
|---|---|---|---|
| Spoofing | Stolen password used to sign in | MFA by category; passkey origin binding | SMS and push still accepted as second factors for low-risk apps |
| Spoofing | Push-bombing until the user taps approve | Push-flood detector, number-match push | Threshold tuning is a guess for this lab |
| Spoofing | Help-desk reset by social engineering | Recovery must match sign-in strength | Real identity proofing is out of scope |
| Spoofing | Former employee uses a forgotten local account | Leaver disables local accounts via connector, read-back, orphan scan | Apps unknown to the inventory are invisible |
| Tampering | Edit of audit records to hide activity | Hash chain, `verify_chain()` | A full rewrite of the chain needs an external anchor (planned) |
| Tampering | Forged token or `alg: none` | Pinned algorithm, signature, issuer and audience checks | HMAC shared key in the lab, not asymmetric |
| Repudiation | "I never approved that" | Approvals, JIT grants, SoD exceptions and privileged commands are logged | — |
| Information disclosure | PII leaking into logs or error messages | `mask()` on every audit field and `SafeError` | Unformatted 10-digit phone numbers are not detected (known miss test) |
| Information disclosure | Live session after leave | Explicit session kill and token revocation | Apps that cache tokens beyond the not-before list |
| Denial of service | Provisioning target down during offboarding | Retries, flagged exceptions, reconcile | Long outages need a human; the flag is the alert |
| Elevation of privilege | Privilege creep on transfer | Mover removes old access; review campaign | Manual grants made outside the engine |
| Elevation of privilege | One person creates a vendor and approves its payment | SoD rules at grant time and in review | Rules cover three pairs only |
| Elevation of privilege | Standing admin rights | JIT with 8 h cap and expiry sweep; break-glass monitored | Sweep must actually be scheduled |
