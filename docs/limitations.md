# Limitations and known failures

* **Simulated cryptography.** Tokens, assertions and the passkey use HMAC with keys held in-process. A
  real deployment uses asymmetric keys, published signing keys and XML signatures for SAML. The
  properties tested (origin binding, audience, expiry, tamper detection) carry over; the mechanics do not.
* **SCIM is a local mock.** The request and response shapes follow SCIM 2.0 (schemas, PatchOp, error
  body, `userName eq` filter) but there is no HTTP server, paging, ETags or bulk endpoint.
* **Synthetic company.** 40 workers generated from a fixed seed. Counts are regression checks for this
  model, not evidence about any real organisation.
* **Impossible travel uses coordinates I supply.** Real systems geolocate IPs, which is noisy; VPNs and
  mobile carriers cause false positives. This lab only allows known VPN egress addresses.
* **Push-flood threshold (3 in 10 minutes) is a lab choice**, not a tuned value.
* **Known miss, kept as a test:** a phone number written as ten bare digits is not masked, because the
  pattern would also hit order ids and timestamps (`test_known_miss_unformatted_phone`).
* **The ranking puts number-match push below TOTP** as requested for this lab. Some guidance ranks them
  the other way; both are phishable, and only the passkey is phishing resistant.
* **Customer, partner and machine identity are deliberately thin.** See the related repos.
* **No real tenant.** Nothing here has been connected to an actual identity provider.
