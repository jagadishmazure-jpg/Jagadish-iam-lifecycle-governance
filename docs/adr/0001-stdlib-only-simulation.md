# ADR 0001: Standard library only, in-process simulation

**Status:** accepted

**Context:** The goal is to show IAM lifecycle reasoning that anyone can run for free in seconds.

**Decision:** No runtime dependencies. Tokens use HMAC-SHA256, SCIM is a dict-in/dict-out mock,
time is a controllable clock.

**Consequences:** Deterministic tests and zero cost. Cryptographic mechanics differ from production
(see limitations); behaviours under test do not.
