# ADR 0002: Apps keep their own sessions; revocation is explicit

**Status:** accepted

**Context:** Many apps create a local session after SSO and never consult the identity provider again.

**Decision:** Model apps that way, and make the leaver revoke IdP sessions and refresh tokens, publish a
not-before time and kill sessions in every app.

**Consequences:** The test suite can prove that disabling the identity alone leaves access open, and that
the full leaver closes it.
