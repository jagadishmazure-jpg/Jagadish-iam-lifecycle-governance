# ADR 0003: Verify by reading back; flag instead of assuming

**Status:** accepted

**Context:** A provisioning call can succeed at the transport level and still not apply, or the target may
be down.

**Decision:** After every leaver and mover, read each app back. Retry transient failures up to four times
with exponential backoff. Anything unresolved becomes an open exception and an audit event; `reconcile()`
re-runs pending leavers.

**Consequences:** Offboarding is only "done" when verified. Outages produce visible work, not silent gaps.
