import pytest

from iamlc.audit import AuditLog
from iamlc.clock import Clock
from iamlc.pii import SafeError, contains_pii, luhn_ok, mask


@pytest.mark.parametrize(
    "text,token",
    [
        ("mail jane.doe@zestlane.example now", "[EMAIL]"),
        ("card 4111 1111 1111 1111 on file", "[CARD]"),
        ("card 4111-1111-1111-1111", "[CARD]"),
        ("card 5500005555555559", "[CARD]"),
        ("ssn 123-45-6789", "[SSN]"),
        ("call +1 416-555-0199", "[PHONE]"),
        ("call (416) 555-0199", "[PHONE]"),
        ("call 416.555.0199", "[PHONE]"),
    ],
)
def test_masks_each_pii_type(text, token):
    out = mask(text)
    assert token in out
    assert not contains_pii(out)


@pytest.mark.parametrize("text", ["order 55120", "card 4111 1111 1111 1112", "ssn 000-12-3456", "ts 1800000000"])
def test_does_not_mask_non_pii(text):
    assert mask(text) == text


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_safe_error_masks_message():
    err = SafeError("user a.b@zestlane.example with 4111 1111 1111 1111 and 123-45-6789 at 416-555-0199")
    s = str(err)
    for raw in ["a.b@", "4111 1111", "123-45-6789", "555-0199"]:
        assert raw not in s


def test_audit_log_masks_all_fields():
    log = AuditLog(Clock())
    ev = log.record("x@zestlane.example", "act", "123-45-6789", "ok", "card 4111111111111111 phone 416-555-0199")
    blob = log.to_jsonl()
    assert "[EMAIL]" in ev.actor and "[SSN]" in ev.target
    for raw in ["x@zestlane", "123-45-6789", "4111111111111111", "555-0199"]:
        assert raw not in blob


def test_known_miss_unformatted_phone():
    """Known limitation, kept visible: a bare 10-digit phone number is not masked (would hit ids)."""
    assert mask("call 4165550199") == "call 4165550199"
