"""PII masking used by the audit log, error messages and the SIEM feed.

Covers email addresses, phone numbers, payment card numbers (Luhn-checked, so order ids are not
masked by mistake) and US social security numbers. Masking runs on every string that leaves a module.
"""

from __future__ import annotations

import re

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
# A separator is required between the groups so bare 10-digit ids and timestamps are not masked.
# Known miss (kept visible as a test): an unformatted 10-digit phone number is not detected.
PHONE = re.compile(r"(?<![\w-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w-])")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _card(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 13 <= len(digits) <= 19 and luhn_ok(digits):
        return "[CARD]"
    return m.group(0)


def mask(text: str) -> str:
    """Replace PII with typed placeholders. Order matters: cards before phones, SSNs before phones."""
    text = EMAIL.sub("[EMAIL]", text)
    text = CARD_CANDIDATE.sub(_card, text)
    text = SSN.sub("[SSN]", text)
    text = PHONE.sub("[PHONE]", text)
    return text


def contains_pii(text: str) -> bool:
    return mask(text) != text


class SafeError(Exception):
    """Exception whose message is masked before it is stored, so logs and tracebacks stay clean."""

    def __init__(self, message: str) -> None:
        super().__init__(mask(message))
