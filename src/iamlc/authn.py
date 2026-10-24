"""Authentication: factor model, MFA strength ranking, phishing resistance, push-fatigue detection and
recovery that is held to the same bar as sign-in.

Ranking used here (weakest to strongest second factor):
    sms_otp < push_number_match < totp < passkey
The passkey is simulated with an HMAC over (origin, challenge) held per device. A real passkey uses a
public/private key pair; the property tested here is the same: the proof is bound to the real origin, so a
look-alike site cannot replay it, and the secret never leaves the device object.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from .clock import MINUTE, Clock
from .pii import SafeError

KNOW, HAVE, ARE = "know", "have", "are"

# name -> (categories it proves, strength rank, phishing resistant)
FACTORS: dict[str, tuple[frozenset[str], int, bool]] = {
    "password": (frozenset({KNOW}), 0, False),
    "sms_otp": (frozenset({HAVE}), 1, False),
    "push_number_match": (frozenset({HAVE}), 2, False),
    "totp": (frozenset({HAVE}), 3, False),
    # a passkey unlock uses a device (have) plus a local biometric or PIN (are / know)
    "passkey": (frozenset({HAVE, ARE}), 4, True),
}

# second-factor ranking; password is not a second factor
SECOND_FACTOR_ORDER = ["sms_otp", "push_number_match", "totp", "passkey"]


class AuthError(SafeError):
    pass


def strength(factor: str) -> int:
    if factor not in FACTORS:
        raise AuthError(f"unknown factor {factor!r}")
    return FACTORS[factor][1]


def is_mfa(used: list[str]) -> bool:
    """MFA means at least two distinct categories were proven, not two factors of the same kind."""
    cats: set[str] = set()
    for f in used:
        if f not in FACTORS:
            raise AuthError(f"unknown factor {f!r}")
        cats |= FACTORS[f][0]
    return len(cats) >= 2


def assurance(used: list[str]) -> int:
    """Strength of the strongest non-password factor, or -1 when only a password was used."""
    ranks = [strength(f) for f in used if f != "password"]
    return max(ranks, default=-1)


def phishing_resistant(used: list[str]) -> bool:
    return any(FACTORS[f][2] for f in used if f in FACTORS)


@dataclass
class Passkey:
    """Device-held credential bound to one relying-party origin."""

    rp_origin: str
    _secret: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    def sign(self, origin: str, challenge: str) -> str:
        # The authenticator signs the origin it actually sees in the browser, not the one it was told.
        return hmac.new(self._secret, f"{origin}|{challenge}".encode(), hashlib.sha256).hexdigest()

    def verify(self, origin: str, challenge: str, proof: str) -> bool:
        expected = hmac.new(self._secret, f"{self.rp_origin}|{challenge}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, proof)


@dataclass
class PushFatigueDetector:
    """Flags a user who is being flooded with push prompts.

    Rule: `threshold` or more prompts that were denied or ignored inside `window` seconds marks the account
    as under attack. While flagged, plain push is refused and an approval that arrives during the flood is
    not trusted. Number-match push still works because the attacker cannot see the number.
    """

    clock: Clock
    threshold: int = 3
    window: int = 10 * MINUTE
    history: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    flagged: set[str] = field(default_factory=set)

    def record(self, user: str, outcome: str) -> bool:
        """outcome: approved | denied | ignored. Returns True if this prompt should be trusted."""
        if outcome not in {"approved", "denied", "ignored"}:
            raise AuthError(f"bad push outcome {outcome!r}")
        now = self.clock.now
        h = [(t, o) for t, o in self.history.get(user, []) if now - t <= self.window]
        h.append((now, outcome))
        self.history[user] = h
        rejected = sum(1 for _, o in h if o in {"denied", "ignored"})
        if rejected >= self.threshold:
            self.flagged.add(user)
        return outcome == "approved" and user not in self.flagged

    def allow_method(self, user: str, method: str) -> bool:
        return not (user in self.flagged and method == "push")

    def clear(self, user: str) -> None:
        self.flagged.discard(user)
        self.history.pop(user, None)


@dataclass
class RecoveryPolicy:
    """Account recovery must be at least as strong as the sign-in it replaces."""

    def allowed(self, enrolled_login: list[str], recovery_method: list[str]) -> tuple[bool, str]:
        login_bar = assurance(enrolled_login)
        rec_bar = assurance(recovery_method)
        if rec_bar < login_bar:
            return False, f"recovery assurance {rec_bar} is below sign-in assurance {login_bar}"
        if phishing_resistant(enrolled_login) and not phishing_resistant(recovery_method):
            return False, "sign-in is phishing resistant but recovery is not"
        if not is_mfa(recovery_method):
            return False, "recovery must use two categories of proof"
        return True, "ok"


# Help-desk style recovery methods, expressed as factor lists, for tests and docs.
RECOVERY_METHODS: dict[str, list[str]] = {
    "security_questions": ["password"],
    "sms_link": ["password", "sms_otp"],
    "manager_verified_video_plus_new_passkey": ["passkey", "password"],
    "backup_totp": ["password", "totp"],
}
