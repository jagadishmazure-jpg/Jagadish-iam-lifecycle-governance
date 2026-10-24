import pytest

from iamlc.authn import (
    RECOVERY_METHODS,
    SECOND_FACTOR_ORDER,
    AuthError,
    Passkey,
    PushFatigueDetector,
    RecoveryPolicy,
    assurance,
    is_mfa,
    phishing_resistant,
    strength,
)
from iamlc.clock import MINUTE, Clock


def test_ranking_order_is_sms_push_totp_passkey():
    ranks = [strength(f) for f in SECOND_FACTOR_ORDER]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4
    assert SECOND_FACTOR_ORDER == ["sms_otp", "push_number_match", "totp", "passkey"]


@pytest.mark.parametrize(
    "used,expected",
    [
        (["password"], False),
        (["password", "sms_otp"], True),
        (["password", "totp"], True),
        (["sms_otp", "totp"], False),  # two things you have is still one category
        (["passkey"], True),
        (["password", "password"], False),
    ],
)
def test_mfa_needs_two_categories(used, expected):
    assert is_mfa(used) is expected


def test_unknown_factor_rejected():
    with pytest.raises(AuthError):
        is_mfa(["password", "carrier-pigeon"])
    with pytest.raises(AuthError):
        strength("x")


def test_assurance_and_phishing():
    assert assurance(["password"]) == -1
    assert assurance(["password", "sms_otp", "passkey"]) == 4
    assert phishing_resistant(["passkey"]) and not phishing_resistant(["password", "totp"])


def test_passkey_bound_to_origin():
    pk = Passkey("https://login.zestlane.example")
    good = pk.sign("https://login.zestlane.example", "c1")
    assert pk.verify("https://login.zestlane.example", "c1", good)
    phished = pk.sign("https://login.zestlane-help.example", "c1")
    assert not pk.verify("https://login.zestlane.example", "c1", phished)
    assert not pk.verify("https://login.zestlane.example", "c2", good)


def test_passkey_secret_not_in_repr():
    assert "secret" not in repr(Passkey("https://a.example"))


def test_push_flood_flags_and_distrusts_late_approval():
    c = Clock()
    d = PushFatigueDetector(c)
    for o in ["ignored", "denied", "ignored"]:
        assert d.record("u", o) is False
        c.advance(MINUTE)
    assert "u" in d.flagged
    assert d.record("u", "approved") is False
    assert not d.allow_method("u", "push")
    assert d.allow_method("u", "push_number_match")


def test_push_below_threshold_is_fine():
    c = Clock()
    d = PushFatigueDetector(c)
    d.record("u", "denied")
    c.advance(MINUTE)
    assert d.record("u", "approved") is True


def test_push_window_slides():
    c = Clock()
    d = PushFatigueDetector(c)
    d.record("u", "denied")
    d.record("u", "denied")
    c.advance(30 * MINUTE)
    d.record("u", "denied")
    assert "u" not in d.flagged


def test_push_clear_and_bad_outcome():
    c = Clock()
    d = PushFatigueDetector(c, threshold=1)
    d.record("u", "denied")
    d.clear("u")
    assert d.allow_method("u", "push")
    with pytest.raises(AuthError):
        d.record("u", "maybe")


@pytest.mark.parametrize(
    "method,ok",
    [
        ("security_questions", False),
        ("sms_link", False),
        ("backup_totp", False),
        ("manager_verified_video_plus_new_passkey", True),
    ],
)
def test_recovery_for_passkey_user(method, ok):
    assert RecoveryPolicy().allowed(["password", "passkey"], RECOVERY_METHODS[method])[0] is ok


def test_recovery_for_totp_user_accepts_totp_not_sms():
    rp = RecoveryPolicy()
    assert rp.allowed(["password", "totp"], ["password", "totp"])[0]
    assert not rp.allowed(["password", "totp"], ["password", "sms_otp"])[0]


def test_recovery_must_be_mfa():
    ok, why = RecoveryPolicy().allowed(["password"], ["password"])
    assert not ok and "two categories" in why
