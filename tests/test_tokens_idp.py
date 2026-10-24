import base64
import json

import pytest

from iamlc.clock import MINUTE
from iamlc.idp import ISSUER, IdpError
from iamlc.scenario import oidc_login
from iamlc.tokens import TokenError, sign, unverified_claims, verify
from iamlc.world import ORDERS_REDIRECT

KEY = b"k" * 32


def claims(**kw):
    return {"iss": ISSUER, "aud": "a", "sub": "s", "exp": 100, **kw}


def test_roundtrip():
    assert verify(sign(claims(), KEY), KEY, now=50, audience="a", issuer=ISSUER)["sub"] == "s"


@pytest.mark.parametrize(
    "kw,aud,now",
    [({}, "b", 50), ({"iss": "evil"}, "a", 50), ({}, "a", 100), ({"exp": "100"}, "a", 50)],
)
def test_rejections(kw, aud, now):
    with pytest.raises(TokenError):
        verify(sign(claims(**kw), KEY), KEY, now=now, audience=aud, issuer=ISSUER)


def test_bad_signature_and_alg_none():
    tok = sign(claims(), KEY)
    with pytest.raises(TokenError):
        verify(tok, b"x" * 32, now=1, audience="a", issuer=ISSUER)
    none_hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    forged = none_hdr + "." + tok.split(".")[1] + "."
    with pytest.raises(TokenError):
        verify(forged, KEY, now=1, audience="a", issuer=ISSUER)
    with pytest.raises(TokenError):
        verify("garbage", KEY, now=1, audience="a", issuer=ISSUER)


def test_unverified_claims_reads():
    assert unverified_claims(sign(claims(), KEY))["aud"] == "a"


def uid(w, eid="E1001"):
    return w.directory.by_employee(eid).user_id


def test_signin_requires_mfa(world):
    with pytest.raises(IdpError):
        world.idp.authenticate(uid(world), ["password"])


def test_oidc_code_flow_and_id_token(world):
    sid, toks = oidc_login(world, uid(world))
    c = unverified_claims(toks["id_token"])
    assert c["sub"] == uid(world) and c["nonce"] == "n1" and c["acr"] == 4
    assert world.apps["orders"].session_user(sid)


def test_code_single_use_and_bound(world):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    code = world.idp.authorize("orders", ORDERS_REDIRECT, s.sid, {"openid"}, "st", "n")
    with pytest.raises(IdpError):
        world.idp.exchange(code, "orders", "wrong", ORDERS_REDIRECT)
    with pytest.raises(IdpError):  # consumed by the failed attempt
        world.idp.exchange(code, "orders", "orders-secret", ORDERS_REDIRECT)


def test_code_expires(world):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    code = world.idp.authorize("orders", ORDERS_REDIRECT, s.sid, {"openid"}, "st", "n")
    world.clock.advance(2 * MINUTE)
    with pytest.raises(IdpError):
        world.idp.exchange(code, "orders", "orders-secret", ORDERS_REDIRECT)


@pytest.mark.parametrize(
    "client,redirect,scope",
    [
        ("orders", "https://evil.example/cb", {"openid"}),
        ("ghost", ORDERS_REDIRECT, {"openid"}),
        ("orders", ORDERS_REDIRECT, {"openid", "payments:write"}),
    ],
)
def test_authorize_rejects(world, client, redirect, scope):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    with pytest.raises(IdpError):
        world.idp.authorize(client, redirect, s.sid, scope, "st", "n")


def test_refresh_rotation_and_reuse_detection(world):
    _, toks = oidc_login(world, uid(world))
    new = world.idp.refresh_tokens(toks["refresh_token"], "orders")
    with pytest.raises(IdpError):
        world.idp.refresh_tokens(toks["refresh_token"], "orders")  # reuse
    with pytest.raises(IdpError):
        world.idp.refresh_tokens(new["refresh_token"], "orders")  # family revoked


def test_refresh_fails_for_disabled_user(world):
    _, toks = oidc_login(world, uid(world))
    world.directory.disable(uid(world))
    with pytest.raises(IdpError):
        world.idp.refresh_tokens(toks["refresh_token"], "orders")


def test_saml_assertion_verified(world):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    msg = world.idp.saml_assertion("payroll-saml", s.sid)
    assert world.idp.verify_saml("payroll-saml", msg) == uid(world)


def test_saml_tamper_audience_and_expiry(world):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    msg = world.idp.saml_assertion("payroll-saml", s.sid)
    with pytest.raises(IdpError):
        world.idp.verify_saml("payroll-saml", {**msg, "assertion": msg["assertion"].replace(uid(world), "usr-E1099")})
    with pytest.raises(IdpError):
        world.idp.verify_saml("other-sp", msg)
    world.clock.advance(10 * MINUTE)
    with pytest.raises(IdpError):
        world.idp.verify_saml("payroll-saml", msg)


def test_saml_only_for_saml_clients(world):
    s = world.idp.authenticate(uid(world), ["password", "totp"])
    with pytest.raises(IdpError):
        world.idp.saml_assertion("orders", s.sid)
