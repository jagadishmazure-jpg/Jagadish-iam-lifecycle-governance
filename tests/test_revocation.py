"""The core claim: disabling the identity at the IdP does not end sessions that already exist."""

import pytest

from iamlc.idp import ISSUER, IdpError
from iamlc.scenario import oidc_login
from iamlc.tokens import verify


@pytest.fixture
def signed_in(world):
    u = world.directory.by_employee("E1001").user_id
    sid, toks = oidc_login(world, u)
    return world, u, sid, toks


def test_idp_disable_alone_leaves_app_session_alive(signed_in):
    w, u, sid, _ = signed_in
    w.directory.disable(u)
    assert w.apps["orders"].session_user(sid) is not None


def test_idp_disable_alone_leaves_access_token_valid(signed_in):
    w, u, _, toks = signed_in
    w.directory.disable(u)
    assert verify(toks["access_token"], w.idp.key, now=w.clock.now, audience="orders", issuer=ISSUER)
    assert not w.idp.is_revoked(
        verify(toks["access_token"], w.idp.key, now=w.clock.now, audience="orders", issuer=ISSUER)
    )


def test_idp_disable_blocks_new_signin(signed_in):
    w, u, _, _ = signed_in
    w.directory.disable(u)
    with pytest.raises(IdpError):
        w.idp.authenticate(u, ["password", "passkey"])


def test_revoke_marks_tokens_and_idp_sessions(signed_in):
    w, u, _, toks = signed_in
    n = w.idp.revoke_user(u)
    assert n >= 2
    claims = verify(toks["access_token"], w.idp.key, now=w.clock.now, audience="orders", issuer=ISSUER)
    assert w.idp.is_revoked(claims)
    with pytest.raises(IdpError):
        w.idp.refresh_tokens(toks["refresh_token"], "orders")


def test_revoke_without_app_kill_still_leaves_app_session(signed_in):
    w, u, sid, _ = signed_in
    w.idp.revoke_user(u)
    assert w.apps["orders"].session_user(sid) is not None  # app does not ask the IdP


def test_full_leaver_kills_app_session(signed_in):
    w, u, sid, _ = signed_in
    w.hr.terminate("E1001")
    rep = w.engine.process()[0]
    assert rep.verified
    assert w.apps["orders"].session_user(sid) is None
    assert w.audit.find(action="app.sessions_killed")


def test_new_tokens_after_revoke_not_flagged(signed_in):
    w, u, _, _ = signed_in
    w.idp.revoke_user(u)
    w.clock.advance(5)
    assert not w.idp.is_revoked({"sub": u, "iat": w.clock.now})
