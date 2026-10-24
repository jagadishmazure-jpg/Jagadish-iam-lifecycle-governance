import pytest

from iamlc.clock import HOUR, MINUTE, Clock
from iamlc.directory import DirUser
from iamlc.idp import IdpError
from iamlc.oauth import PLATFORM_API, PartnerApi, login_with_access_token
from iamlc.other_identities import CIAM_POLICY, GuestAccount, SecretError, SecretsManager
from iamlc.siem import Siem, SignIn, km_between
from iamlc.tokens import TokenError


def test_distance_sane():
    a, b = SignIn("u", 0, 43.65, -79.38, "x"), SignIn("u", 0, 50.11, 8.68, "y")
    assert 6000 < km_between(a, b) < 7000


def test_impossible_travel_medium():
    s = Siem()
    s.ingest(SignIn("u", 0, 43.65, -79.38, "1.1.1.1"))
    assert s.ingest(SignIn("u", 20 * MINUTE, 50.11, 8.68, "2.2.2.2")) == "medium"
    assert s.alerts[0]["rule"] == "impossible-travel"


def test_vpn_egress_noted_not_challenged():
    s = Siem(vpn_egress={"203.0.113.10"})
    s.ingest(SignIn("u", 0, 43.65, -79.38, "1.1.1.1"))
    assert s.ingest(SignIn("u", 15 * MINUTE, 51.5, -0.13, "203.0.113.10")) == "low"
    assert s.notes and not s.alerts


def test_plausible_travel_low():
    s = Siem()
    s.ingest(SignIn("u", 0, 43.65, -79.38, "1.1.1.1"))
    assert s.ingest(SignIn("u", 10 * HOUR, 50.11, 8.68, "2.2.2.2")) == "low"


def test_travel_plus_new_device_high():
    s = Siem()
    s.ingest(SignIn("u", 0, 43.65, -79.38, "1.1.1.1"))
    assert s.ingest(SignIn("u", 60, 50.11, 8.68, "2.2.2.2", new_device=True)) == "high"


def test_push_flag_raises_risk():
    s = Siem()
    assert s.ingest(SignIn("u", 0, 0, 0, "1"), push_flagged=True) == "medium"


def test_disabled_account_signin_alerts():
    s = Siem()
    assert s.ingest(SignIn("u", 0, 0, 0, "1", outcome="disabled")) == "high"
    assert s.alerts[0]["rule"] == "disabled-account-signin"


def test_failed_signin_does_not_move_baseline():
    s = Siem()
    s.ingest(SignIn("u", 0, 43.65, -79.38, "1"))
    s.ingest(SignIn("u", 60, 50.11, 8.68, "2", outcome="failure"))
    assert s.last["u"].ip == "1"


@pytest.fixture
def partner(world):
    world.directory.upsert(DirUser("own-1", "-", "owner1", "Partner", "CA", kind="guest"))
    world.idp.register(
        "books",
        "s",
        ("https://books.example/cb",),
        kind="oauth_partner",
        allowed_scopes=frozenset({"sales:read"}),
        resource=PLATFORM_API,
    )
    api = PartnerApi(world.idp, {"own-1": [1, 2]})
    sess = world.idp.authenticate("own-1", ["password", "totp"])
    code = world.idp.authorize("books", "https://books.example/cb", sess.sid, {"sales:read"}, "s", "n")
    return world, api, world.idp.exchange(code, "books", "s", "https://books.example/cb")


def test_delegated_read_works_without_password(partner):
    _, api, toks = partner
    assert api.read_sales(toks["access_token"]) == [1, 2]
    assert "id_token" not in toks


def test_delegated_scope_enforced(partner):
    _, api, toks = partner
    with pytest.raises(TokenError):
        api.write_menu(toks["access_token"])


def test_partner_cannot_request_openid(partner):
    w = partner[0]
    sess = w.idp.authenticate("own-1", ["password", "totp"])
    with pytest.raises(IdpError):
        w.idp.authorize("books", "https://books.example/cb", sess.sid, {"openid", "sales:read"}, "s", "n")


def test_access_token_is_not_login(partner):
    with pytest.raises(IdpError):
        login_with_access_token(partner[2]["access_token"])


def test_revoked_owner_token_refused(partner):
    w, api, toks = partner
    w.idp.revoke_user("own-1")
    with pytest.raises(TokenError):
        api.read_sales(toks["access_token"])


def test_orders_token_wrong_audience_for_api(world):
    from iamlc.scenario import oidc_login

    _, toks = oidc_login(world, "usr-E1001")
    with pytest.raises(TokenError):
        PartnerApi(world.idp).read_sales(toks["access_token"])


def test_guest_expires():
    g = GuestAccount("g1", "usr-E1001", "partner-org", 100, frozenset({"partner_menu:edit"}))
    assert g.usable(99) and not g.usable(100)


def test_ciam_policy_present():
    assert {"signup", "mfa", "recovery", "scale_target"} <= set(CIAM_POLICY)


def test_secrets_manager_acl_lease_rotate():
    c = Clock()
    sm = SecretsManager(c)
    sm.put("db", "v1", {"svc-a"})
    with pytest.raises(SecretError):
        sm.lease("svc-b", "db")
    lease = sm.lease("svc-a", "db")
    with pytest.raises(SecretError):
        sm.read("svc-b", lease)
    assert sm.read("svc-a", lease) == "v1"
    sm.rotate("db")
    with pytest.raises(SecretError):
        sm.read("svc-a", lease)
    assert "v1" not in repr(sm)


def test_secret_lease_expires():
    c = Clock()
    sm = SecretsManager(c)
    sm.put("db", "v1", {"svc-a"})
    lease = sm.lease("svc-a", "db")
    c.advance(HOUR)
    with pytest.raises(SecretError):
        sm.read("svc-a", lease)


def test_clock_cannot_go_back():
    with pytest.raises(ValueError):
        Clock().advance(-1)
