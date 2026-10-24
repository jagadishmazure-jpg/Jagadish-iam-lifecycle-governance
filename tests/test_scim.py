import pytest

from iamlc.apps import PATCH_SCHEMA, USER_SCHEMA, AppError, LocalAccountApp, ScimApp
from iamlc.clock import Clock


@pytest.fixture
def app():
    return ScimApp("t", Clock())


def create(app, name="ua", **kw):
    return app.handle("POST", "/Users", {"schemas": [USER_SCHEMA], "userName": name, **kw})


def test_create_and_get(app):
    st, body = create(app, roles=["b", "a"])
    assert st == 201 and body["active"] and body["roles"] == ["a", "b"]
    assert app.handle("GET", f"/Users/{body['id']}")[0] == 200


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"userName": "x"}, 400),
        ({"schemas": [USER_SCHEMA]}, 400),
        ({"schemas": [USER_SCHEMA], "userName": ""}, 400),
        ({"schemas": [USER_SCHEMA], "userName": "x", "password": "p"}, 400),
    ],
)
def test_create_validation(app, payload, status):
    assert app.handle("POST", "/Users", payload)[0] == status


def test_duplicate_conflict(app):
    create(app)
    assert create(app)[0] == 409


def test_filter(app):
    create(app, "ua")
    create(app, "ub")
    st, body = app.handle("GET", '/Users?filter=userName eq "ub"')
    assert st == 200 and body["totalResults"] == 1
    assert app.handle("GET", "/Users?filter=emails co x")[0] == 400


def test_patch_active(app):
    uid = create(app)[1]["id"]
    ops = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": False}]}
    assert app.handle("PATCH", f"/Users/{uid}", ops)[1]["active"] is False
    assert not app.account_active("ua")


@pytest.mark.parametrize(
    "body",
    [
        {"Operations": []},
        {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "add", "path": "active", "value": False}]},
        {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "userName", "value": "z"}]},
        {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": "false"}]},
    ],
)
def test_patch_validation(app, body):
    uid = create(app)[1]["id"]
    assert app.handle("PATCH", f"/Users/{uid}", body)[0] == 400


def test_delete_and_404(app):
    uid = create(app)[1]["id"]
    assert app.handle("DELETE", f"/Users/{uid}")[0] == 204
    assert app.handle("GET", f"/Users/{uid}")[0] == 404
    assert app.handle("GET", "/Groups")[0] == 404


def test_outage_modes(app):
    app.fail_next = 1
    assert create(app)[0] == 503
    assert create(app)[0] == 201
    app.down = True
    assert app.handle("GET", "/Users/x")[0] == 503


def test_error_body_has_schema(app):
    st, body = app.handle("GET", "/Users/nope")
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"] and body["status"] == "404"


def test_sso_login_needs_active(app):
    with pytest.raises(AppError):
        app.sso_login("ua")
    create(app)
    assert app.sso_login("ua")


def test_local_app_password_and_disable():
    a = LocalAccountApp("h", Clock())
    a.create_local("ua", "pw-123456", ["support_agent"])
    sid = a.local_login("ua", "pw-123456")
    assert a.session_user(sid) == "ua"
    with pytest.raises(AppError):
        a.local_login("ua", "wrong")
    a.disable_local("ua")
    with pytest.raises(AppError):
        a.local_login("ua", "pw-123456")
    assert a.accounts["ua"]["pw"] != "pw-123456"


def test_local_connector_outage():
    a = LocalAccountApp("h", Clock(), connector_enabled=False)
    with pytest.raises(AppError):
        a.create_local("u", "p", [])
    with pytest.raises(AppError):
        a.disable_local("u")


def test_session_expiry():
    c = Clock()
    a = LocalAccountApp("h", c)
    sid = a.open_session("u")
    c.advance(13 * 3600)
    assert a.session_user(sid) is None and a.live_sessions("u") == 0


def test_export_requires_session():
    a = LocalAccountApp("h", Clock())
    with pytest.raises(AppError):
        a.export_customers("nope", 5)
