"""Downstream applications.

* ScimApp exposes a SCIM 2.0-style API (a local mock, dict in / dict out) for create, read, filter, patch
  and delete of Users.
* LocalAccountApp has no SCIM. It keeps its own username/password accounts and is reached through a
  custom connector, the way many older support tools are. This is where offboarding usually misses.

Both keep their own sessions. Neither asks the IdP about the user on each request, which is realistic and
is why the leaver flow must kill app sessions directly.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

from .clock import HOUR, Clock
from .pii import SafeError

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
FILTER = re.compile(r'^userName eq "([^"]+)"$')


class AppError(SafeError):
    pass


def _err(status: int, detail: str) -> tuple[int, dict]:
    return status, {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}


@dataclass
class BaseApp:
    name: str
    clock: Clock
    session_ttl: int = 12 * HOUR
    sessions: dict[str, dict] = field(default_factory=dict)

    def open_session(self, username: str) -> str:
        sid = secrets.token_urlsafe(12)
        self.sessions[sid] = {"username": username, "exp": self.clock.now + self.session_ttl}
        return sid

    def session_user(self, sid: str) -> str | None:
        s = self.sessions.get(sid)
        if s is None or self.clock.now >= s["exp"]:
            return None
        return s["username"]

    def kill_sessions(self, username: str) -> int:
        doomed = [k for k, v in self.sessions.items() if v["username"] == username]
        for k in doomed:
            del self.sessions[k]
        return len(doomed)

    def live_sessions(self, username: str) -> int:
        return sum(1 for v in self.sessions.values() if v["username"] == username and self.clock.now < v["exp"])


@dataclass
class ScimApp(BaseApp):
    users: dict[str, dict] = field(default_factory=dict)
    fail_next: int = 0  # simulate an outage: the next N write calls return 503
    down: bool = False  # permanently unavailable
    calls: int = 0

    # -- SCIM endpoint ----------------------------------------------------------------------------------
    def handle(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        self.calls += 1
        if self.down:
            return _err(503, "service unavailable")
        if method in {"POST", "PATCH", "DELETE"} and self.fail_next > 0:
            self.fail_next -= 1
            return _err(503, "temporary failure")
        if method == "POST" and path == "/Users":
            return self._create(body or {})
        if method == "GET" and path.startswith("/Users?filter="):
            m = FILTER.match(path.split("=", 1)[1])
            if not m:
                return _err(400, "unsupported filter")
            hits = [u for u in self.users.values() if u["userName"] == m.group(1)]
            return 200, {"totalResults": len(hits), "Resources": hits}
        if path.startswith("/Users/"):
            uid = path.removeprefix("/Users/")
            if uid not in self.users:
                return _err(404, "user not found")
            if method == "GET":
                return 200, self.users[uid]
            if method == "PATCH":
                return self._patch(uid, body or {})
            if method == "DELETE":
                del self.users[uid]
                return 204, {}
        return _err(404, "no such endpoint")

    def _create(self, body: dict) -> tuple[int, dict]:
        if USER_SCHEMA not in body.get("schemas", []):
            return _err(400, "missing core User schema")
        name = body.get("userName")
        if not isinstance(name, str) or not name:
            return _err(400, "userName required")
        if any(u["userName"] == name for u in self.users.values()):
            return _err(409, "userName already exists")
        unknown = set(body) - {"schemas", "userName", "externalId", "active", "roles", "displayName"}
        if unknown:
            return _err(400, "unknown attributes")
        uid = secrets.token_hex(6)
        rec = {
            "schemas": [USER_SCHEMA],
            "id": uid,
            "userName": name,
            "externalId": body.get("externalId"),
            "active": bool(body.get("active", True)),
            "roles": sorted(body.get("roles", [])),
        }
        self.users[uid] = rec
        return 201, rec

    def _patch(self, uid: str, body: dict) -> tuple[int, dict]:
        if PATCH_SCHEMA not in body.get("schemas", []):
            return _err(400, "missing PatchOp schema")
        rec = self.users[uid]
        for op in body.get("Operations", []):
            if op.get("op", "").lower() != "replace" or op.get("path") not in {"active", "roles"}:
                return _err(400, "only replace of active or roles is supported")
            if op["path"] == "active":
                if not isinstance(op.get("value"), bool):
                    return _err(400, "active must be boolean")
                rec["active"] = op["value"]
            else:
                rec["roles"] = sorted(op.get("value", []))
        return 200, rec

    # -- helpers used by the lifecycle engine and tests -------------------------------------------------
    def find(self, username: str) -> dict | None:
        return next((u for u in self.users.values() if u["userName"] == username), None)

    def account_active(self, username: str) -> bool:
        u = self.find(username)
        return bool(u and u["active"])

    def sso_login(self, username: str) -> str:
        if not self.account_active(username):
            raise AppError(f"{self.name}: no active account")
        return self.open_session(username)

    def usernames(self) -> list[str]:
        return [u["userName"] for u in self.users.values()]


def _hash_pw(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


@dataclass
class LocalAccountApp(BaseApp):
    """Legacy app with its own password accounts and no SCIM. Reached by a custom connector."""

    accounts: dict[str, dict] = field(default_factory=dict)
    connector_enabled: bool = True
    exports: list[tuple[str, int]] = field(default_factory=list)

    def create_local(self, username: str, password: str, roles: list[str]) -> None:
        if not self.connector_enabled:
            raise AppError(f"{self.name}: connector unavailable")
        salt = secrets.token_bytes(16)
        self.accounts[username] = {"salt": salt, "pw": _hash_pw(password, salt), "active": True, "roles": roles}

    def disable_local(self, username: str) -> bool:
        if not self.connector_enabled:
            raise AppError(f"{self.name}: connector unavailable")
        acct = self.accounts.get(username)
        if acct is None:
            return False
        acct["active"] = False
        return True

    def local_login(self, username: str, password: str) -> str:
        acct = self.accounts.get(username)
        if acct is None or not hmac.compare_digest(acct["pw"], _hash_pw(password, acct["salt"])):
            raise AppError(f"{self.name}: bad credentials")
        if not acct["active"]:
            raise AppError(f"{self.name}: account disabled")
        return self.open_session(username)

    def sso_login(self, username: str) -> str:
        acct = self.accounts.get(username)
        if acct is None or not acct["active"]:
            raise AppError(f"{self.name}: no active account")
        return self.open_session(username)

    def export_customers(self, sid: str, rows: int) -> int:
        user = self.session_user(sid)
        if user is None:
            raise AppError(f"{self.name}: not signed in")
        self.exports.append((user, rows))
        return rows

    def account_active(self, username: str) -> bool:
        a = self.accounts.get(username)
        return bool(a and a["active"])

    def usernames(self) -> list[str]:
        return list(self.accounts)
