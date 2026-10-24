"""Mock identity provider: sign-in, OIDC authorization-code flow, SAML-style assertions, refresh-token
rotation and revocation.

Important property, proven in tests: disabling a user here blocks *new* sign-ins and refreshes, but it does
not reach into applications. A session an app already created, or an access token already issued, keeps
working until it is revoked or expires. The leaver flow therefore has to revoke and kill explicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from .authn import assurance, is_mfa
from .clock import HOUR, MINUTE, Clock
from .directory import Directory
from .pii import SafeError
from .tokens import sign

ISSUER = "https://idp.zestlane.example"


class IdpError(SafeError):
    pass


@dataclass
class Client:
    client_id: str
    secret_hash: str
    redirect_uris: tuple[str, ...]
    kind: str = "oidc"  # oidc | saml | oauth_partner
    allowed_scopes: frozenset[str] = frozenset({"openid", "profile"})
    resource: str | None = None  # audience for access tokens; defaults to the client id


@dataclass
class IdpSession:
    sid: str
    user_id: str
    factors: tuple[str, ...]
    created: int
    revoked: bool = False


@dataclass
class IdentityProvider:
    clock: Clock
    directory: Directory
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    clients: dict[str, Client] = field(default_factory=dict)
    sessions: dict[str, IdpSession] = field(default_factory=dict)
    codes: dict[str, dict] = field(default_factory=dict)
    refresh: dict[str, dict] = field(default_factory=dict)  # token hash -> record
    not_before: dict[str, int] = field(default_factory=dict)  # user_id -> tokens issued before are revoked
    access_ttl: int = 15 * MINUTE
    refresh_ttl: int = 8 * HOUR

    # ---- registration -------------------------------------------------------------------------------
    def register(self, client_id: str, secret: str, redirect_uris: tuple[str, ...], **kw) -> Client:
        c = Client(client_id, hashlib.sha256(secret.encode()).hexdigest(), redirect_uris, **kw)
        self.clients[client_id] = c
        return c

    def _client(self, client_id: str, secret: str | None = None) -> Client:
        c = self.clients.get(client_id)
        if c is None:
            raise IdpError("unknown client")
        if secret is not None and not hmac.compare_digest(c.secret_hash, hashlib.sha256(secret.encode()).hexdigest()):
            raise IdpError("bad client secret")
        return c

    # ---- sign-in ------------------------------------------------------------------------------------
    def authenticate(self, user_id: str, factors: list[str], require_mfa: bool = True) -> IdpSession:
        u = self.directory.users.get(user_id)
        if u is None or not u.enabled:
            raise IdpError("sign-in refused: account disabled or unknown")
        if require_mfa and not is_mfa(factors):
            raise IdpError("sign-in refused: MFA required")
        s = IdpSession(secrets.token_urlsafe(16), user_id, tuple(factors), self.clock.now)
        self.sessions[s.sid] = s
        return s

    def _live_session(self, sid: str) -> IdpSession:
        s = self.sessions.get(sid)
        if s is None or s.revoked:
            raise IdpError("no IdP session")
        u = self.directory.users.get(s.user_id)
        if u is None or not u.enabled:
            raise IdpError("account disabled")
        return s

    # ---- OIDC authorization-code flow ---------------------------------------------------------------
    def authorize(self, client_id: str, redirect_uri: str, sid: str, scope: set[str], state: str, nonce: str) -> str:
        c = self._client(client_id)
        if redirect_uri not in c.redirect_uris:
            raise IdpError("redirect_uri not registered")
        if not scope <= c.allowed_scopes:
            raise IdpError("scope not allowed for this client")
        s = self._live_session(sid)
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "user_id": s.user_id,
            "scope": sorted(scope),
            "nonce": nonce,
            "state": state,
            "exp": self.clock.now + MINUTE,
            "factors": list(s.factors),
        }
        return code

    def exchange(self, code: str, client_id: str, secret: str, redirect_uri: str) -> dict:
        rec = self.codes.pop(code, None)  # one use only
        self._client(client_id, secret)
        if rec is None:
            raise IdpError("code unknown or already used")
        if rec["client_id"] != client_id or rec["redirect_uri"] != redirect_uri:
            raise IdpError("code was issued to another client or redirect")
        if self.clock.now >= rec["exp"]:
            raise IdpError("code expired")
        u = self.directory.users.get(rec["user_id"])
        if u is None or not u.enabled:
            raise IdpError("account disabled")
        aud = self.clients[client_id].resource or client_id
        out = {"access_token": self._access(rec["user_id"], aud, rec["scope"])}
        if "openid" in rec["scope"]:
            out["id_token"] = sign(
                {
                    "iss": ISSUER,
                    "aud": client_id,
                    "sub": rec["user_id"],
                    "nonce": rec["nonce"],
                    "iat": self.clock.now,
                    "exp": self.clock.now + 5 * MINUTE,
                    "amr": rec["factors"],
                    "acr": assurance(rec["factors"]),
                },
                self.key,
            )
        out["refresh_token"] = self._new_refresh(rec["user_id"], client_id, rec["scope"], family=None)
        return out

    def _access(self, user_id: str, aud: str, scope: list[str]) -> str:
        return sign(
            {
                "iss": ISSUER,
                "aud": aud,
                "sub": user_id,
                "scope": " ".join(scope),
                "iat": self.clock.now,
                "exp": self.clock.now + self.access_ttl,
                "jti": secrets.token_hex(8),
            },
            self.key,
        )

    def _new_refresh(self, user_id: str, client_id: str, scope: list[str], family: str | None) -> str:
        tok = secrets.token_urlsafe(24)
        self.refresh[hashlib.sha256(tok.encode()).hexdigest()] = {
            "user_id": user_id,
            "client_id": client_id,
            "scope": scope,
            "family": family or secrets.token_hex(6),
            "exp": self.clock.now + self.refresh_ttl,
            "used": False,
            "revoked": False,
        }
        return tok

    def refresh_tokens(self, refresh_token: str, client_id: str) -> dict:
        rec = self.refresh.get(hashlib.sha256(refresh_token.encode()).hexdigest())
        if rec is None or rec["client_id"] != client_id:
            raise IdpError("refresh token unknown")
        if rec["used"]:
            # reuse of a rotated token: assume theft, kill the whole family
            for r in self.refresh.values():
                if r["family"] == rec["family"]:
                    r["revoked"] = True
            raise IdpError("refresh token reuse detected; family revoked")
        if rec["revoked"] or self.clock.now >= rec["exp"]:
            raise IdpError("refresh token revoked or expired")
        u = self.directory.users.get(rec["user_id"])
        if u is None or not u.enabled:
            raise IdpError("account disabled")
        rec["used"] = True
        aud = self.clients[client_id].resource or client_id
        return {
            "access_token": self._access(rec["user_id"], aud, rec["scope"]),
            "refresh_token": self._new_refresh(rec["user_id"], client_id, rec["scope"], rec["family"]),
        }

    # ---- revocation ---------------------------------------------------------------------------------
    def revoke_user(self, user_id: str) -> int:
        """Revoke IdP sessions and refresh tokens, and publish a not-before time for access tokens."""
        n = 0
        for s in self.sessions.values():
            if s.user_id == user_id and not s.revoked:
                s.revoked, n = True, n + 1
        for r in self.refresh.values():
            if r["user_id"] == user_id and not r["revoked"]:
                r["revoked"], n = True, n + 1
        self.not_before[user_id] = self.clock.now + 1
        return n

    def is_revoked(self, claims: dict) -> bool:
        """Resource servers that check this list stop accepting tokens issued before revocation."""
        nb = self.not_before.get(claims.get("sub", ""))
        return nb is not None and claims.get("iat", 0) < nb

    # ---- SAML-style assertion -----------------------------------------------------------------------
    def saml_assertion(self, sp_entity_id: str, sid: str) -> dict:
        c = self._client(sp_entity_id)
        if c.kind != "saml":
            raise IdpError("client is not a SAML service provider")
        s = self._live_session(sid)
        body = (
            f"<Assertion Issuer='{ISSUER}' Audience='{sp_entity_id}' Subject='{s.user_id}' "
            f"NotBefore='{self.clock.now}' NotOnOrAfter='{self.clock.now + 5 * MINUTE}' "
            f"AuthnContext='{assurance(list(s.factors))}'/>"
        )
        sig = hmac.new(self.key, body.encode(), hashlib.sha256).hexdigest()
        return {"assertion": body, "signature": sig}

    def verify_saml(self, sp_entity_id: str, msg: dict) -> str:
        body, sig = msg.get("assertion", ""), msg.get("signature", "")
        expected = hmac.new(self.key, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise IdpError("assertion signature invalid")
        attrs = dict(part.split("=", 1) for part in body.strip("<>/ ").split(" ")[1:])
        attrs = {k: v.strip("'") for k, v in attrs.items()}
        if attrs.get("Audience") != sp_entity_id:
            raise IdpError("assertion meant for another service")
        if attrs.get("Issuer") != ISSUER:
            raise IdpError("assertion from untrusted issuer")
        if not (int(attrs["NotBefore"]) <= self.clock.now < int(attrs["NotOnOrAfter"])):
            raise IdpError("assertion outside its validity window")
        return attrs["Subject"]
