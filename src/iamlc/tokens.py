"""Compact signed tokens (JWT layout, HS256) using only the standard library.

A JWT is a format for signed claims. It is not a sign-in protocol; OIDC uses it for the ID token and many
platforms use it for access tokens. Verification rejects `alg: none`, wrong audience, wrong issuer and
expired tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .pii import SafeError


class TokenError(SafeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(claims: dict, key: bytes) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64(hmac.new(key, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify(token: str, key: bytes, *, now: int, audience: str, issuer: str) -> dict:
    try:
        header_s, body_s, sig_s = token.split(".")
        header = json.loads(_unb64(header_s))
        claims = json.loads(_unb64(body_s))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed token") from exc
    if header.get("alg") != "HS256":
        raise TokenError("unexpected algorithm")
    expected = _b64(hmac.new(key, f"{header_s}.{body_s}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig_s):
        raise TokenError("bad signature")
    if claims.get("iss") != issuer:
        raise TokenError("wrong issuer")
    if claims.get("aud") != audience:
        raise TokenError("wrong audience")
    if not isinstance(claims.get("exp"), int) or now >= claims["exp"]:
        raise TokenError("expired")
    return claims


def unverified_claims(token: str) -> dict:
    """For display only. Never use for decisions."""
    return json.loads(_unb64(token.split(".")[1]))
