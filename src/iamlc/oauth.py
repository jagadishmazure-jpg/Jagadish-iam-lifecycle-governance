"""Delegated access for a partner app (OAuth-style), kept separate from sign-in.

A restaurant owner lets a third-party bookkeeping app read daily sales. The app never sees the owner's
password and gets an access token limited to `sales:read`. That token says nothing trustworthy about who
is using the bookkeeping app, so this module refuses to treat it as a login.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .idp import ISSUER, IdentityProvider, IdpError
from .tokens import TokenError, verify

PLATFORM_API = "https://api.zestlane.example"


@dataclass
class PartnerApi:
    idp: IdentityProvider
    sales: dict[str, list[int]] = field(default_factory=dict)  # restaurant owner id -> daily totals

    def read_sales(self, access_token: str) -> list[int]:
        claims = verify(access_token, self.idp.key, now=self.idp.clock.now, audience=PLATFORM_API, issuer=ISSUER)
        if self.idp.is_revoked(claims):
            raise TokenError("token revoked")
        if "sales:read" not in claims.get("scope", "").split():
            raise TokenError("scope sales:read missing")
        return self.sales.get(claims["sub"], [])

    def write_menu(self, access_token: str) -> None:
        claims = verify(access_token, self.idp.key, now=self.idp.clock.now, audience=PLATFORM_API, issuer=ISSUER)
        if "menu:write" not in claims.get("scope", "").split():
            raise TokenError("scope menu:write missing")


def login_with_access_token(access_token: str) -> None:
    """Deliberately refuses: an access token is for calling an API, not proof of sign-in."""
    raise IdpError("access tokens are not identity; use an OIDC ID token")
