#!/usr/bin/env python3
"""Google OAuth front door for the existing local REA 6.8.0 MCP server.

Never listen on a public interface. REA's original source and local endpoint
remain unchanged. Credentials are delivered by systemd LoadCredential.
"""
from pathlib import Path
import os
import re

from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.google import GoogleTokenVerifier
from fastmcp.server.providers.proxy import ProxyProvider, ProxyClient

BASE = "https://rea-reversa.duckdns.org"
REA_LOCAL = "http://127.0.0.1:8765/mcp"


def credential(name):
    base = Path(os.environ["CREDENTIALS_DIRECTORY"])
    value = (base / name).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("Missing credential: " + name)
    return value


client_id = credential("google-client-id")
client_secret = credential("google-client-secret")
owner_email = credential("google-owner-email").casefold()
if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", owner_email):
    raise RuntimeError("Invalid owner address")


class OwnerOnlyGoogleVerifier(GoogleTokenVerifier):
    def __init__(self):
        super().__init__(
            required_scopes=[
                "openid", "https://www.googleapis.com/auth/userinfo.email"
            ]
        )

    async def verify_token(self, token: str):
        result = await super().verify_token(token)
        if result is None or result.client_id != client_id:
            return None
        claims = result.claims or {}
        user = claims.get("google_user_data") or {}
        if not isinstance(user, dict) or user.get("verified_email") is not True:
            return None
        email = claims.get("email")
        if not isinstance(email, str) or email.casefold() != owner_email:
            return None
        return result


auth = OAuthProxy(
    upstream_authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
    upstream_token_endpoint="https://oauth2.googleapis.com/token",
    upstream_client_id=client_id,
    upstream_client_secret=client_secret,
    token_verifier=OwnerOnlyGoogleVerifier(),
    base_url=BASE,
    issuer_url=BASE,
    allowed_client_redirect_uris=[
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/*",
    ],
    require_authorization_consent=True,
    extra_authorize_params={"access_type": "offline", "prompt": "consent"},
)

gateway = FastMCP(
    "REA 6.8.0",
    auth=auth,
    providers=[ProxyProvider(lambda: ProxyClient(REA_LOCAL, mode="legacy"))],
)

if __name__ == "__main__":
    gateway.run(transport="http", host="127.0.0.1", port=8766)
