#!/usr/bin/env python3
"""One authenticated HTTPS front door for the unchanged local REA 6.8.0 MCP."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.google import GoogleTokenVerifier
from fastmcp.server.providers.proxy import ProxyClient, ProxyProvider
from fastmcp.client.transports import StreamableHttpTransport

PUBLIC_URL = "https://rea-reversa.duckdns.org"
ORIGINAL_REA_MCP = "http://127.0.0.1:8765/mcp"
# SHA256 of the owner's previously designated Google account, no email in repo.
OWNER_EMAIL_SHA256 = "1e7da28162a94b099ab657d91bb55be47478b593db0de66f0de36168e1867182"


def read_credential(name: str) -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory or not Path(directory).is_absolute():
        raise RuntimeError("Systemd LoadCredential directory is required")
    path = Path(directory) / name
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Missing REA Google OAuth credential: " + name)
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError("Empty REA Google OAuth credential: " + name)
    return value


client_id = read_credential("google-client-id")
client_secret = read_credential("google-client-secret")
if not re.fullmatch(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com", client_id):
    raise RuntimeError("Unexpected REA Google client ID")


class OwnerGoogleVerifier(GoogleTokenVerifier):
    """Fail closed unless Google verifies the explicitly authorized owner."""

    async def verify_token(self, token: str):
        verified = await super().verify_token(token)
        if verified is None:
            return None
        # FastMCP GoogleTokenVerifier returns client_id=Google's user sub, not
        # the OAuth application's ID. The validated audience is claims["aud"].
        claims = verified.claims or {}
        if claims.get("aud") != client_id:
            return None
        # Google returns either bool True or the literal "true" for this claim.
        if claims.get("email_verified") not in (True, "true"):
            return None
        email = claims.get("email")
        if not isinstance(email, str):
            return None
        fingerprint = hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()
        if fingerprint != OWNER_EMAIL_SHA256:
            return None
        return verified


auth = OAuthProxy(
    upstream_authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
    upstream_token_endpoint="https://oauth2.googleapis.com/token",
    upstream_client_id=client_id,
    upstream_client_secret=client_secret,
    token_verifier=OwnerGoogleVerifier(
        required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
        audience=client_id
    ),
    base_url=PUBLIC_URL,
    issuer_url=PUBLIC_URL,
    allowed_client_redirect_uris=[
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/*",
    ],
    require_authorization_consent=True,
    forward_resource=False,
    extra_authorize_params={"access_type": "offline", "prompt": "select_account consent"},
)

# This is only an authentication/transport front door. The sole tool registry
# remains on the original REA 6.8.0 process at 127.0.0.1:8765.
backend = ProxyProvider(
    lambda: ProxyClient(
        StreamableHttpTransport(
            ORIGINAL_REA_MCP,
            max_sse_event_size=16 * 1024 * 1024,
        ),
        forward_incoming_headers=False,
    ),
)
gateway = FastMCP("REA 6.8.0", auth=auth, providers=[backend])


if __name__ == "__main__":
    gateway.run(transport="http", host="127.0.0.1", port=8766)
