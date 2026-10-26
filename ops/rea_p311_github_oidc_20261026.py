"""P311 offline-only prototype for GitHub Actions OIDC owner-review evidence.

No grant enrollment, no MCP execution, no SSH change, and no modification to
the original REA motor. The JWT is a GitHub-signed proof of the *workflow job*,
not an owner Ed25519 signature and not, by itself, authorization for tools.

Security model (must ALL hold, never one OR the other):
  1. Live GitHub REST independently says the pinned owner approved the
     exact run, SHA, request digest and protected environment.
  2. A short-lived GitHub OIDC JWT, signed by GitHub's official keys, attests
     the same run, job, SHA, branch, owner, environment and exact audience.
  3. The VPS separately verifies owner-signed, revocable Ed25519 tool scope.
This module only implements 1+2, offline-testable; it does NOT implement 3.
"""
import base64
import json
import re
from datetime import datetime, timezone
from urllib import request as urlrequest
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from ops import rea_p311_owner_gate_20261026 as gate

ISSUER = "https://token.actions.githubusercontent.com"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
JWKS_URL = ISSUER + "/.well-known/jwks"
OWNER_LOGIN = gate.OWNER_LOGIN
OWNER_ID = str(gate.OWNER_ID)
REPO = gate.REPO
REPOSITORY_ID = "1386634013"
ENVIRONMENT = gate.REVIEW_ENVIRONMENT
BRANCH = gate.BRANCH
WORKFLOW_REF = REPO + "/" + gate.WORKFLOW + "@refs/heads/" + BRANCH
MAX_JWT_BYTES = 20000
MAX_TOKEN_AGE = 600
CLOCK_SKEW_SECONDS = 30
SUBJECTS = frozenset({
    "repo:" + REPO + ":environment:" + ENVIRONMENT,
    "repo:martaxi-boss@" + OWNER_ID + "/VPS@" + REPOSITORY_ID +
    ":environment:" + ENVIRONMENT,
})
SAFE_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
SAFE_JWT_ID = re.compile(r"[A-Za-z0-9_.:-]{8,128}\Z")


class GithubOIDCError(ValueError):
    pass


def _json_unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise GithubOIDCError("Repeated OIDC JSON attribute")
        value[key] = item
    return value


def _b64url(value):
    if not isinstance(value, str) or not SAFE_B64URL.fullmatch(value):
        raise GithubOIDCError("Malformed OIDC base64url")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4),
                                altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise GithubOIDCError("Malformed OIDC binary encoding") from exc


def _decoded_json(segment, maximum):
    data = _b64url(segment)
    if not 0 < len(data) <= maximum:
        raise GithubOIDCError("OIDC JSON part size limit")
    try:
        return json.loads(data, object_pairs_hook=_json_unique)
    except (UnicodeError, ValueError) as exc:
        raise GithubOIDCError("Invalid OIDC JSON") from exc


def _read_official_json(url, *, max_bytes=25000):
    """Fetch ONLY the GitHub issuer endpoints over TLS without redirects."""
    if url not in (DISCOVERY_URL, JWKS_URL):
        raise GithubOIDCError("Untrusted OIDC key source")
    # Avoid HTTP redirects to unrelated key providers.
    class NoRedirect(urlrequest.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise GithubOIDCError("Redirect from pinned GitHub issuer forbidden")
    opener = urlrequest.build_opener(NoRedirect())
    req = urlrequest.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "rea-p311-github-oidc-stage",
    })
    try:
        with opener.open(req, timeout=8) as stream:
            if stream.geturl() != url:
                raise GithubOIDCError("OIDC request left pinned GitHub endpoint")
            raw = stream.read(max_bytes + 1)
    except (OSError, ValueError) as exc:
        raise GithubOIDCError("Cannot load official GitHub OIDC public keys") from exc
    if not 0 < len(raw) <= max_bytes:
        raise GithubOIDCError("OIDC metadata too large")
    try:
        return json.loads(raw, object_pairs_hook=_json_unique)
    except (UnicodeError, ValueError) as exc:
        raise GithubOIDCError("Invalid OIDC public metadata") from exc


def load_official_github_jwks():
    """Trusted runtime would fetch keys from the fixed issuer, never caller URL.

    Tests inject synthetic JWKS explicitly; never copy JWTs into repo/logs.
    """
    config = _read_official_json(DISCOVERY_URL)
    if (not isinstance(config, dict) or config.get("issuer") != ISSUER or
            config.get("jwks_uri") != JWKS_URL):
        raise GithubOIDCError("Unexpected OIDC issuer or key location")
    jwks = _read_official_json(JWKS_URL)
    if (not isinstance(jwks, dict) or
            not isinstance(jwks.get("keys"), list) or
            not 1 <= len(jwks["keys"]) <= 16):
        raise GithubOIDCError("Unexpected GitHub OIDC key set")
    return jwks


def audience_for_review(public_request):
    if (not isinstance(public_request, dict) or
            set(public_request) != {
                "purpose", "request_id", "operation_sha256", "project", "expires_at"} or
            public_request["purpose"] != gate.PURPOSE or
            public_request["project"] != "Engenharia Reversa" or
            not isinstance(public_request["request_id"], str) or
            not gate.HEX32.fullmatch(public_request["request_id"]) or
            not isinstance(public_request["operation_sha256"], str) or
            not gate.HEX64.fullmatch(public_request["operation_sha256"])):
        raise GithubOIDCError("Invalid reviewed task challenge")
    return ("rea-p311-consent:" + public_request["request_id"] + ":" +
            public_request["operation_sha256"])


def _matching_rsa_jwk(jwks, kid):
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise GithubOIDCError("No trusted GitHub OIDC key set")
    matches = [key for key in jwks["keys"]
               if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        raise GithubOIDCError("OIDC signing key missing or ambiguous")
    key = matches[0]
    if (key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or
            key.get("alg", "RS256") != "RS256" or
            not isinstance(key.get("n"), str) or
            not isinstance(key.get("e"), str)):
        raise GithubOIDCError("OIDC key is not a trusted RSA signing key")
    n = int.from_bytes(_b64url(key["n"]), "big")
    e = int.from_bytes(_b64url(key["e"]), "big")
    if e != 65537 or not 2048 <= n.bit_length() <= 8192:
        raise GithubOIDCError("Unsafe RSA public-key parameters")
    try:
        return rsa.RSAPublicNumbers(e=e, n=n).public_key()
    except ValueError as exc:
        raise GithubOIDCError("Malformed RSA public key") from exc


def verify_github_oidc_jwt(jwt, trusted_jwks, *, public_request,
                           workflow_run, now=None):
    """Cryptographically bind a GitHub job to ONE already-reviewed challenge.

    The caller must independently retrieve verified run/reviewer data via
    GitHub REST; this function alone never verifies the human's click.
    Its return value cannot bypass the owner's Ed25519 grant verifier.
    """
    if not isinstance(jwt, str) or not 100 <= len(jwt) <= MAX_JWT_BYTES:
        raise GithubOIDCError("Missing or oversized OIDC JWT")
    pieces = jwt.split(".")
    if len(pieces) != 3:
        raise GithubOIDCError("JWT must contain exactly three pieces")
    header = _decoded_json(pieces[0], 1800)
    claims = _decoded_json(pieces[1], 10000)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise GithubOIDCError("OIDC header or claims not an object")
    if (header.get("typ") != "JWT" or header.get("alg") != "RS256" or
            not isinstance(header.get("kid"), str) or
            not 1 <= len(header["kid"]) <= 128 or
            any(field in header for field in (
                "jku", "x5u", "jwk", "x5c", "crit", "b64", "zip"))):
        raise GithubOIDCError("Untrusted OIDC JWT header")
    key = _matching_rsa_jwk(trusted_jwks, header["kid"])
    signature = _b64url(pieces[2])
    try:
        key.verify(signature, (pieces[0] + "." + pieces[1]).encode("ascii"),
                   padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError) as exc:
        raise GithubOIDCError("GitHub OIDC token signature invalid") from exc

    audience = audience_for_review(public_request)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise GithubOIDCError("OIDC validation needs timezone-aware UTC")
    current = now.timestamp()
    iat, nbf, exp = (claims.get("iat"), claims.get("nbf"),
                     claims.get("exp"))
    if (any(type(x) is not int for x in (iat, nbf, exp)) or
            not 0 < exp - iat <= MAX_TOKEN_AGE or
            iat > current + CLOCK_SKEW_SECONDS or
            nbf > current + CLOCK_SKEW_SECONDS or
            exp <= current - CLOCK_SKEW_SECONDS or
            current - iat > MAX_TOKEN_AGE or
            nbf > exp):
        raise GithubOIDCError("OIDC JWT outside short permitted window")

    if not isinstance(workflow_run, dict):
        raise GithubOIDCError("Untrusted workflow context")
    run_id = workflow_run.get("id")
    sha = workflow_run.get("head_sha")
    if (type(run_id) is not int or run_id <= 0 or
            not isinstance(sha, str) or not gate.HEX40.fullmatch(sha) or
            workflow_run.get("run_attempt") != 1):
        raise GithubOIDCError("Unexpected reviewed run binding")
    expected = {
        "iss": ISSUER,
        "aud": audience,
        "repository": REPO,
        "repository_id": REPOSITORY_ID,
        "repository_owner": OWNER_LOGIN,
        "repository_owner_id": OWNER_ID,
        "actor": OWNER_LOGIN,
        "actor_id": OWNER_ID,
        "environment": ENVIRONMENT,
        "workflow_ref": WORKFLOW_REF,
        "sha": sha,
        "run_id": str(run_id),
        "run_attempt": "1",
        "ref": "refs/heads/" + BRANCH,
        "ref_type": "branch",
        "event_name": "push",
        "runner_environment": "github-hosted",
    }
    for name, value in expected.items():
        if claims.get(name) != value:
            raise GithubOIDCError("OIDC claim did not match pinned owner workflow: " + name)
    jti = claims.get("jti")
    if (claims.get("sub") not in SUBJECTS or
            not isinstance(jti, str) or not SAFE_JWT_ID.fullmatch(jti)):
        raise GithubOIDCError("GitHub environment subject or nonce invalid")

    return {
        "attested_oidc_preview_only": True, "jti": jti,
        "run_id": run_id, "head_sha": sha,
        "review_id": public_request["request_id"],
        "operation_sha256": public_request["operation_sha256"],
    }


def verify_review_and_oidc_for_signed_task(
        github_context, workflow_run, review_history, public_request,
        signed_task, jwt, official_jwks, *, request_path, now=None):
    """Both platform human approval and JWT signature must pass.

    This returns NO owner authorization, no RSA private key and no MCP grant.
    The production bridge is NOT connected to this helper.
    """
    bound = gate.verify_and_bind_github_owner_review(
        github_context, workflow_run, review_history, public_request,
        signed_task, request_path=request_path, now=now)
    jwt_verified = verify_github_oidc_jwt(
        jwt, official_jwks, public_request=public_request,
        workflow_run=workflow_run, now=now)
    if (bound["run_id"] != jwt_verified["run_id"] or
            bound["operation_sha256"] != jwt_verified["operation_sha256"] or
            bound["request_id"] != jwt_verified["review_id"]):
        raise GithubOIDCError("GitHub review and signed JWT target differ")
    return {"owner_button_and_oidc_preview_only": True,
            "run_id": bound["run_id"],
            "request_id": bound["request_id"],
            "operation_sha256": bound["operation_sha256"],
            "jwt_jti": jwt_verified["jti"]}

