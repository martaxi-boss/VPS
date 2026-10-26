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
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from datetime import datetime, timezone
from urllib import request as urlrequest
from urllib import error as urlerror
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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



def verify_committed_review_request(
        workflow_run, public_request, request_path, reviewed_commit,
        committed_request_bytes, *, now=None):
    """Require exact GitHub commit/blob provenance for the consent challenge.

    A TRUSTED GitHub REST client must fetch commit metadata and blob from the
    pinned repository at workflow_run['head_sha'], never from a mutable
    branch tip or user-supplied request parameters. This is preview code,
    not an MCP permission or a private GitHub credential.
    """
    sha = workflow_run.get("head_sha") if isinstance(workflow_run, dict) else None
    if (not isinstance(sha, str) or not gate.HEX40.fullmatch(sha) or
            not isinstance(reviewed_commit, dict) or
            reviewed_commit.get("sha") != sha):
        raise GithubOIDCError("Reviewed commit differs from approved run SHA")
    parents, files, stats = (reviewed_commit.get("parents"),
                             reviewed_commit.get("files"),
                             reviewed_commit.get("stats"))
    if (not isinstance(parents, list) or len(parents) != 1 or
            not isinstance(parents[0], dict) or
            not isinstance(parents[0].get("sha"), str) or
            not gate.HEX40.fullmatch(parents[0]["sha"]) or
            not isinstance(files, list) or len(files) != 1 or
            not isinstance(stats, dict)):
        raise GithubOIDCError("Reviewed commit must add exactly one request")
    entry = files[0]
    if (not isinstance(entry, dict) or
            entry.get("filename") != request_path or
            entry.get("status") != "added" or
            not isinstance(entry.get("sha"), str) or
            not gate.HEX40.fullmatch(entry["sha"])):
        raise GithubOIDCError("Reviewed commit added a different file")
    additions, deletions, changes = (
        entry.get("additions"), entry.get("deletions"), entry.get("changes"))
    if (any(type(value) is not int for value in (
            additions, deletions, changes, stats.get("additions"),
            stats.get("deletions"), stats.get("total"))) or
            additions < 1 or deletions != 0 or changes != additions or
            stats["additions"] != additions or
            stats["deletions"] != deletions or stats["total"] != changes):
        raise GithubOIDCError("Reviewed commit includes unapproved changes")
    if (not isinstance(committed_request_bytes, bytes) or
            not 0 < len(committed_request_bytes) <= 2000):
        raise GithubOIDCError("Missing or oversized reviewed Git blob")
    actual_blob_sha = hashlib.sha1(
        b"blob " + str(len(committed_request_bytes)).encode("ascii") +
        b"\x00" + committed_request_bytes).hexdigest()
    if actual_blob_sha != entry["sha"]:
        raise GithubOIDCError("Committed request blob SHA does not match")
    try:
        committed = json.loads(
            committed_request_bytes.decode("utf-8"),
            object_pairs_hook=gate._parse_no_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise GithubOIDCError("Invalid committed owner-review JSON") from exc
    if committed != public_request:
        raise GithubOIDCError("Review challenge differs from committed Git blob")
    gate.validate_review_request(
        committed, path=request_path, now=now or datetime.now(timezone.utc))
    return True

def verify_owner_review_oidc_and_consume_once(
        github_context, workflow_run, review_history, public_request,
        signed_task, jwt, owner_public_pem, trusted_contracts, *,
        request_path, reviewed_commit, committed_request_bytes,
        revocation_dir, private_spent_dir, now=None):
    """Preview-only replay gate: Git commit + owner approval + JWT + Ed25519.

    Called ONLY by trusted server code that obtains review_history and
    workflow_run directly from GitHub REST (never caller-supplied metadata),
    derives trusted_contracts from pinned REA source and provisioned owner key,
    and uses the GitHub issuer's pinned JWKS. This has NO connection to
    active MCP and returns NO permission to execute tools.

    A successful proof for a given request_id can be consumed once. Replays,
    revoked owner scopes, unsafe private directories or invalid signatures
    fail without rewriting any existing Evidence/Unknowns or grant files.
    """
    now = now or datetime.now(timezone.utc)
    verify_committed_review_request(
        workflow_run, public_request, request_path, reviewed_commit,
        committed_request_bytes, now=now)
    proof = verify_review_and_oidc_for_signed_task(
        github_context, workflow_run, review_history, public_request,
        signed_task, jwt, load_official_github_jwks(),
        request_path=request_path, now=now)
    from ops import rea_scoped_approval_20261026 as scoped
    # Independent Ed25519 verification against source-pinned contract scope.
    grant = scoped._verify_registration_contracts(
        signed_task, owner_public_pem, trusted_contracts,
        now=now, revocation_dir=revocation_dir)
    if grant["project"] != "Engenharia Reversa":
        raise GithubOIDCError("Unexpected owner-signed project")
    # PREPROVISIONED server-private store: do not create a grant, nonce ledger,
    # or review folder as a side effect of an untrusted request.
    directory = scoped._check_private_grant_directory(private_spent_dir)
    rid = proof["request_id"]   # Already strict 32-character lowercase hex.
    if not gate.HEX32.fullmatch(rid):
        raise GithubOIDCError("Invalid consumed approval identity")
    record = {
        "purpose": "REA_P311_SPENT_OWNER_OIDC_PREVIEW_V1",
        "request_id": rid,
        "run_id": proof["run_id"],
        "grant_id": grant["grant_id"],
        "operation_sha256": proof["operation_sha256"],
        "oidc_jti_sha256": hashlib.sha256(
            proof["jwt_jti"].encode("ascii")).hexdigest(),
    }
    marker = rid + ".spent"
    raw = json.dumps(record, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True).encode("ascii")
    # Pin the directory inode and atomically create the marker; path traversal
    # and symlink swaps are not able to redirect marker creation.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    # Pin the owner-private parent and child directory descriptors: an
    # intervening symlink or rename cannot redirect the spent marker.
    parentfd = os.open(directory.parent, flags)
    try:
        parent_meta = os.fstat(parentfd)
        if (not stat.S_ISDIR(parent_meta.st_mode) or
                parent_meta.st_uid != os.geteuid() or
                stat.S_IMODE(parent_meta.st_mode) != 0o700):
            raise GithubOIDCError("Unsafe parent for immutable review ledger")
        dirfd = os.open(directory.name, flags, dir_fd=parentfd)
        try:
            meta = os.fstat(dirfd)
            if (not stat.S_ISDIR(meta.st_mode) or
                    meta.st_uid != os.geteuid() or
                    stat.S_IMODE(meta.st_mode) != 0o700):
                raise GithubOIDCError("Unsafe immutable owner review ledger")
            try:
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
            except FileExistsError as exc:
                raise GithubOIDCError("Owner button proof has already been used") from exc
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Sync the directory entry too: fsync(file) alone cannot
            # guarantee the antireplay marker persists after a crash.
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        os.close(parentfd)
    return {
        "verified_spent_preview_only": True,
        "request_id": rid,
        "run_id": proof["run_id"],
        "grant_id": grant["grant_id"],
    }


# Optional, read-only REST adapter for a FUTURE trusted server. It cannot
# mint an OIDC token, sign for the owner, register a task or invoke MCP.
GITHUB_API_REPO = "https://api.github.com/repos/" + REPO
GITHUB_REST_MAX = 250000


def _p311_github_rest_get(resource, *, token, max_bytes=GITHUB_REST_MAX):
    """Read pinned repository evidence; reject redirects, large or duplicate JSON.

    The token must be supplied by a trusted server/Actions job, NEVER by
    arguments from a public challenge or an untrusted MCP tool.
    """
    if (not isinstance(resource, str) or
            not re.fullmatch(
                r"/(?:actions/runs/[1-9][0-9]{0,19}(?:/approvals)?"
                r"|commits/[0-9a-f]{40}|git/blobs/[0-9a-f]{40})",
                resource) or
            not isinstance(token, str) or not 20 <= len(token) <= 4096 or
            not isinstance(max_bytes, int) or not 0 < max_bytes <= GITHUB_REST_MAX):
        raise GithubOIDCError("Unsafe or missing GitHub owner-review fetch parameters")
    url = GITHUB_API_REPO + resource

    class NoRedirect(urlrequest.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise GithubOIDCError("GitHub evidence request redirected")

    req = urlrequest.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": "Bearer " + token,
        "User-Agent": "rea-p311-owner-proof-read-only",
    })
    try:
        with urlrequest.build_opener(NoRedirect()).open(req, timeout=12) as stream:
            if stream.geturl() != url:
                raise GithubOIDCError("GitHub evidence left pinned repository")
            raw = stream.read(max_bytes + 1)
    except (OSError, ValueError) as exc:
        raise GithubOIDCError("Trusted GitHub owner-review evidence unavailable") from exc
    if not 0 < len(raw) <= max_bytes:
        raise GithubOIDCError("GitHub evidence response outside permitted size")
    try:
        return json.loads(raw, object_pairs_hook=_json_unique)
    except (UnicodeError, ValueError) as exc:
        raise GithubOIDCError("Invalid GitHub owner-review evidence JSON") from exc


def fetch_trusted_owner_review_evidence(
        run_id, request_id, *, github_token, now=None):
    """Bind owner review and Git blob to fixed repo/run using live REST data.

    Never read the changing branch tip and never trust a caller's workflow
    context, reviewer list, commit metadata, request body or blob bytes.
    The GitHub API token is read-only and never printed or returned.
    """
    if (type(run_id) is not int or not 0 < run_id < 10**20 or
            not isinstance(request_id, str) or
            not gate.HEX32.fullmatch(request_id)):
        raise GithubOIDCError("Invalid pinned owner-review run/request ID")

    run = _p311_github_rest_get(
        "/actions/runs/" + str(run_id), token=github_token)
    if not isinstance(run, dict) or run.get("id") != run_id:
        raise GithubOIDCError("GitHub returned a different workflow run")
    # ONLY the future server-side consumption path requires a finished,
    # successful job. The in-job OIDC preview remains independently usable
    # while its own workflow is still in progress.
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise GithubOIDCError(
            "Owner-review workflow has not completed successfully")
    sha = run.get("head_sha")
    if not isinstance(sha, str) or not gate.HEX40.fullmatch(sha):
        raise GithubOIDCError("GitHub reviewed run SHA malformed")
    for identity in ("repository", "head_repository"):
        item = run.get(identity)
        if (not isinstance(item, dict) or item.get("full_name") != REPO or
                type(item.get("id")) is not int or
                str(item["id"]) != REPOSITORY_ID):
            raise GithubOIDCError("GitHub workflow run belongs to another repository")
    triggering = run.get("triggering_actor")
    if (not isinstance(triggering, dict) or
            triggering.get("login") != OWNER_LOGIN or
            triggering.get("id") != gate.OWNER_ID):
        raise GithubOIDCError("GitHub review run was rerun by another actor")
    ctx = {
        "repository": REPO,
        "actor": run.get("actor", {}).get("login") if isinstance(
            run.get("actor"), dict) else None,
        "triggering_actor": triggering["login"],
        "event": run.get("event"),
        "ref": "refs/heads/" + BRANCH,
        "sha": sha,
        "run_id": str(run_id),
        "attempt": str(run.get("run_attempt")),
    }
    # The review API is queried for this exact run, never by author name.
    reviews = _p311_github_rest_get(
        "/actions/runs/" + str(run_id) + "/approvals",
        token=github_token)
    if not isinstance(reviews, list) or not 1 <= len(reviews) <= 100:
        raise GithubOIDCError("Missing or excessive GitHub protected environment reviews")
    commit = _p311_github_rest_get("/commits/" + sha, token=github_token)
    if not isinstance(commit, dict) or commit.get("sha") != sha:
        raise GithubOIDCError("GitHub commit does not match reviewed run SHA")
    path = gate.REQUEST_DIRECTORY + "/" + request_id + ".json"
    files = commit.get("files")
    if (not isinstance(files, list) or len(files) != 1 or
            not isinstance(files[0], dict) or
            files[0].get("filename") != path or
            files[0].get("status") != "added" or
            not isinstance(files[0].get("sha"), str) or
            not gate.HEX40.fullmatch(files[0]["sha"])):
        raise GithubOIDCError("Reviewed commit is not a single added owner challenge")
    blob = _p311_github_rest_get(
        "/git/blobs/" + files[0]["sha"], token=github_token, max_bytes=12000)
    if (not isinstance(blob, dict) or blob.get("sha") != files[0]["sha"] or
            blob.get("encoding") != "base64" or
            type(blob.get("size")) is not int or
            not 0 < blob["size"] <= 2000 or
            not isinstance(blob.get("content"), str) or
            len(blob["content"]) > 4000):
        raise GithubOIDCError("Invalid GitHub challenge blob wrapper")
    encoded = blob["content"].replace("\n", "")
    try:
        committed = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise GithubOIDCError("Malformed GitHub challenge blob") from exc
    if len(committed) != blob["size"]:
        raise GithubOIDCError("GitHub challenge blob size mismatch")
    try:
        public = json.loads(committed.decode("utf-8"),
                            object_pairs_hook=gate._parse_no_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise GithubOIDCError("Invalid GitHub challenge body") from exc
    verify_committed_review_request(
        run, public, path, commit, committed, now=now)
    # Re-verify independently on the server. No owner review, no JWT and
    # no signed task is accepted on the basis of this object alone.
    gate.verify_github_review(
        ctx, run, reviews, public, request_path=path, now=now)
    return ctx, run, reviews, public, path, commit, committed


def verify_trusted_owner_review_oidc_and_consume_once(
        run_id, request_id, signed_task, jwt, owner_public_pem,
        trusted_contracts, *, github_token, revocation_dir,
        private_spent_dir, now=None):
    """Experimental trusted-entrypoint ONLY; NOT connected to tools/call.

    Reads the review+commit+blob independently from GitHub and performs the
    full existing JWT+Ed25519+revocation+one-use marker checks. Caller-supplied
    review/commit fields are not accepted, only opaque run and request IDs.
    A successful return is explicitly NOT a permission to use an MCP tool.
    """
    evidence = fetch_trusted_owner_review_evidence(
        run_id, request_id, github_token=github_token, now=now)
    ctx, run, reviews, public, path, commit, committed = evidence
    return verify_owner_review_oidc_and_consume_once(
        ctx, run, reviews, public, signed_task, jwt,
        owner_public_pem, trusted_contracts, request_path=path,
        reviewed_commit=commit, committed_request_bytes=committed,
        revocation_dir=revocation_dir, private_spent_dir=private_spent_dir,
        now=now)


def enroll_trusted_reviewed_task_offline_only(
        run_id, request_id, signed_task, jwt, owner_public_pem,
        trusted_contracts, *, github_token, private_registry_dir,
        revocation_dir, private_spent_dir, now=None):
    """Offline-only end-to-end staging; NEVER exposed by deployed MCP.

    The real owner Ed25519 key stays OFF the server. This must be called by
    trusted server code with the already-provisioned PUBLIC owner verifier,
    source-pinned tool contracts and server-private directories; no caller
    may provide an alternate key, project policy, or registry path.

    Fail closed: refuse an unprovisioned grant registry BEFORE consuming the
    GitHub proof. After a successful single-use proof, register exactly one
    owner-signed scope. If disk or registration fails at that point, the proof
    remains SPENT and requires explicit recovery, never an automatic retry.
    This is not a transaction/production permission and performs no MCP call.
    """
    from ops import rea_scoped_approval_20261026 as scoped
    timestamp = now or datetime.now(timezone.utc)
    # No untrusted request can create a new authorization store.
    scoped._check_private_grant_directory(private_registry_dir, create=False)
    proof = verify_trusted_owner_review_oidc_and_consume_once(
        run_id, request_id, signed_task, jwt, owner_public_pem,
        trusted_contracts, github_token=github_token,
        revocation_dir=revocation_dir, private_spent_dir=private_spent_dir,
        now=timestamp)
    if proof.get("verified_spent_preview_only") is not True:
        raise GithubOIDCError("Reviewed task was not cryptographically consumed")
    grant_id = scoped.register_signed_task_grant(
        signed_task, owner_public_pem,
        private_registry_dir=private_registry_dir,
        revocation_dir=revocation_dir,
        trusted_contracts=trusted_contracts, now=timestamp)
    if grant_id != proof["grant_id"]:
        raise GithubOIDCError("Registered grant did not match consumed consent")
    return {
        "registered_offline_stage_only": True,
        "grant_id": grant_id,
        "review_id": proof["request_id"],
        "run_id": proof["run_id"],
    }



def _actions_audience_request_url(source_url, public_request):
    """Bind the GitHub-provided job token endpoint to the exact reviewed task.

    GitHub-hosted runner hosts are sharded (pipelines*, not necessarily only
    pipelines). URLs, bearer credentials and JWT values are NEVER logged.
    A caller-provided arbitrary host, redirect, custom port or query is denied.
    """
    if not isinstance(source_url, str) or len(source_url) > 4096:
        raise GithubOIDCError("Missing trusted GitHub Actions token endpoint")
    parts = urlsplit(source_url)
    if (parts.scheme != "https" or parts.username is not None or
            parts.password is not None or parts.port is not None or
            parts.fragment or not isinstance(parts.hostname, str) or
            not re.fullmatch(r"pipelines[a-z0-9-]*\.actions\.githubusercontent\.com",
                             parts.hostname) or
            not parts.path.endswith("/idtoken")):
        raise GithubOIDCError("Unexpected GitHub Actions identity endpoint")
    params = parse_qsl(parts.query, keep_blank_values=True)
    if params != [("api-version", "2.0")]:
        raise GithubOIDCError("Unexpected GitHub Actions OIDC query")
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(params + [("audience", audience_for_review(
                           public_request))]), ""))


def request_actions_oidc_jwt(*, public_request, endpoint=None, bearer=None):
    """Get a fresh GitHub-signed JWT ONLY inside its approved Actions job.

    Fetches from the runner's trusted env URL with an ephemeral bearer.
    Never prints or writes the bearer or returned token to public logs.
    """
    endpoint = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") if endpoint is None else endpoint
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") if bearer is None else bearer
    if not isinstance(bearer, str) or not 50 <= len(bearer) <= 20000:
        raise GithubOIDCError("GitHub Actions job identity is unavailable")
    url = _actions_audience_request_url(endpoint, public_request)

    class NoRedirect(urlrequest.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise GithubOIDCError("GitHub identity redirected to another endpoint")

    req = urlrequest.Request(url, headers={
        "Authorization": "Bearer " + bearer,
        "Accept": "application/json",
        "User-Agent": "rea-p311-protected-review-only",
    })
    try:
        with urlrequest.build_opener(NoRedirect()).open(req, timeout=12) as stream:
            if stream.geturl() != url:
                raise GithubOIDCError("Unexpected OIDC identity endpoint")
            raw = stream.read(MAX_JWT_BYTES + 2000)
    except (OSError, ValueError) as exc:
        raise GithubOIDCError("GitHub job identity request failed") from exc
    if not 0 < len(raw) <= MAX_JWT_BYTES + 1000:
        raise GithubOIDCError("OIDC response size limit")
    try:
        response = json.loads(raw, object_pairs_hook=_json_unique)
    except (ValueError, UnicodeError) as exc:
        raise GithubOIDCError("OIDC identity response invalid") from exc
    token = response.get("value") if isinstance(response, dict) else None
    if not isinstance(token, str) or len(token) > MAX_JWT_BYTES:
        raise GithubOIDCError("GitHub did not issue a bounded identity JWT")
    return token


def preview_real_oidc_owner_button(*, request_path):
    """Actual GitHub-runner OIDC check, preview ONLY (no owner permission).

    This job verifies GitHub REST approval and source context independently.
    The token's audience binds the public digest and review nonce, but without
    the private Ed25519 grant it cannot confer any REA/MCP authority.
    """
    ctx = gate._runtime_context()
    if not isinstance(ctx.get("sha"), str):
        raise GithubOIDCError("Missing trusted checkout identity")
    selected = gate.selected_request_from_commit(ctx["sha"])
    if selected != request_path:
        raise GithubOIDCError("Owner preview request changed during job")
    public = gate._load_request(request_path)
    gate.validate_review_request(public, path=request_path)
    run_id = ctx.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise GithubOIDCError("Invalid GitHub workflow run identity")
    token = os.environ.get("GITHUB_TOKEN")
    workflow = gate._get_github_api(
        "/repos/martaxi-boss/VPS/actions/runs/" + run_id, token=token)
    reviews = gate._get_github_api(
        "/repos/martaxi-boss/VPS/actions/runs/" + run_id + "/approvals",
        token=token)
    proof = gate.verify_github_review(ctx, workflow, reviews, public,
                                      request_path=request_path)
    jwt = request_actions_oidc_jwt(public_request=public)
    jwks = load_official_github_jwks()
    identity = verify_github_oidc_jwt(
        jwt, jwks, public_request=public, workflow_run=workflow)
    if (identity["run_id"] != proof["run_id"] or
            identity["review_id"] != proof["request_id"] or
            identity["operation_sha256"] != proof["operation_sha256"]):
        raise GithubOIDCError("GitHub button and token disagree")
    return {"oidc_review_preview_only": True,
            "run_id": proof["run_id"], "request_id": proof["request_id"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="REA P311 OIDC preview - no VPS")
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)
    result = preview_real_oidc_owner_button(request_path=args.request)
    # Never print JWT, jti, signed grant, cryptographic keys or bearer.
    if result["oidc_review_preview_only"] is not True:
        raise GithubOIDCError("Owner button validation did not complete")
    print("REA_P311_GITHUB_OIDC_OWNER_PREVIEW=PASS")
    print("REA_P311_VPS_CHANGED=false")
    print("REA_P311_OWNER_PERMISSION_REGISTERED=false")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GithubOIDCError, gate.ApprovalGateError, KeyError, TypeError,
            OSError, RuntimeError, ValueError) as exc:
        print("REA_P311_GITHUB_OIDC_OWNER_PREVIEW=FAIL " +
              type(exc).__name__, file=sys.stderr)
        sys.exit(2)
