#!/usr/bin/env python3
"""P311: read-only proof of a REAL GitHub Environments approval button.

This module never signs a grant, changes the VPS, runs MCP tools, or replaces
the existing owner Ed25519 proof. A GitHub review is accepted as a *preview*
only when GitHub REST says the named account explicitly approved the exact
workflow run waiting for a protected environment.

The workflow runs only on the isolated P311 review branch, with no VPS secrets.
"""
import argparse
import base64
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "martaxi-boss/VPS"
BRANCH = "rea/p311-autonomia-escopos-20261026"
OWNER_LOGIN = "martaxi-boss"
OWNER_ID = 277365554
REVIEW_ENVIRONMENT = "rea-p311-owner-consent"
# Stable environment identity observed on the successful authentic GitHub review.
REVIEW_ENVIRONMENT_ID = 25387773772
WORKFLOW = ".github/workflows/rea-p311-owner-review-preview-20261026.yml"
REQUEST_DIRECTORY = "rea-linux/owner-review-requests"
PURPOSE = "REA_GITHUB_REVIEW_PREVIEW_V1"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class ApprovalGateError(ValueError):
    pass


def _timestamp(value):
    if not isinstance(value, str) or not ISO.fullmatch(value):
        raise ApprovalGateError("Review request requires an exact UTC expiry")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError as exc:
        raise ApprovalGateError("Invalid review expiry") from exc


def _parse_no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ApprovalGateError("Duplicate review request field")
        obj[key] = value
    return obj


def validate_review_request(request, *, path, now=None):
    if (not isinstance(request, dict) or set(request) != {
            "purpose", "request_id", "operation_sha256", "project", "expires_at"}):
        raise ApprovalGateError("Unexpected owner-review request schema")
    if request["purpose"] != PURPOSE or request["project"] != "Engenharia Reversa":
        raise ApprovalGateError("Review request is outside REA project")
    rid, digest = request["request_id"], request["operation_sha256"]
    if (not isinstance(rid, str) or not HEX32.fullmatch(rid) or
            not isinstance(digest, str) or not HEX64.fullmatch(digest)):
        raise ApprovalGateError("Review request has invalid identifiers")
    if path != f"{REQUEST_DIRECTORY}/{rid}.json":
        raise ApprovalGateError("Review request file and ID do not match")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ApprovalGateError("Review requires timezone-aware current time")
    seconds = (_timestamp(request["expires_at"]) - now).total_seconds()
    if not 0 < seconds <= 3600:
        raise ApprovalGateError("Owner-review request expired or too long-lived")
    return request


def signed_task_review_digest(signed_task, *, request_id):
    """Bind a public button review digest to ONE exact owner-signed enrollment.

    The public GitHub request stores ONLY this hash. The signed task must
    travel separately inside the EXISTING RSA-OAEP/AES-GCM request envelope.
    This function does NOT verify the Ed25519 signature or grant authority.
    Source-pinned schema/effect/owner checks remain mandatory in the VPS.
    """
    if not isinstance(request_id, str) or not HEX32.fullmatch(request_id):
        raise ApprovalGateError("Invalid owner review ID")
    if not isinstance(signed_task, dict) or set(signed_task) != {
            "grant", "owner_signature", "project", "task_id", "origin", "artifact_root"}:
        raise ApprovalGateError("Malformed task attached to owner review")
    grant = signed_task.get("grant")
    signature = signed_task.get("owner_signature")
    if (not isinstance(grant, dict) or
            set(grant) != {
                "purpose", "grant_id", "project", "task_id", "origin",
                "not_before", "expires_at", "allowed_tools",
                "permitted_effects", "artifact_root"} or
            grant.get("purpose") != "REA_OWNER_SCOPED_TASK_V1" or
            grant.get("origin") != "martaxi-boss/VPS:rea/one-skill-bridge-20261023" or
            not isinstance(signature, str) or
            not re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature) or
            not isinstance(grant.get("grant_id"), str) or
            not HEX32.fullmatch(grant["grant_id"]) or
            grant.get("project") != "Engenharia Reversa" or
            any(signed_task.get(key) != grant.get(key) for key in (
                "project", "task_id", "origin", "artifact_root"))):
        raise ApprovalGateError("Task review does not match owner-signed project")
    data = {
        "purpose": "REA_P311_GITHUB_TASK_REVIEW_BINDING_V1",
        "request_id": request_id,
        "operation": "sealed_task_enroll",
        "signed_task": signed_task,
    }
    try:
        # Canonical bytes agree with the REA Ed25519 signature format.
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ApprovalGateError("Unsafe signed task for owner review") from exc
    return hashlib.sha256(b"REA_P311_GITHUB_TASK_REVIEW_V1\x00" + canonical).hexdigest()


def prepare_owner_review_request(signed_task, *, expires_at,
                                 request_id=None, now=None):
    """Prepare ONLY a public SHA-256 challenge, not the owner-signed task.

    This is used AFTER offline owner Ed25519 signing and BEFORE asking for a
    GitHub button click. The full signed_task may ONLY travel in the existing
    encrypted GitHub->SSH bridge; it must never appear in a public request.
    """
    now = now or datetime.now(timezone.utc)
    rid = secrets.token_hex(16) if request_id is None else request_id
    digest = signed_task_review_digest(signed_task, request_id=rid)
    request = {
        "purpose": PURPOSE,
        "request_id": rid,
        "operation_sha256": digest,
        "project": "Engenharia Reversa",
        "expires_at": expires_at,
    }
    path = f"{REQUEST_DIRECTORY}/{rid}.json"
    validate_review_request(request, path=path, now=now)
    grant = signed_task["grant"]
    if not isinstance(grant["expires_at"], str):
        raise ApprovalGateError("Owner grant expiry is missing")
    # Approval must occur while the cryptographically signed task is valid.
    signed_expires = _timestamp(grant["expires_at"])
    signed_not_before = _timestamp(grant["not_before"])
    if not signed_not_before <= now < _timestamp(expires_at) <= signed_expires:
        raise ApprovalGateError("Review cannot outlive owner-signed task")
    return path, request


def match_verified_review_to_signed_task(preview_receipt, signed_task):
    """Check the exact reviewed enrollment without granting permission.

    Never accept a receipt from an untrusted request or tool argument. Only
    call after independent GitHub REST validation of the same real run,
    owner reviewer and protected environment, and then verify owner Ed25519.
    """
    if (not isinstance(preview_receipt, dict) or
            set(preview_receipt) != {
                "verified_preview", "request_id", "operation_sha256",
                "run_id", "review_environment"} or
            preview_receipt["verified_preview"] is not True or
            preview_receipt["review_environment"] != REVIEW_ENVIRONMENT or
            type(preview_receipt["run_id"]) is not int or
            preview_receipt["run_id"] <= 0):
        raise ApprovalGateError("Review proof has not been verified")
    actual = signed_task_review_digest(
        signed_task, request_id=preview_receipt["request_id"])
    if actual != preview_receipt["operation_sha256"]:
        raise ApprovalGateError("The GitHub click approved a DIFFERENT operation")
    return {
        "request_id": preview_receipt["request_id"],
        "operation_sha256": actual,
        "run_id": preview_receipt["run_id"],
        "bound_preview_only": True,
    }


def verify_and_bind_github_owner_review(
        github_context, workflow_run, review_history, public_request,
        signed_task, *, request_path, now=None):
    """Verify the real GitHub reviewer AND bind the exact Ed25519 task.

    Both checks are indispensable. The workflow run, review history and
    request must be fetched by a trusted GitHub API client, NEVER provided
    by user-controlled workflow/request JSON. Does not grant MCP authority:
    the VPS must still independently validate the Ed25519 signature and its
    source-audited effects, expiry, nonce and revocation.

    The earlier successful P311 demo proves the human button only; its
    arbitrary digest must NOT unlock an unrelated signed task.
    """
    verified = verify_github_review(
        github_context, workflow_run, review_history, public_request,
        request_path=request_path, now=now)
    result = match_verified_review_to_signed_task(verified, signed_task)
    return result





def _p311_github_read(resource, *, token):
    """Fixed-origin read-only GitHub REST; no redirects, duplicate JSON or logs."""
    if (not isinstance(resource, str) or
            not re.fullmatch(
                r"/(?:actions/runs/[1-9][0-9]{0,19}(?:/approvals)?"
                r"|commits/[0-9a-f]{40}|git/blobs/[0-9a-f]{40})",
                resource) or not isinstance(token, str) or
            not 20 <= len(token) <= 4096):
        raise ApprovalGateError("Invalid trusted GitHub REST review request")
    url = "https://api.github.com/repos/" + REPO + resource

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ApprovalGateError("Untrusted GitHub REST redirect")

    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "rea-p311-approval-button-only",
    })
    try:
        with urllib.request.build_opener(NoRedirect()).open(
                req, timeout=12) as stream:
            if stream.geturl() != url:
                raise ApprovalGateError("GitHub REST response changed origin")
            raw = stream.read(250001)
        if not 0 < len(raw) <= 250000:
            raise ApprovalGateError("GitHub REST response size exceeded")
        return json.loads(raw, object_pairs_hook=_parse_no_duplicates)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise ApprovalGateError("Trusted GitHub review unavailable") from exc


def _fetch_real_github_button_review(run_id, request_id, *,
                                     github_token, now=None):
    """One GitHub Approve/Reject: verify immutable single-file SHA and reviewer.

    Use ONLY the trusted Actions read token. No JWT, OIDC, encrypted identity
    artifact or second confirmation. Never trust caller-supplied review data.
    """
    if (type(run_id) is not int or not 0 < run_id < 10**20 or
            not isinstance(request_id, str) or not HEX32.fullmatch(request_id)):
        raise ApprovalGateError("Invalid review run or request")
    run = _p311_github_read(
        "/actions/runs/" + str(run_id), token=github_token)
    if (not isinstance(run, dict) or run.get("id") != run_id or
            run.get("status") != "completed" or
            run.get("conclusion") != "success"):
        raise ApprovalGateError("GitHub approval run is not successful")
    for field in ("repository", "head_repository"):
        repo = run.get(field)
        if (not isinstance(repo, dict) or
                repo.get("full_name") != REPO or
                type(repo.get("id")) is not int or
                repo["id"] != 1386634013):
            raise ApprovalGateError("Wrong GitHub repository identity")
    actor = run.get("triggering_actor")
    if (not isinstance(actor, dict) or
            actor.get("login") != OWNER_LOGIN or
            actor.get("id") != OWNER_ID):
        raise ApprovalGateError("GitHub re-run by another identity")
    sha = run.get("head_sha")
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise ApprovalGateError("Invalid GitHub commit identity")
    context = {
        "repository": REPO, "actor": run.get("actor", {}).get("login")
            if isinstance(run.get("actor"), dict) else None,
        "triggering_actor": actor["login"], "event": run.get("event"),
        "ref": "refs/heads/" + BRANCH, "sha": sha,
        "run_id": str(run_id), "attempt": str(run.get("run_attempt")),
    }
    reviews = _p311_github_read(
        "/actions/runs/" + str(run_id) + "/approvals",
        token=github_token)
    if not isinstance(reviews, list) or not 1 <= len(reviews) <= 100:
        raise ApprovalGateError("Missing authenticated GitHub owner approval")
    commit = _p311_github_read("/commits/" + sha, token=github_token)
    path = REQUEST_DIRECTORY + "/" + request_id + ".json"
    if (not isinstance(commit, dict) or commit.get("sha") != sha or
            not isinstance(commit.get("parents"), list) or
            len(commit["parents"]) != 1 or
            not isinstance(commit.get("files"), list) or
            len(commit["files"]) != 1):
        raise ApprovalGateError("GitHub review commit is not isolated")
    entry = commit["files"][0]
    if (not isinstance(entry, dict) or entry.get("filename") != path or
            entry.get("status") != "added" or
            not isinstance(entry.get("sha"), str) or
            not HEX40.fullmatch(entry["sha"])):
        raise ApprovalGateError("GitHub review commit contains another change")
    stats = commit.get("stats")
    if (not isinstance(stats, dict) or
            any(type(x) is not int for x in
                (entry.get("additions"), entry.get("deletions"),
                 entry.get("changes"), stats.get("additions"),
                 stats.get("deletions"), stats.get("total"))) or
            entry["additions"] < 1 or entry["deletions"] != 0 or
            entry["changes"] != entry["additions"] or
            stats["total"] != entry["changes"] or
            stats["additions"] != entry["additions"] or
            stats["deletions"] != 0):
        raise ApprovalGateError("Review commit had extra modifications")
    blob = _p311_github_read(
        "/git/blobs/" + entry["sha"], token=github_token)
    if (not isinstance(blob, dict) or
            blob.get("sha") != entry["sha"] or
            blob.get("encoding") != "base64" or
            type(blob.get("size")) is not int or
            not 0 < blob["size"] <= 2000 or
            not isinstance(blob.get("content"), str) or
            len(blob["content"]) > 4000):
        raise ApprovalGateError("GitHub review blob is untrusted")
    try:
        raw = base64.b64decode(
            blob["content"].replace("\n", ""), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ApprovalGateError("GitHub review blob has invalid encoding") from exc
    calculated = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()
    if len(raw) != blob["size"] or calculated != entry["sha"]:
        raise ApprovalGateError("GitHub reviewed SHA differs from public challenge")
    try:
        public = json.loads(raw.decode("utf-8"),
                            object_pairs_hook=_parse_no_duplicates)
    except (ValueError, UnicodeError) as exc:
        raise ApprovalGateError("GitHub reviewed challenge JSON is invalid") from exc
    return verify_github_review(
        context, run, reviews, public, request_path=path, now=now)


def register_task_after_github_approval(
        run_id, request_id, signed_task, owner_public_pem,
        trusted_contracts, *, github_token, private_registry_dir,
        revocation_dir, now=None):
    """One GitHub Approve/Reject click + an EXISTING scoped owner signature.

    Only enabled in the existing sealed SSH bridge for a server opt-in.
    GitHub REST, not user input, proves the exact run, owner, environment,
    reviewed commit and digest-only challenge. The existing Ed25519 verifier
    STILL checks the signed task, audited tool effects, expiry and revocation.

    No GitHub OIDC JWT, OIDC artifact or second confirmation is needed.
    The existing O_EXCL private grant registry serves as the one-use replay
    boundary: a second review cannot enroll the same signed grant twice.
    """
    from ops import rea_scoped_approval_20261026 as scoped
    # The registry may be provisioned only AFTER GitHub's independent
    # completed/success review and Ed25519 source-scope proof are both valid.
    # A public challenge by itself never creates the private store.
    # GitHub is the ONLY button authority. REST checks the completed run,
    # owner approval, protected environment and immutable challenge.
    proof = _fetch_real_github_button_review(
        run_id, request_id, github_token=github_token, now=now)
    bound = match_verified_review_to_signed_task(proof, signed_task)
    # Only sensitive tools can use the GitHub button. Ordinary read and
    # workspace tools stay on the unchanged existing REA policy.
    chosen = signed_task.get("grant", {}).get("allowed_tools", [])
    if (not isinstance(chosen, list) or not chosen or
            any(tool not in trusted_contracts or
                trusted_contracts[tool][1] != "sensitive" for tool in chosen)):
        raise ApprovalGateError("GitHub button grant is sensitive-only")
    # Independently verify the owner Ed25519 scope and revocation before
    # creating any new private approval state.
    scoped._verify_registration_contracts(
        signed_task, owner_public_pem, trusted_contracts,
        now=now, revocation_dir=revocation_dir)
    scoped._check_private_grant_directory(private_registry_dir, create=True)
    # Registration repeats the same checks; O_EXCL rejects replayed grants.
    grant_id = scoped.register_signed_task_grant(
        signed_task, owner_public_pem,
        private_registry_dir=private_registry_dir,
        revocation_dir=revocation_dir,
        trusted_contracts=trusted_contracts, now=now)
    return {
        "registered_button_only_offline_stage": True,
        "grant_id": grant_id,
        "run_id": bound["run_id"],
        "request_id": bound["request_id"],
    }


def selected_request_from_commit(commit, *, cwd="."):
    """Select a single NEW request; never execute deleted/modified files."""
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise ApprovalGateError("Invalid Git commit binding")
    result = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit],
        check=True, capture_output=True, text=True, cwd=cwd)
    changed = [line.split("\t", 1) for line in result.stdout.splitlines()]
    if len(changed) != 1 or changed[0][0] != "A":
        raise ApprovalGateError("Exactly one newly added owner-review request required")
    path = changed[0][1]
    if not re.fullmatch(
            r"rea-linux/owner-review-requests/[0-9a-f]{32}\.json", path):
        raise ApprovalGateError("Review request path outside isolated directory")
    return path


def _review_environment(review):
    if not isinstance(review, dict):
        raise ApprovalGateError("Invalid GitHub review")
    environments = review.get("environments")
    if not isinstance(environments, list):
        raise ApprovalGateError("Review omitted environment identity")
    return [env for env in environments
            if isinstance(env, dict) and
            env.get("name") == REVIEW_ENVIRONMENT and
            type(env.get("id")) is int and
            env["id"] == REVIEW_ENVIRONMENT_ID]


def verify_github_review(context, workflow_run, review_history, request,
                         *, request_path, now=None):
    """Validate platform-fetched proof; caller-supplied text is never identity.

    This only checks a preview gate. It returns no permission to run a tool
    or enroll any task, and must never be used as a substitute for Ed25519.
    """
    if not isinstance(context, dict) or not isinstance(workflow_run, dict):
        raise ApprovalGateError("Missing GitHub runtime identity")
    if (context.get("repository") != REPO or
            context.get("actor") != OWNER_LOGIN or
            context.get("triggering_actor") != OWNER_LOGIN or
            context.get("event") != "push" or
            context.get("ref") != f"refs/heads/{BRANCH}" or
            context.get("attempt") != "1"):
        raise ApprovalGateError("GitHub runtime is not the owner's isolated run")
    sha = context.get("sha")
    run_id = context.get("run_id")
    if (not isinstance(sha, str) or not HEX40.fullmatch(sha) or
            not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)):
        raise ApprovalGateError("GitHub run binding is invalid")
    if (workflow_run.get("id") != int(run_id) or
            workflow_run.get("event") != "push" or
            workflow_run.get("head_branch") != BRANCH or
            workflow_run.get("head_sha") != sha or
            workflow_run.get("run_attempt") != 1 or
            not isinstance(workflow_run.get("actor"), dict) or
            workflow_run["actor"].get("login") != OWNER_LOGIN or
            workflow_run["actor"].get("id") != OWNER_ID):
        raise ApprovalGateError("GitHub workflow run identity does not match")
    path = workflow_run.get("path")
    if (not isinstance(path, str) or
            path.split("@", 1)[0] != WORKFLOW):
        raise ApprovalGateError("Workflow source does not match reviewed code")
    validate_review_request(request, path=request_path, now=now)
    if not isinstance(review_history, list):
        raise ApprovalGateError("GitHub returned no trustworthy review history")
    approved = 0
    for review in review_history:
        if _review_environment(review):
            reviewer = review.get("user")
            # Rejections, pending actions, administrator bypasses by any
            # other identity or multiple approvals are all fail-closed.
            if (review.get("state") != "approved" or
                    not isinstance(reviewer, dict) or
                    reviewer.get("login") != OWNER_LOGIN or
                    reviewer.get("id") != OWNER_ID):
                raise ApprovalGateError("Review was not explicitly owner-approved")
            approved += 1
    if approved != 1:
        raise ApprovalGateError("No unique owner approval for this run/environment")
    return {"verified_preview": True,
            "request_id": request["request_id"],
            "operation_sha256": request["operation_sha256"],
            "run_id": int(run_id),
            "review_environment": REVIEW_ENVIRONMENT}


def _get_github_api(resource, *, token):
    if not isinstance(token, str) or len(token) < 20:
        raise ApprovalGateError("Missing ephemeral GitHub Actions API credential")
    if not isinstance(resource, str) or not resource.startswith(
            "/repos/martaxi-boss/VPS/actions/runs/"):
        raise ApprovalGateError("Untrusted GitHub API path")
    req = urllib.request.Request(
        "https://api.github.com" + resource, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "rea-p311-owner-review-preview",
        })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read(400001)
            if len(raw) > 400000:
                raise ApprovalGateError("Oversized GitHub review response")
            return json.loads(raw)
    except (urllib.error.URLError, ValueError) as exc:
        raise ApprovalGateError("Cannot verify GitHub owner-review evidence") from exc


def _runtime_context():
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "actor": os.environ.get("GITHUB_ACTOR"),
        "triggering_actor": os.environ.get("GITHUB_TRIGGERING_ACTOR"),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "ref": os.environ.get("GITHUB_REF"),
        "sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }


def _load_request(path):
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 2000:
        raise ApprovalGateError("Unsafe public review-preview request")
    return json.loads(target.read_text(encoding="utf-8"),
                      object_pairs_hook=_parse_no_duplicates)


def main(argv=None):
    parser = argparse.ArgumentParser(description="REA owner GitHub-button preview; no VPS effects")
    parser.add_argument("--mode", choices=("preflight", "verify-review"), required=True)
    parser.add_argument("--request", default=None)
    args = parser.parse_args(argv)
    ctx = _runtime_context()
    if args.mode == "preflight":
        path = selected_request_from_commit(ctx["sha"])
        validate_review_request(_load_request(path), path=path)
        out = Path(os.environ["GITHUB_OUTPUT"])
        with out.open("a", encoding="utf-8") as stream:
            stream.write("request_file=" + path + "\n")
        print("REA_P311_REVIEW_PREFLIGHT=PASS")
        return 0
    if not isinstance(args.request, str):
        raise ApprovalGateError("Review job omitted preflight request")
    path = selected_request_from_commit(ctx["sha"])
    if path != args.request:
        raise ApprovalGateError("Request path changed between review and preflight")
    token = os.environ.get("GITHUB_TOKEN")
    rid = ctx["run_id"]
    if not isinstance(rid, str) or not rid.isdecimal():
        raise ApprovalGateError("Invalid Actions run ID")
    run = _get_github_api(f"/repos/martaxi-boss/VPS/actions/runs/{rid}", token=token)
    reviews = _get_github_api(
        f"/repos/martaxi-boss/VPS/actions/runs/{rid}/approvals", token=token)
    proof = verify_github_review(
        ctx, run, reviews, _load_request(path), request_path=path)
    print("REA_P311_AUTHENTICATED_GITHUB_BUTTON_PREVIEW=PASS")
    print("REA_P311_REVIEW_RUN_ID=" + str(proof["run_id"]))
    # Never log full owner-sensitive request or signed authorization.
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ApprovalGateError, KeyError, TypeError, OSError,
            subprocess.CalledProcessError) as exc:
        print("REA_P311_GITHUB_BUTTON_PREVIEW=FAIL " + type(exc).__name__,
              file=sys.stderr)
        sys.exit(2)

