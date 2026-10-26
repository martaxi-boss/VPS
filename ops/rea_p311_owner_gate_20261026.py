#!/usr/bin/env python3
"""P311: read-only proof of a REAL GitHub Environments approval button.

This module never signs a grant, changes the VPS, runs MCP tools, or replaces
the existing owner Ed25519 proof. A GitHub review is accepted as a *preview*
only when GitHub REST says the named account explicitly approved the exact
workflow run waiting for a protected environment.

The workflow runs only on the isolated P311 review branch, with no VPS secrets.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "martaxi-boss/VPS"
BRANCH = "rea/p311-autonomia-escopos-20261026"
OWNER_LOGIN = "martaxi-boss"
OWNER_ID = 277365554
REVIEW_ENVIRONMENT = "rea-p311-owner-consent"
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
            isinstance(env.get("id"), int) and env["id"] > 0]


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

