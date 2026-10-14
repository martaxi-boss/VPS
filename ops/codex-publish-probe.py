#!/usr/bin/env python3
"""Owner-only, NO-MODEL, NO-WRITE dry-run of the existing Codex publisher push."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = "martaxi-boss/Project-leader-codex"
BRANCH = "codex/issue-134-38235356661-1-1"
# Targets and branch refs are fixed in trusted code. No Issue body, arbitrary
# repo, or caller-controlled Git URL can reach this privileged dry-run.
PINK_REPO = "martaxi-boss/pink-iptv"
PINK_BRANCH = "codex/issue-224-38578348749-1"
PROBES = {
    "codex": (REPO, BRANCH),
    "pink": (PINK_REPO, PINK_BRANCH),
}
CATEGORIES = {
    "authentication": ("authentication failed", "bad credentials",
                       "invalid username", "could not read username"),
    "permission_denied": ("write access to repository not granted", "permission to",
                          "requested url returned error: 403", "http 403",
                          "remote: permission", "you are not allowed to push"),
    "branch_rules": ("gh013", "gh006", "repository rule", "protected branch",
                     "ruleset", "create branch not permitted"),
    "remote_not_found": ("repository not found", "could not read from remote repository"),
    "network_failure": ("could not resolve host", "failed to connect", "connection timed out"),
}

def classify(output: str, status: int) -> str:
    if status == 0:
        return "accepted_dry_run"
    low = output.casefold()
    for code, phrases in CATEGORIES.items():
        if any(phrase in low for phrase in phrases):
            return code
    return "other_git_failure"

def call(args, *, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, text=True,
                          capture_output=True, check=False, timeout=50)

def publisher_module():
    file = Path(__file__).with_name("codex-autonomous-publish.py")
    spec = importlib.util.spec_from_file_location("trusted_codex_publisher", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def diagnose(target: str = "codex"):
    if target not in PROBES:
        raise ValueError("Unsupported fixed publication probe target")
    repo, branch = PROBES[target]
    git_url = "https://github.com/" + repo + ".git"
    result = {"status": "NOT_COMPLETED",
              "repo": repo,
              "probe_branch": branch,
              "permission_flag": "unknown", "api_check": "unknown",
              "normal": "not_attempted", "no_helper": "not_attempted",
              "models_called": False, "git_writes": False}
    if not os.environ.get("CODEX_GITHUB_TOKEN"):
        result["status"] = "MISSING_SECRET"
        return result
    publisher = publisher_module()
    try:
        info = publisher.api("GET", f"repos/{repo}")
        result["api_check"] = "ok"
        result["permission_flag"] = (
            "push_true" if info.get("permissions", {}).get("push") is True
            else "push_not_confirmed"
        )
    except RuntimeError as error:
        # Only an exact, bounded HTTP class leaves this process. The raw
        # exception / API payload must never reach an issue comment or log.
        code = str(error).rsplit(" HTTP ", 1)[-1]
        result["api_check"] = {
            "401": "http_401", "403": "http_403", "404": "http_404",
            "429": "http_429", "500": "http_5xx", "502": "http_5xx",
            "503": "http_5xx", "504": "http_5xx",
        }.get(code, "other_api_error")
    except (KeyError, TypeError, ValueError, OSError):
        result["api_check"] = "other_api_error"
    # A REST permission query is NOT proof of Git push rights and may fail
    # independently. Always test the actual Git publisher before deciding.
    with tempfile.TemporaryDirectory(prefix="codex-publish-dry-run-") as temporary:
        root = Path(temporary)
        checkout = root / "target"
        try:
            cloned = call(["git", "clone", "--quiet", "--depth", "1",
                           "--branch", "main", "--", git_url, str(checkout)])
            if cloned.returncode:
                result["normal"] = classify(cloned.stdout + cloned.stderr, cloned.returncode)
                result["status"] = "CLONE_FAILED"
                return result
            existing = call(["git", "ls-remote", "--heads", "origin",
                             "refs/heads/" + branch], cwd=checkout)
            if existing.returncode or existing.stdout.strip():
                result["status"] = "BRANCH_NOT_AVAILABLE_FOR_SAFE_PROBE"
                return result
            env = publisher.git_push_environment(root)
            # Same credential and argument ordering as the real publisher,
            # with --dry-run added. Never create a ref or spend model tokens.
            normal = call(["git", "push", "--dry-run", "--porcelain",
                           "origin", "HEAD:refs/heads/" + branch],
                          cwd=checkout, env=env)
            result["normal"] = classify(normal.stdout + normal.stderr, normal.returncode)
            if normal.returncode:
                # Distinguishes an inherited git credential helper from
                # target token/rules failures. Still no remote writes.
                forced = call(["git", "-c", "credential.helper=", "push",
                               "--dry-run", "--porcelain", "origin",
                               "HEAD:refs/heads/" + BRANCH],
                              cwd=checkout, env=env)
                result["no_helper"] = classify(
                    forced.stdout + forced.stderr, forced.returncode)
            if normal.returncode:
                result["status"] = "DRY_RUN_REFUSED"
            elif result["api_check"] != "ok":
                result["status"] = "PERMISSION_QUERY_FAILED"
            elif result["permission_flag"] != "push_true":
                result["status"] = "PERMISSION_DENIED"
            else:
                result["status"] = "DRY_RUN_ACCEPTED"
        except (OSError, subprocess.TimeoutExpired, ValueError):
            result["status"] = "PROBE_ERROR"
    return result

if __name__ == "__main__":
    # Never print raw Git or API output: it may contain credential details.
    # Only the workflow's exact Owner-authored Issue title selects this fixed
    # profile; arbitrary strings fail before any secret or Git operation.
    print(json.dumps(diagnose(os.environ.get("CODEX_PUBLISH_PROBE_TARGET", "codex")),
                     sort_keys=True))
