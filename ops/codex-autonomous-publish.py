#!/usr/bin/env python3
"""Trusted GitHub Actions side of Codex execution; never execute an agent patch.

Codex runs remotely without any GitHub write credential. This separate process
validates its patch, pushes an isolated branch, waits for target-repository CI,
and merges only a correctly evidenced, exact-head PR without bypassing policies.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from codex_patch_guard import MAX_FILES, MAX_PATCH_BYTES, guard_path

ALLOWED = {
    "martaxi-boss/VPS": {( "Codex autonomous validation", "pull_request")},
    "martaxi-boss/Project-leader": {
        ("Control contract tests", "pull_request"),
        ("Validate control plane", "pull_request"),
        ("Package ChatGPT plugins", "pull_request"),
        ("Trusted authorization gate", "pull_request_target"),
    },
}
TERMINAL_FAILURES = {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
MAX_WAIT_SECONDS = 900


def run(*args, cwd=None, env=None, capture=True):
    return subprocess.run(args, cwd=cwd, env=env, check=True,
                          text=True, capture_output=capture)


def api(method, route, data=None):
    url = "https://api.github.com/" + route.lstrip("/")
    headers = {
        "Authorization": "Bearer " + os.environ["CODEX_GITHUB_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "project-leader-codex-autonomous/1",
    }
    payload = None if data is None else json.dumps(data).encode("utf-8")
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, method=method, headers=headers, data=payload)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        # GitHub errors do not contain our secret, but do not echo response payloads.
        raise RuntimeError(f"GitHub {method} {route.split('?')[0]} HTTP {error.code}") from error


def current_main(repo):
    ref = api("GET", f"repos/{repo}/git/ref/heads/main")
    return ref["object"]["sha"]


def classify_runs(runs, expected, commit_sha, branch):
    """Return (state, detail) from independently observed exact SHA checks."""
    latest = {}
    for item in runs:
        if item.get("head_sha") != commit_sha:
            continue
        if item.get("head_branch") not in (branch, None):
            continue
        key = (item.get("name"), item.get("event"))
        if item.get("event") not in ("pull_request", "pull_request_target"):
            continue
        old = latest.get(key)
        if old is None or item.get("created_at", "") >= old.get("created_at", ""):
            latest[key] = item
    for key, item in latest.items():
        if item.get("status") == "completed" and item.get("conclusion") in TERMINAL_FAILURES:
            return "BLOCKED", f"Required or related CI failed: {key[0]}"
    missing = expected.difference(latest)
    if missing:
        return "WAIT", "Missing checks: " + ", ".join(sorted(n for n, _ in missing))
    pending = [key[0] for key in expected if latest[key].get("status") != "completed"]
    if pending:
        return "WAIT", "Running checks: " + ", ".join(sorted(pending))
    bad = [key[0] for key in expected if latest[key].get("conclusion") != "success"]
    if bad:
        return "BLOCKED", "Required checks not successful: " + ", ".join(sorted(bad))
    return "PASS", "All named workflows passed on exact head"


def safe_changed_paths(checkout):
    result = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "-z"], cwd=checkout
    )
    paths = [x.decode("utf-8", "strict") for x in result.split(b"\0") if x]
    if not paths or len(paths) > MAX_FILES:
        raise ValueError("Empty patch or too many changed paths")
    # Reject new symlinks and gitlinks even when a diff patch hides their mode.
    modes = {}
    for entry in subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=checkout).split(b"\0"):
        if entry:
            info, path = entry.split(b"\t", 1)
            modes[path.decode("utf-8", "strict")] = info.split(b" ", 1)[0].decode("ascii")
    for name in paths:
        if name in modes and modes[name] not in ("100644", "100755"):
            raise ValueError("Unsafe Git file mode for: " + name)
    old_cwd = os.getcwd()
    try:
        os.chdir(checkout)
        for name in paths:
            guard_path(name)
    finally:
        os.chdir(old_cwd)
    return paths


def git_push_environment(temporary):
    askpass = temporary / "git-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\ncase \"$1\" in\n"
        "  *Username*) printf 'x-access-token' ;;\n"
        '  *Password*) printf "%s" "$CODEX_GITHUB_TOKEN" ;;\n'
        "  *) exit 1 ;;\nesac\n", encoding="utf-8"
    )
    askpass.chmod(0o700)
    return {**os.environ, "GIT_ASKPASS": str(askpass), "GIT_TERMINAL_PROMPT": "0"}


def validate_metadata(source):
    repo = (source / "target.txt").read_text(encoding="utf-8").strip()
    sha = (source / "base-sha.txt").read_text(encoding="utf-8").strip()
    task = (source / "codex-task.txt").read_text(encoding="utf-8")
    if repo not in ALLOWED or task.splitlines()[0] != "TARGET_REPOSITORY=" + repo:
        raise ValueError("Untrusted or unsupported repository")
    if len(sha) != 40 or any(x not in "0123456789abcdef" for x in sha):
        raise ValueError("Invalid clone/base revision")
    patch = source / "patch.diff"
    if not patch.exists() or patch.stat().st_size > MAX_PATCH_BYTES:
        raise ValueError("Missing or oversized patch")
    return repo, sha, patch


def wait_for_checks(repo, sha, branch, expected):
    until = time.monotonic() + MAX_WAIT_SECONDS
    detail = "No checks observed"
    while time.monotonic() < until:
        response = api("GET", "repos/" + repo + "/actions/runs?" +
                       urllib.parse.urlencode({"head_sha": sha, "per_page": 100}))
        state, detail = classify_runs(response.get("workflow_runs", []), expected, sha, branch)
        if state != "WAIT":
            return state, detail
        time.sleep(10)
    return "BLOCKED", "Timed out awaiting exact-SHA CI: " + detail


def perform(source, issue, run_id, attempt):
    repo, base_sha, patch = validate_metadata(source)
    if patch.stat().st_size == 0:
        return {"status": "NO_CHANGE", "repository": repo,
                "reason": "Codex finished but did not alter any project files"}
    if current_main(repo) != base_sha:
        raise RuntimeError("STALE_BASE: main advanced after Codex cloned; require a fresh run")

    branch = f"codex/issue-{issue}-{run_id}-{attempt}"
    with tempfile.TemporaryDirectory(prefix="codex-publish-") as temp:
        root = Path(temp)
        work = root / "target"
        run("git", "clone", "--quiet", "--depth", "1", "--branch", "main",
            "--", "https://github.com/" + repo + ".git", str(work))
        if run("git", "rev-parse", "HEAD", cwd=work).stdout.strip() != base_sha:
            raise RuntimeError("STALE_BASE: fresh checkout SHA mismatch")
        run("git", "switch", "-c", branch, cwd=work)
        run("git", "apply", "--check", str(patch), cwd=work)
        run("git", "apply", "--index", str(patch), cwd=work)
        paths = safe_changed_paths(work)
        run("git", "diff", "--cached", "--check", cwd=work)
        run("git", "config", "user.name", "Codex Bridge", cwd=work)
        run("git", "config", "user.email", "codex-bridge@users.noreply.github.com", cwd=work)
        run("git", "commit", "-m", f"Codex implementation for issue #{issue}", cwd=work)
        sha = run("git", "rev-parse", "HEAD", cwd=work).stdout.strip()
        if current_main(repo) != base_sha:
            raise RuntimeError("STALE_BASE before push; refusing to publish a stale patch")
        run("git", "push", "--quiet", "origin", "HEAD:refs/heads/" + branch,
            cwd=work, env=git_push_environment(root))

        body = (f"Autonomous Codex change from martaxi-boss/VPS issue #{issue}.\n\n"
                f"Remote isolated Codex clone base: `{base_sha}`.\n"
                f"Trusted publisher commit: `{sha}`.\n"
                f"Files: {', '.join('`'+p+'`' for p in paths)}.\n\n"
                "No GitHub write credential was provided to Codex. "
                "Independent target CI, protected branch controls and exact-head verification "
                "are required before any merge. Never infer functional PASS from a model report.")
        pr = api("POST", f"repos/{repo}/pulls", {
            "title": f"Codex: {task_title(source, issue)}",
            "head": branch, "base": "main", "body": body, "draft": False
        })
        number = pr["number"]
        url = pr["html_url"]
        print("CODEX_PR_CREATED=" + url, flush=True)
        # VPS is an operations repo without broad application regression CI.
        # Safe docs may auto-merge; code changes remain a PR for independent review.
        if repo == "martaxi-boss/VPS" and any(
            not name.lower().endswith((".md", ".txt")) for name in paths
        ):
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha,
                    "reason": "VPS operational code needs an independent project-specific test gate"}
        state, evidence = wait_for_checks(repo, sha, branch, ALLOWED[repo])
        if state != "PASS":
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha, "reason": evidence}
        if current_main(repo) != base_sha:
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha,
                    "reason": "Main changed since CI base; fresh exact-state validation required"}
        current_pr = api("GET", f"repos/{repo}/pulls/{number}")
        if (current_pr.get("head", {}).get("sha") != sha or
                current_pr.get("base", {}).get("sha") != base_sha or
                current_pr.get("draft") or not current_pr.get("mergeable")):
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha,
                    "reason": "PR head/base/mergeability changed after validation"}
        try:
            merged = api("PUT", f"repos/{repo}/pulls/{number}/merge", {
                "sha": sha, "merge_method": "merge",
                "commit_title": f"Merge Codex issue #{issue} after required checks"
            })
        except RuntimeError as exc:
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha,
                    "reason": f"GitHub merge refused; no bypass attempted ({exc})"}
        if merged.get("merged") is not True:
            return {"status": "PR_NEEDS_ATTENTION", "repository": repo,
                    "pull_request": url, "commit_sha": sha,
                    "reason": "GitHub did not confirm merged=true"}
        return {"status": "MERGED", "repository": repo, "pull_request": url,
                "commit_sha": sha, "merge_sha": merged.get("sha"),
                "reason": evidence}


def task_title(source, issue):
    lines = (source / "codex-task.txt").read_text(encoding="utf-8").splitlines()
    title = next((line.strip() for line in lines[1:] if line.strip()), f"task {issue}")
    return title[:70]


def main():
    source = Path(os.environ["CODEX_JOB_DIR"]).resolve()
    dest = Path(os.environ["CODEX_RESULT_PATH"]).resolve()
    issue = os.environ["CODEX_ISSUE_NUMBER"]
    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    if not all(x.isdecimal() for x in (issue, run_id, attempt)):
        raise ValueError("Invalid issue/run identity")
    if not os.environ.get("CODEX_GITHUB_TOKEN"):
        raise RuntimeError("Missing CODEX_GITHUB_TOKEN secret; no model run should be started")
    try:
        result = perform(source, issue, run_id, attempt)
    except Exception as exc:
        # Never publish exception details containing raw user task or credentials.
        result = {"status": "FAILED", "reason": str(exc)[:300]}
    usage_path = source / "usage.json"
    try:
        usage = json.loads(usage_path.read_text(encoding="utf-8"))
        result["usage"] = usage if isinstance(usage, dict) else {"observed": False}
    except (FileNotFoundError, ValueError):
        result["usage"] = {"observed": False}
    dest.write_text(json.dumps(result, ensure_ascii=False) + "\n", encoding="utf-8")
    print("CODEX_TRUSTED_RESULT=" + result["status"], flush=True)
    if result["status"] not in ("MERGED", "NO_CHANGE"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
