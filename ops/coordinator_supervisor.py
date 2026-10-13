#!/usr/bin/env python3
"""Independent Project Leader terminal gate for Coordinator-routed Codex PRs.

The AI Coordinator is NOT imported or invoked. This deterministic supervisor
audits actual trusted worker publication outputs and may integrate *small
documentation-only E1 changes* after independent exact-SHA security/CI checks.
Everything else remains safely held for appropriate Project Leader review.
No API key, raw model report, or untrusted Issue body enters a worker.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = "martaxi-boss"
CONTROL = OWNER + "/VPS"
TARGET = OWNER + "/Project-leader-codex"
SOURCE = OWNER + "/Project-leader"
REQUIRED = frozenset({
    ("Codex specialization tests", "pull_request"),
    ("Package ChatGPT plugins", "pull_request"),
    ("Validate control plane", "pull_request"),
    ("Control contract tests", "pull_request"),
})
SHA = re.compile(r"[0-9a-f]{40}\Z")
PR_URL = re.compile(
    r"https://github\.com/martaxi-boss/Project-leader-codex/pull/([1-9][0-9]*)\Z")
BRANCH = re.compile(r"codex/issue-([1-9][0-9]*)-([1-9][0-9]*)-([1-9][0-9]*)"
                    r"(?:-([12]))?\Z")
MAX_FILES = 3
MAX_DIFF_LINES = 180
MAX_NETWORK_BYTES = 1_000_000


class SupervisorHold(ValueError):
    """A safe, non-Human-Gate block; code is a fixed non-private enum."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Worker:
    status: str
    url: str
    sha: str


@dataclass(frozen=True)
class Candidate:
    number: int
    sha: str
    branch: str
    base: str
    paths: tuple[str, ...]


def _int(value: str, label: str, top: int = 10**16) -> int:
    if (type(value) is not str or not re.fullmatch(r"[1-9][0-9]{0,15}", value)
            or int(value) > top):
        raise SupervisorHold("INVALID_" + label)
    return int(value)


def _api(method: str, route: str, data: object = None, *, control: bool = False) -> object:
    # Target PR mutation uses the existing dedicated Publisher credential.
    token = os.environ.get("GH_TOKEN" if control else "CODEX_GITHUB_TOKEN", "")
    if not token:
        raise SupervisorHold("AUTH_UNAVAILABLE")
    url = "https://api.github.com/" + route.lstrip("/")
    payload = json.dumps(data, separators=(",", ":")).encode() if data is not None else None
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Project-Leader-Independent-Supervisor",
    }
    req = urllib.request.Request(url, method=method, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read(MAX_NETWORK_BYTES + 1)
            if len(raw) > MAX_NETWORK_BYTES:
                raise SupervisorHold("RESPONSE_OVERSIZED")
            return json.loads(raw) if raw else {}
    except (urllib.error.URLError, OSError, ValueError):
        raise SupervisorHold("TRANSPORT_UNVERIFIED") from None


def _issue(number: int) -> None:
    issue = _api("GET", f"repos/{CONTROL}/issues/{number}", control=True)
    if (not isinstance(issue, dict) or issue.get("number") != number
            or issue.get("state") != "open"
            or issue.get("user", {}).get("login") != OWNER
            or not issue.get("title", "").startswith("[coordinator run] ")
            or not isinstance(issue.get("body"), str)
            or not issue["body"].startswith("TARGET_REPOSITORY=" + TARGET + "\n")):
        raise SupervisorHold("OWNER_AUTHORITY_UNVERIFIED")


def _safe_doc(path: object) -> bool:
    if type(path) is not str or len(path) > 180 or "\\" in path or "\x00" in path:
        return False
    components = path.split("/")
    if any(not component or component in (".", "..") for component in components):
        return False
    if path == "README_CODEX.md":
        return True
    return (len(components) >= 2 and components[0] == "docs"
            and path.endswith(".md") and
            all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in components[1:]))


def _files(number: int) -> tuple[str, ...]:
    rows = _api("GET", f"repos/{TARGET}/pulls/{number}/files?per_page=100")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise SupervisorHold("DIFF_OUTSIDE_SAFE_DOC_SCOPE")
    total = 0
    result = []
    for row in rows:
        name = row.get("filename")
        if (row.get("status") != "modified" or not _safe_doc(name)
                or type(row.get("additions")) is not int
                or type(row.get("deletions")) is not int):
            raise SupervisorHold("DIFF_OUTSIDE_SAFE_DOC_SCOPE")
        total += row["additions"] + row["deletions"]
        result.append(name)
    if len(result) != len(set(result)) or total > MAX_DIFF_LINES:
        raise SupervisorHold("DIFF_OUTSIDE_SAFE_DOC_SCOPE")
    return tuple(sorted(result))


def _expected_branch(branch: str, issue: int, run: int) -> bool:
    match = BRANCH.fullmatch(branch)
    return bool(match and int(match[1]) == issue and int(match[2]) == run)


def _candidate(worker: Worker, issue: int, run: int) -> Candidate:
    if worker.status != "PR_STAGED" or not SHA.fullmatch(worker.sha):
        raise SupervisorHold("WORKER_RESULT_NOT_STAGED")
    matched = PR_URL.fullmatch(worker.url)
    if not matched:
        raise SupervisorHold("PUBLISHER_PROVENANCE_MISMATCH")
    number = int(matched[1])
    pr = _api("GET", f"repos/{TARGET}/pulls/{number}")
    if not isinstance(pr, dict):
        raise SupervisorHold("PR_UNVERIFIED")
    head = pr.get("head", {})
    base = pr.get("base", {})
    branch = head.get("ref", "")
    if (pr.get("state") != "open" or pr.get("draft") is not False
            or pr.get("merged") is not False or pr.get("mergeable") is not True
            or pr.get("user", {}).get("login") != OWNER
            or head.get("repo", {}).get("full_name") != TARGET
            or base.get("ref") != "main"
            or head.get("sha") != worker.sha
            or not _expected_branch(branch, issue, run)):
        raise SupervisorHold("PR_UNVERIFIED")
    body = pr.get("body")
    if (not isinstance(body, str) or
            "Autonomous Codex change from " + CONTROL + " issue #" + str(issue) + ".\n" not in body
            or "Trusted publisher commit: " + "\x60" + worker.sha + "\x60" not in body
            or "No GitHub write credential was provided to Codex." not in body):
        raise SupervisorHold("PUBLISHER_PROVENANCE_MISMATCH")
    match = re.search(r"Remote isolated Codex clone base: " + "\x60" +
                      r"([0-9a-f]{40})" + "\x60" + r"\.", body)
    if not match:
        raise SupervisorHold("PUBLISHER_PROVENANCE_MISMATCH")
    return Candidate(number, worker.sha, branch, match[1], _files(number))


def _main_sha() -> str:
    response = _api("GET", f"repos/{TARGET}/git/ref/heads/main")
    sha = response.get("object", {}).get("sha", "")
    if not SHA.fullmatch(sha):
        raise SupervisorHold("TARGET_HEAD_UNVERIFIED")
    return sha


def _ci(sha: str, branch: str) -> None:
    query = urllib.parse.urlencode({"head_sha": sha, "per_page": 100})
    response = _api("GET", f"repos/{TARGET}/actions/runs?{query}")
    runs = response.get("workflow_runs", [])
    if not isinstance(runs, list) or len(runs) >= 100:
        raise SupervisorHold("CI_UNBOUNDED")
    latest = {}
    for item in runs:
        if (item.get("head_sha") != sha or
                item.get("head_branch") not in (None, branch) or
                item.get("event") not in ("pull_request", "pull_request_target")):
            continue
        key = (item.get("name"), item.get("event"))
        old = latest.get(key)
        if old is None or item.get("created_at", "") >= old.get("created_at", ""):
            latest[key] = item
    if not REQUIRED.issubset(latest):
        raise SupervisorHold("CI_MISSING")
    if any(r.get("status") == "completed" and r.get("conclusion") != "success"
           for r in latest.values()):
        raise SupervisorHold("CI_NOT_GREEN")
    if any(r.get("status") != "completed" for r in latest.values()):
        raise SupervisorHold("CI_PENDING")


def _review(pr: Candidate, issue: int, run: int, canonical: str) -> None:
    # Independent deterministic Supervisor assessment, explicitly E1/docs only.
    body = (
        "Project Leader Supervisor / bounded independent documentation review.\n\n"
        f"Original authenticated Owner Issue: {CONTROL}#{issue}, run {run}.\n"
        f"Canonical Project Leader revision: {canonical}.\n"
        f"Publisher PR/head: {TARGET}#{pr.number}, {pr.sha}.\n"
        f"Original audited main: {pr.base}.\n"
        "Exact-head target CI: all four mandatory workflows and all related "
        "PR-context runs PASS.\n"
        "Strict E1 scope: only existing documentation, at most 3 files "
        "and 180 changed lines; protected rules, executables and workflows excluded.\n"
        "Independent security/provenance and SHA rechecks are required on merge. "
        "This is not an approval of code, credentials, deployment or any "
        "unverified semantic change.\n"
        "Changed: " + ", ".join(pr.paths)
    )
    _api("POST", f"repos/{TARGET}/pulls/{pr.number}/reviews",
         {"event": "COMMENT", "body": body})


def _merge(pr: Candidate) -> str:
    current = _api("GET", f"repos/{TARGET}/pulls/{pr.number}")
    if (current.get("head", {}).get("sha") != pr.sha
            or current.get("base", {}).get("sha") != _main_sha()
            or current.get("state") != "open"
            or current.get("mergeable") is not True):
        raise SupervisorHold("EXACT_STATE_DRIFT")
    if pr.base != _main_sha():
        raise SupervisorHold("EXACT_STATE_DRIFT")
    result = _api("PUT", f"repos/{TARGET}/pulls/{pr.number}/merge",
                  {"sha": pr.sha, "merge_method": "merge",
                   "commit_title": f"Project Leader validated Codex PR #{pr.number}"})
    if result.get("merged") is not True or not SHA.fullmatch(result.get("sha", "")):
        # An ambiguous GitHub write must be reconciled, not blindly repeated.
        observed = _api("GET", f"repos/{TARGET}/pulls/{pr.number}")
        if (observed.get("merged") is not True or
                not SHA.fullmatch(observed.get("merge_commit_sha", ""))):
            raise SupervisorHold("MERGE_OUTCOME_UNVERIFIED")
        return observed["merge_commit_sha"]
    if _main_sha() != result["sha"]:
        raise SupervisorHold("MERGE_HEAD_UNVERIFIED")
    return result["sha"]


def _wait_updated_branch(second: Candidate, new_base: str) -> Candidate:
    """Ask GitHub to merge updated main into the second *existing* PR.

    Preserve the independently checked worker commit as an actual parent.
    Never accept an arbitrary rewrite, force push, conflicting rebase,
    additional changed file, or third-party patch as a safe continuation.
    """
    before = _api("GET", f"repos/{TARGET}/pulls/{second.number}")
    if (before.get("head", {}).get("sha") != second.sha or
            before.get("head", {}).get("ref") != second.branch or
            before.get("base", {}).get("sha") != new_base or
            before.get("state") != "open"):
        raise SupervisorHold("SECOND_PR_DRIFT")
    # GitHub REST update-branch accepts only expected_head_sha; its update
    # is a server-created merge commit. Never substitute an unverified rebase.
    _api("PUT", f"repos/{TARGET}/pulls/{second.number}/update-branch",
         {"expected_head_sha": second.sha})
    # A GitHub update-branch request is asynchronous. Do not guess the new
    # commit or accept an arbitrary new head just because it has green CI.
    deadline = time.monotonic() + 330
    while time.monotonic() < deadline:
        current = _api("GET", f"repos/{TARGET}/pulls/{second.number}")
        head = current.get("head", {})
        updated = head.get("sha", "")
        if (updated != second.sha and SHA.fullmatch(updated) and
                current.get("state") == "open" and
                head.get("ref") == second.branch and
                head.get("repo", {}).get("full_name") == TARGET and
                current.get("base", {}).get("sha") == new_base):
            ancestry = _api("GET", f"repos/{TARGET}/git/commits/{updated}")
            parents = ancestry.get("parents", [])
            parent_shas = {p.get("sha") for p in parents if isinstance(p, dict)}
            if len(parents) != 2 or parent_shas != {second.sha, new_base}:
                raise SupervisorHold("UPDATED_BRANCH_ANCESTRY_UNVERIFIED")
            if _files(second.number) != second.paths:
                raise SupervisorHold("UPDATED_BRANCH_CHANGED_SCOPE")
            if current.get("mergeable") is True:
                return Candidate(second.number, updated, second.branch,
                                 new_base, second.paths)
            if current.get("mergeable") is False:
                raise SupervisorHold("UPDATED_BRANCH_CONFLICT")
        time.sleep(8)
    raise SupervisorHold("BRANCH_UPDATE_PENDING")


def _wait_fresh_ci(second: Candidate) -> None:
    """New exact-head checks are mandatory after GitHub updates the branch."""
    deadline = time.monotonic() + 390
    while time.monotonic() < deadline:
        try:
            _ci(second.sha, second.branch)
            return
        except SupervisorHold as exc:
            if exc.code not in {"CI_MISSING", "CI_PENDING"}:
                raise
        time.sleep(8)
    raise SupervisorHold("UPDATED_CI_PENDING")


def assess(issue: int, run: int, workers: list[Worker], phase_count: int,
           canonical: str) -> dict:
    """Independently merge up to two non-overlapping, CI-verified doc PRs.

    Second PR receives a GitHub-owned merge update and exact-new-head CI,
    never blind reuse of checks from its stale first-wave parent.
    """
    if not 1 <= len(workers) <= 2 or not 1 <= phase_count <= 8:
        raise SupervisorHold("INVALID_ROUTING")
    if not SHA.fullmatch(canonical):
        raise SupervisorHold("CANONICAL_UNVERIFIED")
    _issue(issue)
    canonical_ref = _api("GET", f"repos/{SOURCE}/git/ref/heads/main")
    if canonical_ref.get("object", {}).get("sha") != canonical:
        raise SupervisorHold("CANONICAL_STALE")
    candidates = [_candidate(w, issue, run) for w in workers]
    if len({c.number for c in candidates}) != len(candidates):
        raise SupervisorHold("DUPLICATE_WORKER_PR")
    if len({c.sha for c in candidates}) != len(candidates):
        raise SupervisorHold("DUPLICATE_WORKER_HEAD")
    main = _main_sha()
    if any(c.base != main for c in candidates):
        raise SupervisorHold("EXACT_STATE_DRIFT")
    if len(candidates) > 1:
        if set(candidates[0].paths).intersection(candidates[1].paths):
            raise SupervisorHold("PARALLEL_FILE_CONFLICT")
    # Validate both original independent worker heads BEFORE merging either.
    # This avoids merging a first PR while an invalid sibling is overlooked.
    for item in candidates:
        _ci(item.sha, item.branch)
    first = candidates[0]
    _review(first, issue, run, canonical)
    sha = _merge(first)
    numbers = [first.number]
    if len(candidates) == 2:
        # Record partial side effect before any new network mutation.
        _api("POST", f"repos/{CONTROL}/issues/{issue}/comments", {
            "body": (f"PROJECT_LEADER_PHASE_PARTIAL: PR #{first.number} merged "
                     f"at {sha}; second PR requires new base and fresh CI. "
                     f"Workflow run {run}.")
        }, control=True)
        next_pr = _wait_updated_branch(candidates[1], sha)
        _wait_fresh_ci(next_pr)
        _review(next_pr, issue, run, canonical)
        sha = _merge(next_pr)
        numbers.append(next_pr.number)
    return {"status": ("PHASE_VALIDATED_PENDING_REAUDIT" if phase_count > 1
                       else "TERMINAL_SUCCESS"),
            "pull_request": numbers[-1], "pull_requests": numbers,
            "merge_sha": sha, "phase_count": phase_count}


def main() -> int:
    try:
        issue = _int(os.environ.get("OWNER_ISSUE", ""), "ISSUE")
        run = _int(os.environ.get("OWNER_RUN", ""), "RUN")
        count = _int(os.environ.get("WORKER_COUNT", ""), "WORKER_COUNT", 2)
        phases = _int(os.environ.get("PHASE_COUNT", ""), "PHASE_COUNT", 8)
        if count not in (1, 2):
            raise SupervisorHold("INVALID_WORKER_COUNT")
        canonical = os.environ.get("CANONICAL_SHA", "")
        workers = [Worker(os.environ.get(f"WORKER_{i}_STATUS", ""),
                          os.environ.get(f"WORKER_{i}_PR", ""),
                          os.environ.get(f"WORKER_{i}_SHA", ""))
                   for i in range(1, count + 1)]
        result = assess(issue, run, workers, phases, canonical)
        numbers = ", ".join("#" + str(n) for n in result["pull_requests"])
        report = ("PROJECT_LEADER_" + result["status"] +
                  ": PR " + numbers + ", merged SHA "
                  + result["merge_sha"] + f"; phases {phases}.")
        print("PROJECT_LEADER_SUPERVISOR=" + result["status"], flush=True)
        _api("POST", f"repos/{CONTROL}/issues/{issue}/comments",
             {"body": report}, control=True)
        if result["status"] == "TERMINAL_SUCCESS":
            # Terminal means covered single phase, exact CI and verified main.
            _api("PATCH", f"repos/{CONTROL}/issues/{issue}",
                 {"state": "closed", "state_reason": "completed"}, control=True)
        return 0
    except SupervisorHold as exc:
        print("PROJECT_LEADER_SUPERVISOR=RECOVERY_REQUIRED:" + exc.code, flush=True)
        # Never publish raw model text, paths, credentials or exception detail.
        return 2


if __name__ == "__main__":
    sys.exit(main())
