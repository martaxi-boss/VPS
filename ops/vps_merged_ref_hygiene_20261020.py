#!/usr/bin/env python3
"""One-shot cleanup of *proved-merged* old GitHub VPS PR branches.

Never deletes code, commits, releases, recovery refs, tags, files, logs, VPS
state or unmerged work. On the PR: audit only. On a trusted main push: delete
stale refs only after reading Github's merge, branch and workflow evidence.

This is GitHub-repo maintenance only: no SSH, secrets vault or VPS commands.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

REPO = "martaxi-boss/VPS"
DEFAULT_BRANCH = "main"
AGE_DAYS = 7
MAX_PRUNE = 60
SELF_BRANCH = "hygiene/vps-merged-refs-20261020"
VALID_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}\Z")
RESERVED = ("main", "master", "develop")
PRESERVE_PREFIXES = ("release/", "recovery/", "vault/", "security/",
                     "project-leader/")
PRESERVE_SUBSTRINGS = ("pink", "fadego", "lowcost", "iptv", "signing",
                       "secret", "oauth", "credential")
MAX_PAGES = 8


class HygieneBlocked(RuntimeError):
    pass


def _is_safe_ref(name: str) -> bool:
    if (not isinstance(name, str) or not VALID_BRANCH.fullmatch(name)
            or name in RESERVED or name.startswith(".")
            or ".." in name or "//" in name or name.endswith("/")):
        return False
    if name == SELF_BRANCH:
        return True
    lower = name.casefold()
    if any(lower.startswith(p) for p in PRESERVE_PREFIXES):
        return False
    if any(word in lower for word in PRESERVE_SUBSTRINGS):
        return False
    return "/" in name


def _iso_utc(value: str) -> datetime:
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise HygieneBlocked("invalid_merge_timestamp") from exc
    if d.tzinfo is None:
        raise HygieneBlocked("unaware_merge_timestamp")
    return d.astimezone(timezone.utc)


def candidates(branches: list[dict], closed_prs: list[dict],
               open_prs: list[dict], now: datetime,
               referenced: set[str] | None = None) -> list[dict]:
    """Exact branch HEAD == merged PR HEAD, merged long ago, no open PR."""
    if now.tzinfo is None:
        raise HygieneBlocked("unaware_current_timestamp")
    cutoff = now.astimezone(timezone.utc) - timedelta(days=AGE_DAYS)
    used = {p.get("head", {}).get("ref") for p in open_prs
            if isinstance(p, dict) and isinstance(p.get("head"), dict)}
    used.update(p.get("base", {}).get("ref") for p in open_prs
                if isinstance(p, dict) and isinstance(p.get("base"), dict))
    referenced = referenced or set()
    verified: dict[str, dict] = {}
    for p in closed_prs:
        if not isinstance(p, dict) or not p.get("merged_at"):
            continue
        head, base = p.get("head"), p.get("base")
        if not isinstance(head, dict) or not isinstance(base, dict):
            continue
        name = head.get("ref")
        if not _is_safe_ref(name) or name in used or name in referenced:
            continue
        if (base.get("ref") != DEFAULT_BRANCH
                or (head.get("repo") or {}).get("full_name") != REPO
                or (base.get("repo") or {}).get("full_name") != REPO):
            continue
        if name != SELF_BRANCH and _iso_utc(p["merged_at"]) > cutoff:
            continue
        sha = head.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            continue
        value = verified.setdefault(name, {"name": name, "sha": sha, "pr": p.get("number")})
        # Ambiguous reused branch names across PRs: avoid pruning.
        if value["sha"] != sha:
            verified[name] = {"name": name, "sha": "", "pr": None}

    accepted = []
    for b in branches:
        if not isinstance(b, dict):
            continue
        name = b.get("name")
        if name not in verified or b.get("protected") is not False:
            continue
        ref = (b.get("commit") or {}).get("sha")
        if ref and ref == verified[name]["sha"]:
            accepted.append(verified[name])
    return sorted(accepted, key=lambda p: (p["name"] != SELF_BRANCH, p["name"]))


def workflow_references(checkout: Path, branch_names: list[str]) -> set[str]:
    """Preserve refs explicitly named anywhere in active workflow definitions."""
    folder = checkout / ".github" / "workflows"
    if not folder.is_dir():
        raise HygieneBlocked("workflow_directory_missing")
    source = []
    for path in sorted(folder.glob("*")):
        if path.suffix not in {".yml", ".yaml"} or path.is_symlink():
            continue
        content = path.read_text(encoding="utf-8")
        if len(content) > 300_000:
            raise HygieneBlocked("workflow_too_large_for_reference_check")
        source.append(content)
    joined = "\n".join(source)
    return {name for name in branch_names if name in joined}


class GitHub:
    def __init__(self, token: str):
        if not token:
            raise HygieneBlocked("github_token_unavailable")
        self.token = token

    def request(self, path: str, method: str = "GET", params: dict | None = None):
        if not path.startswith("/repos/" + REPO + "/"):
            raise HygieneBlocked("github_api_scope_invalid")
        url = "https://api.github.com" + path
        if params:
            url += "?" + urlencode(params)
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vps-oneoff-merged-ref-hygiene",
        }
        request = Request(url, headers=headers, method=method)
        try:
            with urlopen(request, timeout=20) as response:
                data = response.read(6_000_000)
                return json.loads(data) if data else None
        except HTTPError as exc:
            # Never include URL, response body or credentials in error details.
            raise HygieneBlocked(f"github_api_http_{exc.code}") from exc

    def list_pages(self, resource: str) -> list[dict]:
        out: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            items = self.request(f"/repos/{REPO}/{resource}",
                                 params={"per_page": 100, "page": page})
            if not isinstance(items, list):
                raise HygieneBlocked("github_list_invalid")
            out.extend(items)
            if len(items) < 100:
                return out
        raise HygieneBlocked("github_pagination_limit_exceeded")

    def branch_unchanged(self, name: str, expected_sha: str) -> bool:
        branch = self.request("/repos/" + REPO + "/branches/" +
                              quote(name, safe="/"))
        return (isinstance(branch, dict)
                and branch.get("protected") is False
                and (branch.get("commit") or {}).get("sha") == expected_sha)

    def branch_runs_completed(self, name: str) -> bool:
        result = self.request(f"/repos/{REPO}/actions/runs",
                              params={"branch": name, "per_page": 100})
        if not isinstance(result, dict):
            raise HygieneBlocked("github_workflow_status_invalid")
        runs = result.get("workflow_runs")
        if not isinstance(runs, list):
            raise HygieneBlocked("github_workflow_status_invalid")
        # If there are more than 100, we cannot prove no active jobs.
        if result.get("total_count", 0) > len(runs):
            return False
        return all(x.get("status") == "completed" for x in runs
                   if isinstance(x, dict))

    def remove_ref(self, name: str) -> None:
        self.request("/repos/" + REPO + "/git/refs/heads/" +
                     quote(name, safe="/"), method="DELETE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=["audit", "clean"])
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise HygieneBlocked("repository_mismatch")
    if args.mode == "clean" and (
        os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
    ):
        raise HygieneBlocked("cleanup_requires_trusted_main_push")
    github = GitHub(os.environ.get("GITHUB_TOKEN", ""))
    branches = github.list_pages("branches")
    closed = github.list_pages("pulls?state=closed") if False else []
    # Parameters must not be embedded in a repository path: use the same
    # typed requester on each page to prevent accidental endpoint changes.
    for page in range(1, MAX_PAGES + 1):
        items = github.request(f"/repos/{REPO}/pulls",
                               params={"state": "closed", "per_page": 100,
                                       "page": page})
        if not isinstance(items, list):
            raise HygieneBlocked("closed_pr_list_invalid")
        closed.extend(items)
        if len(items) < 100:
            break
    else:
        raise HygieneBlocked("closed_pr_pagination_limit")
    open_prs = github.request(f"/repos/{REPO}/pulls",
                              params={"state": "open", "per_page": 100})
    if not isinstance(open_prs, list) or len(open_prs) == 100:
        raise HygieneBlocked("open_prs_may_be_incomplete")
    names = [b["name"] for b in branches
             if isinstance(b, dict) and isinstance(b.get("name"), str)]
    references = workflow_references(Path("."), names)
    selected = candidates(branches, closed, open_prs, datetime.now(timezone.utc),
                          references)
    if len(selected) > MAX_PRUNE:
        # Fail before any deletion; never prune a partial unknown subset.
        raise HygieneBlocked("candidate_count_over_strict_limit")
    report = {
        "status": "AUDIT_ONLY" if args.mode == "audit" else "MERGED_REFS_PRUNED",
        "total_branches": len(branches),
        "merged_closed_prs": sum(bool(p.get("merged_at")) for p in closed),
        "preserved_workflow_referenced": len(references),
        "eligible": len(selected), "deleted": 0, "retained_unsafe_or_active": 0,
        "runtime_files_deleted": 0, "vps_actions": 0,
    }
    # All state and workflow preflights before any branch ref deletion.
    verified = []
    if args.mode == "clean":
        for item in selected:
            if (not github.branch_unchanged(item["name"], item["sha"])
                    or not github.branch_runs_completed(item["name"])):
                report["retained_unsafe_or_active"] += 1
                continue
            verified.append(item)
        for item in verified:
            if not github.branch_unchanged(item["name"], item["sha"]):
                report["retained_unsafe_or_active"] += 1
                continue
            github.remove_ref(item["name"])
            report["deleted"] += 1
    print("VPS_GITHUB_REF_HYGIENE=" + json.dumps(report, sort_keys=True))
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as file:
            file.write("## VPS GitHub merged-branch hygiene\n\n")
            file.write("Verified merged PR refs only; no VPS host touched.\n\n")
            for k, v in report.items():
                file.write(f"- {k}: {v}\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HygieneBlocked as exc:
        print("VPS_GITHUB_REF_HYGIENE=" + json.dumps(
            {"status": "BLOCKED", "reason": str(exc), "vps_actions": 0},
            sort_keys=True))
        raise SystemExit(2)
