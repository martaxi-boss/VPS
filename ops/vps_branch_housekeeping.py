#!/usr/bin/env python3
"""Lease-safe VPS *repository* branch hygiene on a disposable GitHub runner.

Only fully integrated, older-than-48h refs with no open PR, current trusted
workflow mention or protected-purpose prefix are eligible for deletion. Never
rewrites Git history, repository main or branches that carry unique commits.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote


PREFIXES = ("builder/", "codex/", "config/", "diagnostic/",
            "feat/", "feature/", "fix/", "integration/", "audit/")
MIN_AGE_SECONDS = 48 * 60 * 60
MAX_BRANCHES = 500


def command(args: list[str], timeout: int = 35) -> tuple[int, str]:
    completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, check=False, timeout=timeout)
    return completed.returncode, completed.stdout.strip()


def eligible(name: str, commit_sha: str, main_sha: str, age_seconds: int,
             open_pr_heads: set[str], referenced_in_workflows: bool,
             is_ancestor: bool, protected: bool = False) -> bool:
    return (name not in open_pr_heads
            and name != "main"
            and any(name.startswith(p) for p in PREFIXES)
            and bool(re.fullmatch(r"[a-zA-Z0-9._/-]{1,180}", name))
            and not name.startswith(("control/", "security/", "recovery/", "ops/"))
            and bool(re.fullmatch(r"[0-9a-f]{40}", commit_sha))
            and bool(re.fullmatch(r"[0-9a-f]{40}", main_sha))
            and age_seconds >= MIN_AGE_SECONDS
            and not referenced_in_workflows
            and not protected
            and is_ancestor)


def remote_branch_sha(name: str) -> str | None:
    code, output = command(["git", "ls-remote", "--heads", "origin",
                            "refs/heads/" + name], timeout=20)
    if code != 0:
        raise RuntimeError("Remote-branch verification unavailable")
    if not output:
        return None
    sha, sep, ref = output.partition("\t")
    if sep and ref == "refs/heads/" + name and re.fullmatch(r"[0-9a-f]{40}", sha):
        return sha
    raise RuntimeError("Unexpected remote-branch verification result")


def inspect(mode: str) -> dict:
    if mode not in ("audit", "clean"):
        raise ValueError("Unsafe branch hygiene mode")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if repo != "martaxi-boss/VPS":
        raise ValueError("Unexpected repository boundary")
    code, sha = command(["git", "rev-parse", "refs/remotes/origin/main"])
    if code != 0 or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Main revision unverifiable")
    main_sha = sha
    code, raw_prs = command(["gh", "pr", "list", "--repo", repo,
                            "--state", "open", "--limit", "500",
                            "--json", "headRefName,headRepositoryOwner"])
    if code != 0:
        raise RuntimeError("Open PR list unavailable; must preserve all branches")
    pulls = json.loads(raw_prs)
    if not isinstance(pulls, list) or len(pulls) >= 500:
        raise RuntimeError("Open PR list unbounded")
    pr_heads = {p["headRefName"] for p in pulls
                if isinstance(p, dict) and isinstance(p.get("headRefName"), str)}
    code, refs = command(["git", "for-each-ref",
                          "--format=%(refname:strip=3) %(objectname) %(committerdate:unix)",
                          "refs/remotes/origin"], timeout=20)
    if code != 0:
        raise RuntimeError("Local remote refs unavailable")
    lines = refs.splitlines()
    if len(lines) > MAX_BRANCHES:
        raise RuntimeError("Too many branches; no sweeping permitted")
    workflows = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(Path(".github/workflows").glob("*.yml"))
        if p.is_file()
    )
    checked = 0
    candidates = []
    kept = 0
    now = int(time.time())
    for row in lines:
        parts = row.split(" ")
        if len(parts) != 3:
            kept += 1
            continue
        name, tip, time_str = parts
        if name == "main" or name == "HEAD":
            continue
        checked += 1
        if not time_str.isdecimal():
            kept += 1
            continue
        age = now - int(time_str)
        if age < MIN_AGE_SECONDS:
            kept += 1
            continue
        code, _ = command(["git", "merge-base", "--is-ancestor", tip, main_sha], timeout=10)
        if eligible(name, tip, main_sha, age, pr_heads,
                    name in workflows, code == 0):
            candidates.append((name, tip))
        else:
            kept += 1

    deleted, skipped_changed, skipped_open, skipped_refused = 0, 0, 0, 0
    if mode == "clean":
        for name, tip in candidates:
            if remote_branch_sha("main") != main_sha:
                raise RuntimeError("Main changed since ancestry proof; stopping sweep")
            # Verify actual remote SHA and live open PR list immediately before delete.
            actual = remote_branch_sha(name)
            if actual != tip:
                skipped_changed += 1
                continue
            code, protected_text = command([
                "gh", "api", "repos/" + repo + "/branches/" + quote(name, safe=""),
                "--jq", ".protected"], timeout=15)
            if code != 0 or protected_text not in ("true", "false"):
                raise RuntimeError("Unable to verify branch protection")
            if protected_text == "true":
                skipped_refused += 1
                continue
            code, live_pr = command(["gh", "pr", "list", "--repo", repo,
                                     "--state", "open", "--head", name,
                                     "--json", "number", "--limit", "1"])
            if code != 0:
                raise RuntimeError("Unable to check live PR protections")
            if json.loads(live_pr):
                skipped_open += 1
                continue
            code, _ = command([
                "git", "push", "--force-with-lease=refs/heads/" + name + ":" + tip,
                "origin", ":refs/heads/" + name], timeout=35)
            if code == 0 and remote_branch_sha(name) is None:
                deleted += 1
            else:
                skipped_refused += 1

    return {
        "status": "AUDIT_ONLY" if mode == "audit" else "BRANCH_SWEEP_FINISHED",
        "mode": mode, "remote_branches_checked": checked,
        "fully_merged_candidates": len(candidates),
        "preserved_or_ineligible": kept,
        "deleted_merged_refs": deleted,
        "preserved_changed": skipped_changed,
        "preserved_open_pr": skipped_open,
        "preserved_refused": skipped_refused,
    }


if __name__ == "__main__":
    try:
        result = inspect(sys.argv[1] if len(sys.argv) > 1 else "audit")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except Exception:
        # No error messages or branch/path names are exposed in public logs.
        print('{"status":"BRANCH_HYGIENE_FAILED"}')
        sys.exit(3)
