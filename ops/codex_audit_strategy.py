#!/usr/bin/env python3
"""Token-free, evidence-derived dispatch policy for Owner-audited Codex work.

The ChatGPT manager audits a pinned GitHub revision and supplies findings,
owned paths, and independent work items. This module derives workers, mode,
and reasoning from that evidence, *not* from words in prompts.

The existing agent_switch router still enforces the actual executor boundary:
at most two Codex CLI workers, explicit Owner issue, no provider substitution.
A dependent second stage needs another audited issue after stage-one review.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
PATH = re.compile(r"[A-Za-z0-9._/-]{1,170}\Z")
LEVEL = {"low": 0, "medium": 1, "high": 2}
REPOSITORIES = frozenset({
    "martaxi-boss/VPS", "martaxi-boss/Project-leader-codex",
    "martaxi-boss/pink-iptv",
})
BLOCKED_PARTS = frozenset({
    ".git", ".github", ".codex", ".ssh", ".project-leader", "__pycache__",
})
BLOCKED_NAMES = frozenset({
    ".env", ".npmrc", ".pypirc", "auth.json", "config.toml",
    "codex-autonomous-remote.sh", "codex-autonomous-publish.py",
    "codex_patch_guard.py", "codex_sandbox_repair_ubuntu.sh",
    "telegram_gateway.py", "test_codex_autonomous.py",
})
SECURITY_NAMES = re.compile(
    r"(?:^|/)(?:control|security|auth|permissions|policy|credential)(?:/|[._-])",
    re.I,
)
SENSITIVE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[a-zA-Z0-9]{12,}|"
    r"(?:api[_-]?key|access[_-]?token|secret|password|senha)"
    r"\s*[:=]\s*\S+|\$\{\{|<script)",
    re.I,
)
MAX_AUDIT = 6800


class AuditStrategyError(ValueError):
    pass


def safe_path(value: object) -> str:
    if type(value) is not str or not PATH.fullmatch(value):
        raise AuditStrategyError("Invalid audited file path")
    parts = value.split("/")
    if (any(part in ("", ".", "..") or part.startswith("~") for part in parts)
            or any(part in BLOCKED_PARTS for part in parts)
            or parts[-1].lower() in BLOCKED_NAMES
            or any(re.search(r"(token|credential|secret|private.key|passwd)", p, re.I)
                   for p in parts)):
        raise AuditStrategyError("Protected path cannot be delegated to Codex")
    return value


def scoped(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def bounded_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if (type(value) is not str or not minimum <= len(value) <= maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or SENSITIVE.search(value)):
        raise AuditStrategyError("Invalid or sensitive audit " + label)
    return value


def _ident(value: object) -> str:
    if type(value) is not str or len(value) > 48 or not IDENT.fullmatch(value):
        raise AuditStrategyError("Invalid audit finding/task identity")
    return value


def compile_audit(value: object) -> dict:
    """Produce a legacy manifest after an explicit, pinned ChatGPT audit.

    This function verifies the *structure* of Owner-provided findings; the
    auditor must inspect the real repository and supply its actual HEAD.
    Runtime verify_checkout pins the worker's snapshot before any model call.
    """
    if not isinstance(value, dict) or set(value) != {"target_repository", "audit"}:
        raise AuditStrategyError("Audited order requires target_repository and audit")
    target = value["target_repository"]
    if type(target) is not str or target not in REPOSITORIES:
        raise AuditStrategyError("Only mutable, reviewed target repositories may be audited")
    audit = value["audit"]
    if not isinstance(audit, dict) or set(audit) != {"revision", "findings", "work_items"}:
        raise AuditStrategyError("Audit requires pinned revision, findings, and work_items")
    revision = audit["revision"]
    if type(revision) is not str or not SHA.fullmatch(revision):
        raise AuditStrategyError("Audit must pin exact lowercase GitHub main SHA")
    findings = audit["findings"]
    work = audit["work_items"]
    if not isinstance(findings, list) or not 1 <= len(findings) <= 12:
        raise AuditStrategyError("At least one bounded repository finding required")
    if not isinstance(work, list) or not 1 <= len(work) <= 2:
        raise AuditStrategyError(
            "One audit dispatch is one phase with at most two Codex workers; "
            "re-audit after dependent phases. No model started"
        )
    observed = {}
    for raw in findings:
        if not isinstance(raw, dict) or set(raw) != {"id", "paths", "severity", "observation"}:
            raise AuditStrategyError("Finding requires id, paths, severity and observation")
        fid = _ident(raw["id"])
        if fid in observed or type(raw["severity"]) is not str or raw["severity"] not in LEVEL:
            raise AuditStrategyError("Duplicate finding or invalid severity")
        paths = raw["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 12
                or len(set(map(str, paths))) != len(paths)):
            raise AuditStrategyError("Finding needs distinct inspected paths")
        cleaned = [safe_path(p) for p in paths]
        bounded_text(raw["observation"], "observation", 12, 500)
        observed[fid] = {"paths": cleaned, "severity": raw["severity"]}

    tasks = []
    ids = set()
    for item in work:
        if (not isinstance(item, dict) or
                set(item) not in (
                    {"id", "task", "paths", "finding_ids"},
                    {"id", "task", "paths", "finding_ids", "depends_on"},
                    {"id", "task", "paths", "finding_ids", "allow_no_change"},
                    {"id", "task", "paths", "finding_ids", "depends_on", "allow_no_change"},
                )):
            raise AuditStrategyError("Audited work item has unexpected or missing fields")
        ident = _ident(item["id"])
        if ident in ids:
            raise AuditStrategyError("Duplicate audited work id")
        ids.add(ident)
        instruction = bounded_text(item["task"], "task", 12, 1600)
        if "AUDIT_BASE_SHA=" in instruction or "AUDIT_ALLOWED_PATHS=" in instruction:
            raise AuditStrategyError("Reserved audit markers inside task text")
        paths = item["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 18
                or len(set(map(str, paths))) != len(paths)):
            raise AuditStrategyError("Each audited worker needs distinct owned paths")
        paths = [safe_path(p) for p in paths]
        references = item["finding_ids"]
        if (not isinstance(references, list) or not 1 <= len(references) <= 12
                or len(set(map(str, references))) != len(references)
                or any(type(fid) is not str or fid not in observed for fid in references)):
            raise AuditStrategyError("Worker must cite existing distinct audit findings")
        if not all(any(scoped(p, x) for fid in references for x in observed[fid]["paths"])
                   for p in paths):
            raise AuditStrategyError("Every owned path must be grounded in an audit finding")
        deps = item.get("depends_on", [])
        if type(deps) is not list or len(set(map(str, deps))) != len(deps):
            raise AuditStrategyError("Invalid dependencies")
        if any(type(d) is not str or d not in ids or d == ident for d in deps):
            raise AuditStrategyError("Dependency must reference an earlier audited work item")
        no_change = item.get("allow_no_change", False)
        if type(no_change) is not bool:
            raise AuditStrategyError("allow_no_change must be boolean")
        risk = max((observed[fid]["severity"] for fid in references),
                   key=lambda x: LEVEL[x])
        if any(SECURITY_NAMES.search(path) for path in paths):
            risk = "high"
        # A requested low-effort change to arbitrary source code is not
        # considered low risk until supported by more specific audit evidence.
        if risk == "low" and not all(
            path.endswith((".md", ".rst", ".txt")) or
            "/docs/" in "/" + path or path.startswith("docs/")
            for path in paths
        ):
            risk = "medium"
        scoped_markers = json.dumps(paths, separators=(",", ":"), ensure_ascii=True)
        msg = ("AUDIT_BASE_SHA=" + revision + "\n" +
               "AUDIT_ALLOWED_PATHS=" + scoped_markers + "\n" +
               instruction)
        tasks.append({
            "id": ident,
            "provider": "codex",
            "model": "gpt-5.6-sol",
            "reasoning_effort": risk,
            "task": msg,
            "paths": paths,
            "depends_on": deps,
            "allow_no_change": no_change,
        })

    if len(tasks) == 1:
        mode, independent = "serial", False
    else:
        a, b = tasks
        overlap = any(scoped(p, q) for p in a["paths"] for q in b["paths"])
        if overlap or b["depends_on"]:
            raise AuditStrategyError(
                "Dependent or shared-path stages require a fresh audit after "
                "the first worker's CI; submit them as separate phases. No model started"
            )
        # No implicit parallelism for high-risk independent edits, but serial
        # workers can still publish their own PRs without merging siblings.
        independent = a["reasoning_effort"] == "high" or b["reasoning_effort"] == "high"
        mode = "serial" if independent else "parallel"

    order = {
        "target_repository": target,
        "mode": mode,
        "tasks": [
            {key: value for key, value in task.items()
             if key in ("id", "provider", "model", "reasoning_effort", "task",
                        "allow_no_change")}
            for task in tasks
        ],
    }
    if independent:
        order["serial_independent"] = True
    return order


def audited_markers(task_file: Path) -> tuple[str, list[str]] | None:
    if not task_file.is_file() or task_file.is_symlink() or task_file.stat().st_size > 9000:
        raise AuditStrategyError("Missing or unsafe worker task")
    data = task_file.read_text(encoding="utf-8")
    sha_values = [line[len("AUDIT_BASE_SHA="):] for line in data.splitlines()
                  if line.startswith("AUDIT_BASE_SHA=")]
    scopes = [line[len("AUDIT_ALLOWED_PATHS="):] for line in data.splitlines()
              if line.startswith("AUDIT_ALLOWED_PATHS=")]
    if not sha_values and not scopes:
        return None   # Backwards-compatible explicit Owner Codex orders.
    if len(sha_values) != 1 or len(scopes) != 1 or not SHA.fullmatch(sha_values[0]):
        raise AuditStrategyError("Incomplete/ambiguous audit scope markers")
    try:
        paths = json.loads(scopes[0])
    except (ValueError, TypeError):
        raise AuditStrategyError("Invalid audited path list") from None
    if (not isinstance(paths, list) or not 1 <= len(paths) <= 18
            or len(set(map(str, paths))) != len(paths)):
        raise AuditStrategyError("Invalid audited path count")
    return sha_values[0], [safe_path(p) for p in paths]


def verify_checkout(task_file: Path, current_sha: str) -> None:
    markers = audited_markers(task_file)
    if markers is not None and markers[0] != current_sha:
        raise AuditStrategyError("Audited repository HEAD changed; re-audit before spending Codex quota")


def verify_changed(task_file: Path) -> None:
    markers = audited_markers(task_file)
    if markers is None:
        return
    _, allowed = markers
    changed = subprocess.check_output(
        ["git", "diff", "--no-ext-diff", "--name-only", "-z"], stderr=subprocess.DEVNULL
    )
    if len(changed) > 100_000:
        raise AuditStrategyError("Unbounded Codex change set")
    for raw in changed.split(b"\x00"):
        if not raw:
            continue
        name = raw.decode("utf-8", "strict")
        if not any(name == p or name.startswith(p + "/") for p in allowed):
            raise AuditStrategyError("Codex attempted to modify a path outside audited ownership")


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "verify_checkout":
            verify_checkout(Path(argv[2]), argv[3])
            print("CODEX_AUDITED_HEAD=VERIFIED")
            return 0
        if len(argv) == 3 and argv[1] == "verify_changed":
            verify_changed(Path(argv[2]))
            print("CODEX_AUDITED_PATHS=VERIFIED")
            return 0
        if len(argv) == 2 and argv[1] == "plan":
            raw = sys.stdin.read(MAX_AUDIT + 1)
            if len(raw.encode("utf-8")) > MAX_AUDIT:
                raise AuditStrategyError("Oversized audit")
            print(json.dumps(compile_audit(json.loads(raw)), sort_keys=True))
            return 0
    except (AuditStrategyError, ValueError, OSError, UnicodeError, subprocess.CalledProcessError):
        # Public runner logs must never echo task text, secret names or files.
        print("AUDIT_STRATEGY_BLOCKED", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
