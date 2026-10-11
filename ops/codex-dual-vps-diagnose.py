#!/usr/bin/env python3
"""One-shot read-only, fixed-path diagnosis; output is allowlisted metadata only."""
import json
from pathlib import Path

BASE = Path("/home/ubuntu/codex-bridge/jobs/38184905580-1-dual")
SAFE_STATUS = {"completed", "failed", "no_change", "timeout", "cancelled",
               "unverified_result", "scope_violation", "git_metadata_violation",
               "unauthorized_commit", "unauthorized_ref_change"}
CATEGORIES = (
    ("quota_or_rate_limit", ("quota", "rate limit", "429", "too many requests", "usage limit")),
    ("authentication", ("unauthorized", "login required", "not logged in", "authentication failed", "401")),
    ("cli_argument", ("unexpected argument", "unknown option", "unrecognized option", "usage: codex")),
    ("model_unavailable", ("model not found", "unknown model", "model unavailable")),
    ("permission_or_sandbox", ("permission denied", "sandbox failed", "not permitted")),
    ("invalid_manifest", ("manifest", "invalid task", "unsafe reasoning")),
    ("git_checkout", ("git preflight", "could not create independent git clone", "checkout is dirty")),
    ("runtime_setup", ("no module named", "modulenotfounderror", "traceback", "file not found")),
)

def safe_read(path: Path, max_size: int = 2_000_000) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_size:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")

def classify(raw: str) -> str:
    low = raw.casefold()
    for name, needles in CATEGORIES:
        if any(needle in low for needle in needles):
            return name
    return "unknown" if raw else "none"

def classify_events(path: Path) -> int:
    value = safe_read(path, 100_000)
    if not value:
        return 0
    count = 0
    for line in value.splitlines():
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(record, dict) and record.get("type") == "turn.completed":
            count += 1
    return min(count, 100)

def main() -> None:
    result = {"status": "NOT_FOUND", "target_run": "38184905580",
              "origin_project": "Project-leader-codex", "workers": [],
              "runner_stderr_class": "none",
              "runner_json_present": False, "start_events": 0, "end_events": 0,
              "shared_budget_reservations": 0, "shared_budget_settlements": 0}
    if BASE.is_symlink() or not BASE.is_dir():
        print(json.dumps(result, sort_keys=True))
        return
    result["status"] = "FOUND"
    stderr = safe_read(BASE / "runner.stderr")
    result["runner_stderr_class"] = classify(stderr)
    detail = "none"
    if stderr:
        classes = (
            ("source_git_root", ("Git preflight failed: rev-parse --show-toplevel",)),
            ("source_git_origin_missing", ("Git preflight failed: remote get-url origin",)),
            ("source_git_origin_mismatch", ("Git origin does not match target_repository",)),
            ("source_git_dirty", ("Source checkout is dirty",)),
            ("source_git_head_missing", ("Git preflight failed: rev-parse HEAD",)),
            ("source_refs_unavailable", ("Malformed Git reference listing", "Cannot audit Git references")),
            ("worker_clone_setup", ("Could not create independent Git clone",)),
            ("worker_git_metadata", ("Worker Git directory is not private",)),
            ("source_changed", ("Original Git repository changed during workers",)),
        )
        for item, needles in classes:
            if any(needle.casefold() in stderr.casefold() for needle in needles):
                detail = item
                break
        if detail == "none":
            detail = "git_other"
    result["runner_git_detail"] = detail
    report = safe_read(BASE / "runner.json")
    result["runner_json_present"] = bool(report)
    if report:
        try:
            payload = json.loads(report)
            workers = payload.get("workers", []) if isinstance(payload, dict) else []
            if isinstance(workers, list):
                for worker in workers[:2]:
                    if not isinstance(worker, dict) or worker.get("id") not in ("smoke-alpha", "smoke-beta"):
                        continue
                    status = worker.get("status")
                    result["workers"].append({
                        "id": worker["id"],
                        "status": status if status in SAFE_STATUS else "unknown",
                        "reasoning_low": worker.get("reasoning_effort") == "low",
                    })
        except (TypeError, ValueError):
            pass
    events = safe_read(BASE / "worker-events.tsv", 10_000)
    for line in events.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[1] in ("worker-1", "worker-2") and fields[2].isdigit():
            if fields[0] == "START":
                result["start_events"] += 1
            elif fields[0] == "END":
                result["end_events"] += 1
    for idx, name in enumerate(("smoke-alpha", "smoke-beta"), 1):
        if safe_read(BASE / ("budget-reservation-" + str(idx) + ".json"), 4096):
            result["shared_budget_reservations"] += 1
        if safe_read(BASE / ("budget-settlement-" + str(idx) + ".json"), 4096):
            result["shared_budget_settlements"] += 1
        logs = BASE / "runs"
        entries = list(logs.glob("run-*/" + name + ".stderr")) if logs.is_dir() and not logs.is_symlink() else []
        kind = classify(safe_read(entries[0], 100_000)) if len(entries) == 1 else "none"
        events = list(logs.glob("run-*/" + name + ".jsonl")) if logs.is_dir() and not logs.is_symlink() else []
        turns = classify_events(events[0]) if len(events) == 1 else 0
        known = next((x for x in result["workers"] if x["id"] == name), None)
        if known:
            known["stderr_class"] = kind
            known["completed_turns"] = turns
        else:
            result["workers"].append({"id": name, "status": "not_reported",
                                      "stderr_class": kind, "completed_turns": turns})
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
