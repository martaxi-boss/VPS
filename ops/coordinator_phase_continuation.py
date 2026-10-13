"""Safe later-phase contract for the existing independent Codex Coordinator.

Only the original authenticated Owner DAG may authorize worker IDs/paths.
The Coordinator must re-audit the current Git HEAD before each later wave.
This module does not load Project Leader, spend tokens, or dispatch workers.
"""
from __future__ import annotations

import base64
import json
import re

from ops import agent_switch
from ops.codex_audit_strategy import plan_phases

TARGET = "martaxi-boss/Project-leader-codex"
SHA = re.compile(r"[0-9a-f]{40}\Z")


class PhaseContinuationError(ValueError):
    pass


def _audited(encoded: str) -> tuple[dict, dict]:
    """Decode only via the same validated Owner router used for phase one."""
    try:
        _order, metadata = agent_switch.parse_coordinator_envelope(encoded)
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8", "strict"))
        phases = plan_phases(value)
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise PhaseContinuationError("Original Owner DAG invalid") from None
    if (metadata["phase_count"] != phases["phase_count"] or
            phases["target_repository"] != TARGET):
        raise PhaseContinuationError("Original Owner DAG inconsistency")
    return value, phases


def scope_for_phase(original_b64: str, phase: int) -> dict:
    original, phases = _audited(original_b64)
    if (type(phase) is not int or
            not 2 <= phase <= phases["phase_count"] <= 8):
        raise PhaseContinuationError("Phase not authorized in original Owner DAG")
    part = phases["phases"][phase - 1]
    ids = list(part["task_ids"])
    rows = [r for r in original["audit"]["work_items"] if r["id"] in ids]
    if len(rows) != len(ids) or not 1 <= len(rows) <= 2:
        raise PhaseContinuationError("Phase work identities inconsistent")
    return {
        "phase": phase, "phase_count": phases["phase_count"],
        "task_ids": ids, "work_items": rows,
        "paths": sorted({p for item in rows for p in item["paths"]}),
    }


def new_order(original_b64: str, phase: int, current_sha: str) -> str:
    if type(current_sha) is not str or not SHA.fullmatch(current_sha):
        raise PhaseContinuationError("Current verified target HEAD invalid")
    scope = scope_for_phase(original_b64, phase)
    requested = [
        "TARGET_REPOSITORY=" + TARGET, "",
        "Continue the ORIGINAL verified Owner DAG on current HEAD " + current_sha + ".",
        "Earlier phase PRs have been merged, validated and recorded.",
        "You are the existing independent Coordinator: plan only; do not execute.",
        "Audit tracked files afresh; do not inherit stale observations.",
        "Authorized next-phase items and precise path ownership:",
        json.dumps(scope["work_items"], sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True),
        "Return only the actual unresolved work items with EXACT original IDs and paths.",
        "Omit depends_on: predecessor phases are already accepted.",
        "Findings must be factual and cite only these already authorized files.",
        "Do not add files, jobs or IDs or repeat work from prior phases.",
        "Return the ordinary audited JSON with current revision, exact work item IDs",
        "and findings that justify each item. Re-select risk and reasoning from evidence.",
        'If the entire phase is already fixed, return {"status":"NO_VERIFIABLE_FINDINGS"}',
        "rather than fabricate work. Do not load Project Leader: workers will.",
    ]
    result = "\n".join(requested)
    if len(result.encode("utf-8")) > 8000:
        raise PhaseContinuationError("Bounded phase order exceeds remote transport")
    return result


def validate_new_plan(fresh_b64: str, original_b64: str,
                      phase: int, current_sha: str) -> dict:
    if type(current_sha) is not str or not SHA.fullmatch(current_sha):
        raise PhaseContinuationError("Current verified target HEAD invalid")
    scope = scope_for_phase(original_b64, phase)
    try:
        _, metadata = agent_switch.parse_coordinator_envelope(fresh_b64)
        raw = base64.b64decode(fresh_b64, validate=True)
        value = json.loads(raw.decode("utf-8", "strict"))
        planned = plan_phases(value)
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PhaseContinuationError("New Coordinator audit invalid") from None
    if (value["target_repository"] != TARGET or
            value["audit"]["revision"] != current_sha or
            planned["phase_count"] != 1 or
            metadata["phase_count"] != 1 or
            set(planned["phases"][0]["task_ids"]) != set(scope["task_ids"])):
        raise PhaseContinuationError("Fresh audit changed original phase or revision")
    owned = {item["id"]: tuple(item["paths"]) for item in scope["work_items"]}
    if len(value["audit"]["work_items"]) != len(owned):
        raise PhaseContinuationError("Fresh audit omitted an original phase task")
    for item in value["audit"]["work_items"]:
        if (item["id"] not in owned or tuple(item["paths"]) != owned[item["id"]]
                or item.get("depends_on")):
            raise PhaseContinuationError("Fresh audit expanded work ownership")
    allowed = set(scope["paths"])
    for finding in value["audit"]["findings"]:
        if not set(finding["paths"]).issubset(allowed):
            raise PhaseContinuationError("Fresh audit introduced an unauthorized file")
    return {
        "audited_sha": current_sha, "phase": phase,
        "original_phase_count": scope["phase_count"],
        "remaining_phases": scope["phase_count"] - phase + 1,
        "task_ids": scope["task_ids"],
        "workers": planned["phases"][0]["worker_count"],
        "mode": planned["phases"][0]["mode"],
    }
