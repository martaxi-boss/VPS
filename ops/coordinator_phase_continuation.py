"""Deterministic follow-through of the ORIGINAL Owner-authorized Coordinator DAG.

No new model invocation. The Coordinator audits/plans ONCE; existing Codex
workers with Project Leader decide how to implement their authorized task on
the current verified target main. This module changes only audit base SHA,
never the original task identity, allowed paths, risk or reasoning policy.
"""
from __future__ import annotations

import base64
import json
import re

from ops import agent_switch
from ops.codex_audit_strategy import plan_phases
from ops.project_target import is_managed_target

TARGET = "martaxi-boss/Project-leader-codex"
SHA = re.compile(r"[0-9a-f]{40}\Z")


class PhaseContinuationError(ValueError):
    pass


def _audited(encoded: str) -> tuple[dict, dict]:
    """Only accept original Owner plans verified by the live audited router."""
    try:
        _, metadata = agent_switch.parse_coordinator_envelope(encoded)
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8", "strict"))
        phases = plan_phases(value)
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PhaseContinuationError("Original Owner DAG invalid") from None
    if (metadata["phase_count"] != phases["phase_count"] or
            phases["target_repository"] != value.get("target_repository") or
            not is_managed_target(value.get("target_repository"))):
        raise PhaseContinuationError("Original Owner DAG inconsistent")
    return value, phases


def scope_for_phase(original_b64: str, phase: int) -> dict:
    original, phases = _audited(original_b64)
    if (type(phase) is not int or
            not 2 <= phase <= phases["phase_count"] <= 8):
        raise PhaseContinuationError("Phase not authorized in original Owner DAG")
    selected = phases["phases"][phase - 1]
    ids = list(selected["task_ids"])
    rows = [r for r in original["audit"]["work_items"] if r["id"] in ids]
    if len(rows) != len(ids) or not 1 <= len(rows) <= 2:
        raise PhaseContinuationError("Phase task identity mismatch")
    return {
        "phase": phase,
        "phase_count": phases["phase_count"],
        "task_ids": ids,
        "work_items": rows,
        "paths": sorted({p for item in rows for p in item["paths"]}),
        "mode": selected["mode"],
        "worker_count": selected["worker_count"],
        "reasoning_by_task": selected["reasoning_by_task"],
    }


def prepared_phase(original_b64: str, phase: int, current_sha: str) -> dict:
    """Create the pre-approved next-phase *dispatch*, without calling Codex.

    The Supervisor must have already certified preceding CI/merge and bound
    current_sha to the actual target main. Workers must pin that exact SHA.
    """
    if type(current_sha) is not str or not SHA.fullmatch(current_sha):
        raise PhaseContinuationError("Verified current target HEAD invalid")
    original, _ = _audited(original_b64)
    scoped = scope_for_phase(original_b64, phase)
    ids = set(scoped["task_ids"])
    selected = [
        {k: v for k, v in work.items() if k != "depends_on"}
        for work in original["audit"]["work_items"]
        if work["id"] in ids
    ]
    referenced = set()
    for work in selected:
        referenced.update(work["finding_ids"])
    findings = [
        row for row in original["audit"]["findings"]
        if row["id"] in referenced
    ]
    planned = {
        "target_repository": original["target_repository"],
        "audit": {
            "revision": current_sha,
            "findings": findings,
            "work_items": selected,
        },
    }
    encoded = base64.b64encode(json.dumps(
        planned, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).decode("ascii")
    try:
        _order, metadata = agent_switch.parse_coordinator_envelope(encoded)
        second_plan = plan_phases(planned)
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PhaseContinuationError("Prepared phase fails worker contract") from None
    if (second_plan["phase_count"] != 1 or metadata["phase_count"] != 1
            or second_plan["phases"][0]["task_ids"] != scoped["task_ids"]
            or second_plan["phases"][0]["worker_count"] != scoped["worker_count"]
            or second_plan["phases"][0]["mode"] != scoped["mode"]
            or second_plan["phases"][0]["reasoning_by_task"]
            != scoped["reasoning_by_task"]):
        raise PhaseContinuationError("Prepared phase changed Owner planning")
    return {
        "target_repository": original["target_repository"],
        "coordinator_plan_b64": encoded,
        "phase": phase,
        "remaining_phases": scoped["phase_count"] - phase + 1,
        "audited_sha": current_sha,
        "task_ids": scoped["task_ids"],
        "paths": scoped["paths"],
        "workers": scoped["worker_count"],
        "mode": scoped["mode"],
        "reasoning_by_task": scoped["reasoning_by_task"],
    }
