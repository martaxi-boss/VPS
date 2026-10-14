#!/usr/bin/env python3
"""Validate generic agent plans without starting an agent or spending tokens.

The historical single-Codex dispatch remains intact. The bounded live
workflow additionally supports two explicit Codex workers in serial/parallel.
The versioned provider-neutral plan allows future authenticated adapters,
but unsupported providers or more than two jobs fail before any model call.
"""
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import FrozenSet, Optional

try:
    from ops.codex_resource_policy import choose_effort
except ModuleNotFoundError:
    # Direct 'python3 ops/agent_switch.py' starts with ops/ on sys.path.
    from codex_resource_policy import choose_effort

try:
    from ops.project_target import is_managed_target
except ModuleNotFoundError:
    from project_target import is_managed_target

MODES = {"serial", "parallel"}
MAX_TASKS = 8
PLAN_VERSION = 1
TASK_FIELDS = {"id", "provider", "task", "model", "reasoning_effort", "allow_no_change"}
REQUIRED_TASK_FIELDS = {"id", "provider", "task"}
ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
SUSPICIOUS = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|access[_-]?token|secret|password|senha)\s*[:=]\s*\S+|"
    r"gh[pousr]_[a-zA-Z0-9]{12,}|"
    r"\$\{\{|::(?:set-output|add-mask|stop-commands)\b|<script\b)"
)
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class OrderError(ValueError):
    pass


@dataclass(frozen=True)
class ProviderAdapter:
    """Static capabilities of a reviewed provider adapter."""

    available: bool
    models: FrozenSet[str]
    reasoning_efforts: FrozenSet[str]
    unavailable_reason: str = "adapter is not authenticated, tested and authorized"


# Registration alone never enables execution. ``available`` may only become
# true after the corresponding authenticated executor is integrated and tested.
PROVIDER_REGISTRY = {
    "codex": ProviderAdapter(
        available=True,
        models=frozenset({"gpt-5.6-sol"}),
        reasoning_efforts=frozenset({"auto", "low", "medium", "high"}),
    ),
    "gemini": ProviderAdapter(False, frozenset(), frozenset()),
    "composer": ProviderAdapter(False, frozenset(), frozenset()),
    "claude": ProviderAdapter(False, frozenset(), frozenset()),
}


def _safe_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise OrderError(f"Invalid {label} length")
    if CONTROL_CHARACTERS.search(value) or SUSPICIOUS.search(value):
        raise OrderError(f"Unsafe content in {label}; do not include secrets or control syntax")
    return value


def _validate_optional_choice(
    source: dict, target: dict, field: str, allowed: FrozenSet[str], task_id: str
) -> None:
    if field not in source:
        return
    value = source[field]
    if type(value) is not str or value not in allowed:
        raise OrderError(f"Unauthorized {field} for task {task_id}")
    target[field] = value


def _normalise_tasks(tasks: object) -> list:
    # Legacy form: {"codex": "task"}. Preserve insertion order and give each
    # task a stable identity. The form cannot express repeated providers.
    if isinstance(tasks, dict):
        if not tasks:
            raise OrderError("At least one task is required")
        converted = []
        for provider, task in tasks.items():
            if type(provider) is not str:
                raise OrderError("Legacy task provider names must be strings")
            converted.append({"id": provider, "provider": provider, "task": task})
        tasks = converted

    if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
        raise OrderError(f"Tasks must be an ordered list of 1-{MAX_TASKS} objects")

    normalised = []
    seen_ids = set()
    for position, task in enumerate(tasks, start=1):
        if not isinstance(task, dict):
            raise OrderError(f"Task {position} must be an object")
        fields = set(task)
        if not REQUIRED_TASK_FIELDS.issubset(fields) or not fields.issubset(TASK_FIELDS):
            raise OrderError(
                f"Task {position} requires id, provider and task; optional fields are "
                "model, reasoning_effort and allow_no_change"
            )

        task_id = task["id"]
        if type(task_id) is not str or not 1 <= len(task_id) <= 64 or not ID_PATTERN.fullmatch(task_id):
            raise OrderError(f"Invalid task id at position {position}")
        if task_id in seen_ids:
            raise OrderError(f"Duplicate task id: {task_id}")
        seen_ids.add(task_id)

        provider = task["provider"]
        if type(provider) is not str or provider not in PROVIDER_REGISTRY:
            raise OrderError(f"Unknown provider for task {task_id}")
        adapter = PROVIDER_REGISTRY[provider]
        if not adapter.available:
            raise OrderError(
                f"Provider {provider} is unavailable: {adapter.unavailable_reason}. No agent started"
            )

        clean = {
            "id": task_id,
            "provider": provider,
            "task": _safe_text(task["task"], f"task {task_id}", 12, 2200),
        }
        _validate_optional_choice(task, clean, "model", adapter.models, task_id)
        _validate_optional_choice(
            task, clean, "reasoning_effort", adapter.reasoning_efforts, task_id
        )
        # Explicit permission for no-diff read-only work; implementation tasks
        # must not be marked successful merely because the model returned 0.
        if "allow_no_change" in task:
            if type(task["allow_no_change"]) is not bool:
                raise OrderError(f"allow_no_change must be a boolean for task {task_id}")
            clean["allow_no_change"] = task["allow_no_change"]
        normalised.append(clean)
    return normalised


def parse_order(raw: str) -> dict:
    """Parse and validate an order, returning the canonical ordered form."""
    if not isinstance(raw, str) or not 10 <= len(raw.encode("utf-8")) <= 6800:
        raise OrderError("Order must be 10-6800 bytes")
    try:
        order = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OrderError("Use one JSON task manifest") from exc
    # Explicit Owner-audited work is compiled into the existing bounded router.
    # The dispatcher itself chooses workers, mode, and effort from inspected
    # paths/dependencies/severity, never from prompt keywords alone.
    if isinstance(order, dict) and set(order) == {"target_repository", "audit"}:
        try:
            try:
                from ops.codex_audit_strategy import compile_audit
            except ModuleNotFoundError:
                from codex_audit_strategy import compile_audit
            order = compile_audit(order)
        except ValueError as exc:
            raise OrderError(str(exc)) from None
    required = {"target_repository", "mode", "tasks"}
    allowed = required | {"serial_independent"}
    if not isinstance(order, dict) or not required.issubset(order) or not set(order).issubset(allowed):
        raise OrderError("Required fields: target_repository, mode, tasks")
    target = order["target_repository"]
    if type(target) is not str or not is_managed_target(target):
        raise OrderError("Target repository is not yet authorized")
    mode = order["mode"]
    if type(mode) is not str or mode not in MODES:
        raise OrderError("Mode must be serial or parallel")
    tasks = _normalise_tasks(order["tasks"])
    independent = order.get("serial_independent", False)
    if "serial_independent" in order and (
        type(independent) is not bool or mode != "serial" or len(tasks) != 2
    ):
        raise OrderError("serial_independent requires a boolean and exactly two serial tasks")
    validated = {
        "target_repository": target,
        "mode": mode,
        "tasks": tasks,
    }
    if independent:
        validated["serial_independent"] = True
    return validated


def dispatch_plan(order: dict) -> dict:
    """Build the provider-neutral plan; this function performs no execution."""
    tasks = []
    previous_id: Optional[str] = None
    for task in order["tasks"]:
        item = dict(task)
        item["selected_reasoning_effort"] = choose_effort(task)
        item["effort_selection"] = "explicit" if task.get("reasoning_effort", "auto") != "auto" else "adaptive_task_boundary"
        item["depends_on"] = (
            [previous_id]
            if order["mode"] == "serial" and previous_id
            and not order.get("serial_independent", False)
            else []
        )
        tasks.append(item)
        previous_id = task["id"]
    return {
        "version": PLAN_VERSION,
        "target_repository": order["target_repository"],
        "mode": order["mode"],
        "execution_policy": {
            "explicit_tasks_only": True,
            "allow_provider_substitution": False,
            "parallel_tasks_declared_independent": order["mode"] == "parallel",
            "serial_independent_pr_only": bool(order.get("serial_independent", False)),
        },
        "tasks": tasks,
    }


def dispatch_plan_b64(order: dict) -> str:
    """Encode a validated plan as one injection-safe output value."""
    plan_json = json.dumps(dispatch_plan(order), separators=(",", ":"), sort_keys=True)
    return base64.b64encode(plan_json.encode("utf-8")).decode("ascii")


def _workflow_task(order: dict) -> dict:
    tasks = order["tasks"]
    if len(tasks) != 1 or tasks[0]["provider"] != "codex":
        raise OrderError(
            "Current workflow can execute exactly one Codex task; the complete multi-agent "
            "dispatch backend must be integrated before this plan can run. No agent started"
        )
    return tasks[0]


def codex_task(order: dict) -> str:
    task = _workflow_task(order)
    return (
        f"TARGET_REPOSITORY={order['target_repository']}\n"
        "Single explicit Codex job; do not create or substitute another agent.\n"
        + task["task"]
    )


def output_values(order: dict) -> dict:
    """Return safe Actions outputs for the existing one-Codex workflow only."""
    _workflow_task(order)  # Fail closed before returning any partial dispatch.
    return {
        # Keep the legacy outputs consumed by agent-switch.yml.
        "codex": "true",
        "gemini": "false",
        "composer": "false",
        "codex_task_b64": base64.b64encode(codex_task(order).encode("utf-8")).decode("ascii"),
        # Future executors can decode this after the workflow is explicitly upgraded.
        "dispatch_plan_b64": dispatch_plan_b64(order),
    }



def parse_owner_envelope(raw: str) -> tuple[dict, dict | None]:
    """Take one Owner-audited DAG; dispatch only its validated first wave.

    Other phases are intentionally held for exact-CI acceptance and fresh
    repository audit. The Owner's *entire* original text is bound to quota
    checkpoints so changes to a held later phase cannot silently reuse an
    earlier continuation lease.
    """
    if type(raw) is not str or len(raw.encode("utf-8")) > 24_000:
        raise OrderError("Owner phase audit exceeds bounded request size")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return parse_order(raw), None
    if not (isinstance(value, dict) and
            set(value) == {"target_repository", "audit"}):
        return parse_order(raw), None

    try:
        try:
            from ops.codex_audit_strategy import plan_phases
        except ModuleNotFoundError:
            from codex_audit_strategy import plan_phases
        phases = plan_phases(value)
    except ValueError as exc:
        raise OrderError("Owner phase audit failed validated planning") from None

    first = phases["phases"][0]
    canonical = first["dispatch_json"]
    if type(canonical) is not str:
        raise OrderError("First audited phase is not dispatchable")
    order = parse_order(canonical)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    order["phase_owner_digest"] = digest
    # Keep bounded reporting metadata in the authenticated normalized order,
    # so quota continuation can report the same held phases without trusting
    # dispatch payloads or fetching the Owner Issue a second time.
    order["phase_count"] = phases["phase_count"]
    order["held_task_count"] = sum(
        len(phase["task_ids"]) for phase in phases["phases"][1:]
    )
    return order, {
        "phase_count": phases["phase_count"],
        "active_task_ids": first["task_ids"],
        "pending_task_ids": [
            ident for phase in phases["phases"][1:]
            for ident in phase["task_ids"]
        ],
        "audited_revision": phases["audited_revision"],
        "owner_digest": digest,
    }


def parse_coordinator_envelope(encoded: str) -> tuple[dict, dict]:
    """Route an independently validated Coordinator audit, never model prose.

    The caller MUST authenticate the originating Owner Issue. This bounded
    adapter reuses the exact Owner audit router and does not grant dispatch
    authority, bypass the file guards, or start any agents.
    """
    if type(encoded) is not str or not 16 <= len(encoded) <= 32_000:
        raise OrderError("Coordinator plan encoding is empty or oversized")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        if (not raw or len(raw) > 24_000 or
                base64.b64encode(raw).decode("ascii") != encoded):
            raise ValueError("non-canonical or oversized audit")
        text = raw.decode("utf-8", "strict")
        payload = json.loads(text)
    except (ValueError, UnicodeError) as exc:
        raise OrderError("Coordinator plan encoding is invalid") from None
    if (not isinstance(payload, dict) or
            set(payload) != {"target_repository", "audit"} or
            not is_managed_target(payload["target_repository"])):
        raise OrderError("Coordinator plan target or audit contract is invalid")
    order, metadata = parse_owner_envelope(text)
    if metadata is None or not order.get("phase_owner_digest"):
        raise OrderError("Coordinator did not produce a valid phased audit")
    if order["target_repository"] != payload["target_repository"]:
        raise OrderError("Coordinator target mismatch")
    return order, metadata


def workflow_values(order: dict, resume_stage: str = "") -> dict:
    """Bounded trusted router for one or two verified Codex workers.

    The versioned dispatch_plan remains provider-neutral; the active backend
    supports only verified Codex, at most two jobs. Any other plan is rejected
    as a whole before GitHub starts a model.
    """
    tasks = order["tasks"]
    if not 1 <= len(tasks) <= 2 or any(t["provider"] != "codex" for t in tasks):
        raise OrderError(
            "Active workflow supports one or two Codex workers only; "
            "the whole unsupported plan is blocked. No agent started"
        )
    # A quota continuation is a single *stage* lease, not authorization to
    # replay the original whole serial/parallel order. Validate this before
    # generating any Actions outputs, including for a single worker.
    if type(resume_stage) is not str or resume_stage not in ("", "1", "2"):
        raise OrderError("Unrecognized quota continuation stage; no agent started")
    if resume_stage == "2" and len(tasks) != 2:
        raise OrderError("Second stage is unavailable in this Owner order")
    run_stage_1 = str(resume_stage in ("", "1")).lower()
    run_stage_2 = str(len(tasks) == 2 and resume_stage in ("", "2")).lower()
    audited = str(any("AUDIT_ALLOWED_PATHS=" in t["task"] for t in tasks)).lower()
    if len(tasks) == 1:
        legacy = output_values(order)
        return {
            **legacy,
            "task_count": "1",
            "mode": order["mode"],
            "run_stage_1": run_stage_1,
            "run_stage_2": run_stage_2,
            "serial_independent": "false",
            "audit_managed": audited,
            "codex_1_task_b64": legacy["codex_task_b64"],
            "codex_2_task_b64": "",
            "allow_no_change_1": str(tasks[0].get("allow_no_change", False)).lower(),
            "allow_no_change_2": "false",
            "codex_1_reasoning_effort": choose_effort(tasks[0]),
            "codex_2_reasoning_effort": "",
        }

    encoded = []
    for position, task in enumerate(tasks, start=1):
        if order["mode"] == "parallel":
            extra = ("Parallel independent Codex worker; use only this private checkout. "
                     "Do not depend on sibling results or merge a sibling change.")
        elif order.get("serial_independent", False):
            if position == 1:
                extra = ("Serial independent Codex worker 1; start immediately on fresh main; "
                         "do not depend on or merge a sibling's unmerged changes. "
                         "Publish only your own isolated PR.")
            else:
                extra = ("Serial independent Codex worker 2; wait until the previous worker "
                         "has a verified, CI-passing PR or NO_CHANGE. Work from fresh main; "
                         "do not depend on or merge the previous worker's unmerged changes.")
        else:
            extra = ("Serial Codex worker; the previous stage must complete "
                     "and become visible on the fresh target main before this step.")
        prompt = (
            f"TARGET_REPOSITORY={order['target_repository']}\n"
            f"Explicit worker {task['id']} of 2 in {order['mode']} mode. "
            "Do not create or substitute extra agents.\n"
            f"{extra}\n"
            + task["task"]
        )
        encoded.append(base64.b64encode(prompt.encode("utf-8")).decode("ascii"))
    return {
        "codex": "true",
        "gemini": "false",
        "composer": "false",
        "codex_task_b64": "",
        "dispatch_plan_b64": dispatch_plan_b64(order),
        "task_count": "2",
        "mode": order["mode"],
        "run_stage_1": run_stage_1,
        "run_stage_2": run_stage_2,
        "serial_independent": str(order.get("serial_independent", False)).lower(),
        "audit_managed": audited,
        "codex_1_task_b64": encoded[0],
        "codex_2_task_b64": encoded[1],
        "allow_no_change_1": str(tasks[0].get("allow_no_change", False)).lower(),
        "allow_no_change_2": str(tasks[1].get("allow_no_change", False)).lower(),
        "codex_1_reasoning_effort": choose_effort(tasks[0]),
        "codex_2_reasoning_effort": choose_effort(tasks[1]),
    }


def main() -> int:
    raw = sys.stdin.read(7500)
    try:
        order = parse_order(raw)
        output = workflow_values(order)
    except OrderError as exc:
        print(f"AGENT_SWITCH_BLOCKED: {exc}", file=sys.stderr)
        return 2
    for key, value in output.items():
        print(key + "=" + value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
