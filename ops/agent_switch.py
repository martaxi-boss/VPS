#!/usr/bin/env python3
"""Validate generic agent plans without starting an agent or spending tokens.

The current GitHub workflow can execute exactly one Codex task. This module
also defines the versioned, provider-neutral dispatch contract that a future
executor can consume once it has authenticated and tested adapters.
"""
import base64
import json
import re
import sys
from dataclasses import dataclass
from typing import FrozenSet, Optional

ALLOWED_REPOSITORIES = {"martaxi-boss/VPS", "martaxi-boss/Project-leader"}
MODES = {"serial", "parallel"}
MAX_TASKS = 8
PLAN_VERSION = 1
TASK_FIELDS = {"id", "provider", "task", "model", "reasoning_effort"}
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
        reasoning_efforts=frozenset({"medium"}),
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
                "model and reasoning_effort"
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
    if not isinstance(order, dict) or set(order) != {"target_repository", "mode", "tasks"}:
        raise OrderError("Required fields: target_repository, mode, tasks")
    target = order["target_repository"]
    if type(target) is not str or target not in ALLOWED_REPOSITORIES:
        raise OrderError("Target repository is not yet authorized")
    mode = order["mode"]
    if type(mode) is not str or mode not in MODES:
        raise OrderError("Mode must be serial or parallel")
    return {
        "target_repository": target,
        "mode": mode,
        "tasks": _normalise_tasks(order["tasks"]),
    }


def dispatch_plan(order: dict) -> dict:
    """Build the provider-neutral plan; this function performs no execution."""
    tasks = []
    previous_id: Optional[str] = None
    for task in order["tasks"]:
        item = dict(task)
        item["depends_on"] = [previous_id] if order["mode"] == "serial" and previous_id else []
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



def workflow_values(order: dict) -> dict:
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
    if len(tasks) == 1:
        legacy = output_values(order)
        return {
            **legacy,
            "task_count": "1",
            "mode": order["mode"],
            "codex_1_task_b64": legacy["codex_task_b64"],
            "codex_2_task_b64": "",
        }

    encoded = []
    for task in tasks:
        extra = (
            "Parallel independent Codex worker; use only this private checkout. "
            "Do not depend on sibling results or merge a sibling change."
            if order["mode"] == "parallel"
            else "Serial Codex worker; the previous stage must complete "
            "and become visible on the fresh target main before this step."
        )
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
        "codex_1_task_b64": encoded[0],
        "codex_2_task_b64": encoded[1],
    }


def main() -> int:
    raw = sys.stdin.read(7500)
    try:
        order = parse_order(raw)
        output = output_values(order)
    except OrderError as exc:
        print(f"AGENT_SWITCH_BLOCKED: {exc}", file=sys.stderr)
        return 2
    for key, value in output.items():
        print(key + "=" + value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
