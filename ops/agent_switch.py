#!/usr/bin/env python3
"""Small Owner-Issue -> named executor switch. No credentials or model calls.

The GitHub Issue is the durable instruction; this module validates its JSON
body and derives each executor's immutable task. Publication stays in the
existing trusted Codex GitHub Actions workflow. Other providers fail closed
until their independent authenticated runners are integrated and tested.
"""
import base64
import json
import re
import sys

ALLOWED_REPOSITORIES = {"martaxi-boss/VPS", "martaxi-boss/Project-leader"}
AGENT_NAMES = {"codex", "gemini", "composer"}
MODES = {"parallel"}
SUSPICIOUS = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|access[_-]?token|secret|password|senha)\s*[:=]\s*\S+|"
    r"gh[pousr]_[a-zA-Z0-9]{12,})"
)


class OrderError(ValueError):
    pass


def parse_order(raw: str) -> dict:
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
    if not isinstance(order["mode"], str) or order["mode"] not in MODES:
        raise OrderError("Only parallel independent tasks are supported")
    tasks = order["tasks"]
    if not isinstance(tasks, dict) or not tasks or not set(tasks).issubset(AGENT_NAMES):
        raise OrderError("Tasks must name codex, gemini and/or composer")
    for agent, task in tasks.items():
        if not isinstance(task, str) or not 12 <= len(task) <= 2200:
            raise OrderError(f"Invalid {agent} task length")
        if "\x00" in task or SUSPICIOUS.search(task):
            raise OrderError("Do not put credentials into public GitHub Issues")
    return order


def codex_task(order: dict) -> str:
    if "codex" not in order["tasks"]:
        raise OrderError("No Codex task selected")
    return (
        f"TARGET_REPOSITORY={order['target_repository']}\n"
        "Parallel independent agent job; work in your own branch and do not "
        "depend on unfinished sibling tasks. Do not merge another agent's changes.\n"
        + order["tasks"]["codex"]
    )


def output_values(order: dict) -> dict:
    # One straight b64 output line avoids GitHub Actions multiline-output injection.
    result = {name: "true" if name in order["tasks"] else "false"
              for name in sorted(AGENT_NAMES)}
    result["codex_task_b64"] = (
        base64.b64encode(codex_task(order).encode("utf-8")).decode("ascii")
        if "codex" in order["tasks"] else ""
    )
    return result


def main() -> int:
    raw = sys.stdin.read(7500)
    try:
        order = parse_order(raw)
        output = output_values(order)
    except OrderError as exc:
        print(f"AGENT_SWITCH_BLOCKED: {exc}", file=sys.stderr)
        return 2
    # Do not claim that named agents have functional connections.
    for k, v in output.items():
        print(k + "=" + v)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
