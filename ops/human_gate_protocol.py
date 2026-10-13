#!/usr/bin/env python3
"""Strict, unprivileged transport for EXISTING Project Leader Human Gates.

A Codex report is untrusted prose. A structured, bounded footer is solely a
claim requiring human attention, never a credential, authority grant, command,
workflow dispatch, or excuse to bypass normal recovery/CI. The canonical
Project Leader skill defines Human Gate; this file does NOT redefine it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

START = "PROJECT_LEADER_HUMAN_GATE_V1_BEGIN"
END = "PROJECT_LEADER_HUMAN_GATE_V1_END"
KINDS = frozenset({"EXCLUSIVE_HUMAN_INTERVENTION", "NEW_UNCOVERED_MATERIAL_DECISION"})
MAX_REPORT_BYTES = 65536
TEXT_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
CREDENTIAL_VALUE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{15,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|password|senha|secret|token)\s*[:=]\s*\S{8,})"
)


class GateProtocolError(ValueError):
    pass


def _safe_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if (type(value) is not str or not minimum <= len(value) <= maximum or
            TEXT_UNSAFE.search(value) or CREDENTIAL_VALUE.search(value) or
            "\n" in value or "\r" in value or "\u2028" in value or
            "\u2029" in value):
        raise GateProtocolError("Invalid or potentially sensitive " + label)
    return value


def parse_report(report: bytes) -> dict | None:
    if type(report) is not bytes or not 1 <= len(report) <= MAX_REPORT_BYTES:
        raise GateProtocolError("Missing or oversized private worker report")
    try:
        text = report.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise GateProtocolError("Invalid report encoding") from None
    # The model reports ordinary fixes/technical blockers as normal prose.
    # A real Human Gate must be the *final*, exactly framed object.
    if START not in text and END not in text:
        return None
    matches = re.findall(
        r"(?m)^" + START + r"\r?\n([^\r\n]{20,1200})\r?\n" +
        END + r"\s*\Z", text,
    )
    if len(matches) != 1 or text.count(START) != 1 or text.count(END) != 1:
        raise GateProtocolError("Malformed or repeated Human Gate footer")
    try:
        raw = json.loads(matches[0])
    except json.JSONDecodeError:
        raise GateProtocolError("Malformed Human Gate JSON") from None
    if (type(raw) is not dict or
            set(raw) != {"reason", "summary", "owner_action"} or
            raw["reason"] not in KINDS):
        raise GateProtocolError("Unrecognized Human Gate fields/reason")
    return {
        "reason": raw["reason"],
        "summary": _safe_text(raw["summary"], "summary", 10, 240),
        "owner_action": _safe_text(raw["owner_action"], "owner_action", 10, 550),
    }


def run_cli(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "detect":
        raise GateProtocolError("Usage: detect REPORT OUTPUT")
    report, target = (Path(p) for p in argv[1:])
    if not report.is_file() or report.is_symlink():
        raise GateProtocolError("Report not a regular private file")
    gate = parse_report(report.read_bytes())
    if gate is None:
        return 10
    if target.exists() or target.is_symlink():
        raise GateProtocolError("Existing Human Gate transport refused")
    target.write_text(json.dumps(gate, ensure_ascii=False, sort_keys=True) + "\n",
                      encoding="utf-8")
    target.chmod(0o600)
    print("PROJECT_LEADER_HUMAN_GATE=WORKER_CLAIM_VALIDATED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run_cli(sys.argv[1:]))
    except (GateProtocolError, OSError) as exc:
        print("PROJECT_LEADER_HUMAN_GATE=INVALID:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
