#!/usr/bin/env python3
"""Passive Project Leader worker-status observer: Telegram transport only.

No GitHub API, PR integration, Codex dispatch or Human Gate decisions.
The existing deterministic PR publisher is a separate module.
"""
from __future__ import annotations

import os
import re
import sys

class SupervisorHold(ValueError):
    """A safe, non-Human-Gate block; code is a fixed non-private enum."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _int(value: str, label: str, top: int = 10**16) -> int:
    if (type(value) is not str or not re.fullmatch(r"[1-9][0-9]{0,15}", value)
            or int(value) > top):
        raise SupervisorHold("INVALID_" + label)
    return int(value)


def observe_worker_event() -> int:
    """Passive report transport from the existing authenticated GitHub runner.

    Only *carries* the canonical Project Leader worker's report, errors and
    trusted publisher state to the already configured private Telegram bot.
    NO AI, NO owner decision, NO Human Gate rules, NO GitHub mutation, NO
    workflow dispatch, NO worker instructions, and NO automatic resume.
    The legacy separate merge/CI gate is not invoked by this observation path.
    """
    from pathlib import Path

    category = os.environ.get("SUPERVISOR_OBSERVATION", "")
    mode = os.environ.get("CODEX_REPORT_MODE", "")
    status = os.environ.get("CODEX_JOB_STATUS", "")
    try:
        _int(os.environ.get("CODEX_ISSUE_NUMBER", ""), "NOTICE_ISSUE")
    except SupervisorHold:
        print("PROJECT_LEADER_SUPERVISOR_NOTICE=UNTRUSTED_ISSUE")
        return 2
    run_url = os.environ.get("CODEX_RUN_URL", "")
    if not re.fullmatch(
        r"https://github\.com/martaxi-boss/VPS/actions/runs/[1-9][0-9]{0,15}",
        run_url,
    ):
        print("PROJECT_LEADER_SUPERVISOR_NOTICE=INVALID_RUN_PROVENANCE")
        return 2
    if category == "WORKER_REPORT":
        if mode != "worker" or status != "WORKER_REPORT_RECEIVED":
            print("PROJECT_LEADER_SUPERVISOR_NOTICE=INVALID_REPORT_MODE")
            return 2
        temp = os.environ.get("RUNNER_TEMP", "")
        expected = Path(temp) / "report.md" if temp else None
        supplied = os.environ.get("CODEX_REPORT_PATH", "")
        if (expected is None or supplied != str(expected) or
                not expected.is_file() or expected.is_symlink() or
                not 1 <= expected.stat().st_size <= 65536):
            print("PROJECT_LEADER_SUPERVISOR_NOTICE=REPORT_UNAVAILABLE")
            return 2
    elif category == "FINAL_STATE":
        if mode != "status" or status not in {
            "MERGED", "NO_CHANGE", "PR_STAGED", "PR_NEEDS_ATTENTION",
            "NO_CHANGE_UNVERIFIED", "NOT_STARTED", "NOT_COMPLETED", "FAILED"
        }:
            print("PROJECT_LEADER_SUPERVISOR_NOTICE=INVALID_FINAL_STATE")
            return 2
    else:
        print("PROJECT_LEADER_SUPERVISOR_NOTICE=UNRECOGNIZED_EVENT")
        return 2
    # The report is untrusted model text, destined ONLY for the Owner's
    # existing private chat. It is NEVER a command or a Human Gate classifier.
    try:
        if __package__:
            from ops import telegram_gateway as gateway
        else:
            import telegram_gateway as gateway
        gateway.notify()
    except (RuntimeError, OSError):
        print("PROJECT_LEADER_SUPERVISOR_NOTICE=TELEGRAM_DELIVERY_FAILED")
        return 2
    print("PROJECT_LEADER_SUPERVISOR_NOTICE=FORWARDED")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["observe"]:
        sys.exit(2)
    sys.exit(observe_worker_event())
