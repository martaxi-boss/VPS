#!/usr/bin/env python3
"""Supervisor's factual private Telegram notice for real Codex quota samples.

Inputs are sanitized snapshots from the signed-in provider via
ops/codex_account_limits.py, not estimates or a local token ledger.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

STATES = {"AVAILABLE", "BLOCKED", "UNKNOWN"}
RUN = re.compile(r"^[1-9][0-9]{0,15}$")


def parse_sample(path: Path) -> dict:
    if (not path.is_file() or path.is_symlink() or
            not 10 < path.stat().st_size < 5000):
        raise RuntimeError("QUOTA_SAMPLE_MISSING")
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("QUOTA_SAMPLE_INVALID") from None
    if (not isinstance(result, dict) or
            result.get("source") != "codex_app_server" or
            result.get("status") not in STATES):
        raise RuntimeError("QUOTA_PROVENANCE_UNVERIFIED")
    if result["status"] != "UNKNOWN":
        if (result.get("auth") != "chatgpt" or
                result.get("bucket") != "codex" or
                result.get("model_specific_state") != "NOT_VERIFIED" or
                result.get("owner_resumption") != "REQUIRES_NEW_OWNER_ORDER"):
            raise RuntimeError("QUOTA_SAMPLE_NOT_CHATGPT")
        if not isinstance(result.get("windows"), list) or len(result["windows"]) not in (1, 2):
            raise RuntimeError("QUOTA_WINDOW_MISSING")
    return result


def report(sample: dict, run_id: int) -> str:
    if type(run_id) is not int or not 1 <= run_id < 10**16:
        raise RuntimeError("UNTRUSTED_RUN")
    state = sample["status"]
    if state == "AVAILABLE":
        lines = ["Conta ChatGPT/Codex: quota partilhada DISPONÍVEL neste instante.",
                 "Isto não garante disponibilidade de limites específicos do modelo."]
    elif state == "BLOCKED":
        lines = ["Conta ChatGPT/Codex: limite real ATINGIDO segundo o Codex.",
                 "Operação protegida; tarefas pendentes não devem ser reiniciadas."]
    else:
        lines = ["Quota ChatGPT/Codex: NÃO VERIFICADA.",
                 "Não se assume quota disponível nem se reinicia trabalho."]
    for item in sample.get("windows", [])[:2]:
        if (not isinstance(item, dict) or item.get("window") not in ("primary", "secondary")
                or type(item.get("used_percent")) is not int
                or not 0 <= item["used_percent"] <= 100):
            raise RuntimeError("UNTRUSTED_WINDOW")
        lines.append(item["window"] + ": " + str(item["used_percent"]) +
                     "% utilizado (valor devolvido pelo Codex).")
        timestamp = item.get("resets_at")
        if timestamp is not None:
            if type(timestamp) is not int or not 1_500_000_000 <= timestamp < 4_102_444_800:
                raise RuntimeError("UNTRUSTED_RESET")
            lines.append("Reposição indicada pela conta (UTC): " +
                         datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
                             "%Y-%m-%d %H:%M UTC") + ".")
    lines.append("Intervenção: só o Owner decide quando dar nova ordem ou escolher outro meio.")
    lines.append("Esta observação não consome tokens de modelos.")
    lines.append("https://github.com/martaxi-boss/VPS/actions/runs/" + str(run_id))
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] != "notify":
        return 2
    try:
        sample = parse_sample(Path(argv[2]))
        previous = argv[3]
        if previous and previous not in STATES:
            raise RuntimeError("UNTRUSTED_PREVIOUS_STATE")
        state = sample["status"]
        if previous == state and os.environ.get("QUOTA_FORCE_TEST") != "1":
            print("QUOTA_SUPERVISOR=UNCHANGED")
            return 11
        if os.environ.get("GITHUB_REPOSITORY") != "martaxi-boss/VPS":
            raise RuntimeError("UNTRUSTED_REPOSITORY")
        run_id = int(os.environ.get("GITHUB_RUN_ID", "0"))
        from ops import telegram_gateway, supervisor_audit
        message = report(sample, run_id)
        if not telegram_gateway.BOT_TOKEN or not telegram_gateway.CHAT_ID:
            raise RuntimeError("PRIVATE_TELEGRAM_NOT_CONFIGURED")
        telegram_gateway.say(supervisor_audit.observation(message, source="quota"))
        print("QUOTA_SUPERVISOR=DELIVERED_" + state)
        return 0
    except (ValueError, RuntimeError, OSError):
        print("QUOTA_SUPERVISOR=NOT_CERTIFIED", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
