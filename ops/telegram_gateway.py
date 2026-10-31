#!/usr/bin/env python3
"""Existing passive Supervisor Telegram egress only.

No incoming orders, polling, issue creation, workflow dispatch, or AI planning.
"""
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

REPO = os.environ.get("GITHUB_REPOSITORY", "martaxi-boss/VPS")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
GH_TOKEN = os.environ.get("GH_TOKEN", "").strip()

def telegram(method, data=None, *, document=None):
    if method not in ('sendMessage', 'sendDocument'):
        raise RuntimeError('Telegram egress is outbound-only')
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/" + method
    data = dict(data or {})
    headers = {}
    if document is None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = urlencode(data).encode("utf-8")
    else:
        filename, file_bytes = document
        boundary = "----CodexBridge" + uuid.uuid4().hex
        parts = []
        for key, value in data.items():
            parts.extend([
                ("--" + boundary + "\r\n").encode(),
                ('Content-Disposition: form-data; name="' + key + '"\r\n\r\n').encode(),
                str(value).encode("utf-8"), b"\r\n",
            ])
        parts.extend([
            ("--" + boundary + "\r\n").encode(),
            ('Content-Disposition: form-data; name="document"; filename="' +
             filename + '"\r\n').encode(),
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n",
            file_bytes, b"\r\n",
            ("--" + boundary + "--\r\n").encode(),
        ])
        payload = b"".join(parts)
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    try:
        req = Request(url, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=25) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not result.get("ok"):
            raise RuntimeError("Telegram API rejected request")
        return result["result"]
    except HTTPError as exc:
        # Never print the URL: it contains the Telegram bot token.
        raise RuntimeError("Telegram API HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError):
        raise RuntimeError("Telegram API connection failed") from None


def github(method, path, data=None):
    if method != 'GET' or data is not None:
        raise RuntimeError('Passive Supervisor GitHub access is read-only')
    if not GH_TOKEN:
        raise RuntimeError("GitHub Actions token is missing")
    url = "https://api.github.com/repos/" + REPO + "/" + path.lstrip("/")
    headers = {
        "Authorization": "Bearer " + GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Codex-Telegram-Bridge",
    }
    if data is None:
        payload = None
    else:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, data=payload, headers=headers, method=method),
                     timeout=25) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except HTTPError as exc:
        raise RuntimeError("GitHub API HTTP " + str(exc.code) +
                           " at " + path.split("?")[0]) from None
    except (URLError, TimeoutError):
        raise RuntimeError("GitHub API connection failed") from None


def _supervisor_audit():
    """Shared factual auditor; supports both module and script entrypoints."""
    try:
        from ops import supervisor_audit
    except ModuleNotFoundError:
        import supervisor_audit
    return supervisor_audit


def say(message):
    """Every Owner-directed text message crosses the Supervisor egress audit."""
    if not CHAT_ID or not re.fullmatch(r"[1-9][0-9]{3,17}", CHAT_ID):
        raise RuntimeError("Private Supervisor destination is unavailable")
    verified = _supervisor_audit().check_delivery(message)
    telegram("sendMessage", {
        "chat_id": CHAT_ID,
        "text": verified,
        "disable_web_page_preview": True,
    })

def private_report_status(status):
    """Distinguish staged PRs and unverified results from completed work."""
    if status in ("success", "MERGED", "NO_CHANGE"):
        return "✅ Execução concluída (verificar o resultado)"
    if status == "PR_STAGED":
        return "📝 PR pronta para revisão; alterações NÃO integradas"
    if status == "WORKER_REPORT_RECEIVED":
        return "📩 Relatório do trabalhador recebido; validação final pendente"
    if status == "PAUSED_QUOTA":
        return "⏸️ QUOTA REAL DO CHATGPT/CODEX ATINGIDA — aguarda decisão do Owner"
    if status == "QUOTA_UNVERIFIED":
        return "⏸️ Cota real não verificável — trabalho protegido, sem Codex"
    if status in ("NOT_STARTED", "NOT_COMPLETED", "FAILED"):
        return "⚠️ Execução interrompida ou não certificada"
    if status in ("NO_CHANGE_UNVERIFIED", "PR_NEEDS_ATTENTION"):
        return "⚠️ Revisão necessária; objetivo NÃO certificado"
    return "⚠️ Não concluído ou não verificado"


def notify():
    """Supervisor audits factual origin/outcomes, then privately forwards them.

    The report content is never used as a command, Human Gate classifier or
    public GitHub Issue; only the Project Leader worker owns those decisions.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_NOTIFY=NOT_CONFIGURED")
        return
    audit = _supervisor_audit()
    status = os.environ.get("CODEX_JOB_STATUS", "unknown")
    issue = os.environ.get("CODEX_ISSUE_NUMBER", "")
    run_url = os.environ.get("CODEX_RUN_URL", "")
    worker = os.environ.get("CODEX_INSTANCE_ID", "")
    if not re.fullmatch(r"(?:[12]|p[2-8]-[12])?", worker):
        raise RuntimeError("Invalid trusted Codex worker identity")
    label = (f" fase {worker[1]} trabalhador {worker[-1]}"
             if worker.startswith("p") else (f" {worker}" if worker else ""))
    outcome = private_report_status(status)
    # The Supervisor must not repeat a success badge when trusted CI disagrees.
    if (os.environ.get("CODEX_REPORT_MODE", "worker") == "status"
            and status in ("MERGED", "NO_CHANGE")
            and any(os.environ.get(key) in ("failure", "cancelled") for key in
                    ("PREFLIGHT_OUTCOME", "STAGE_OUTCOME", "CODEX_OUTCOME",
                     "COLLECT_OUTCOME", "ARTIFACTS_OUTCOME", "PUBLISH_OUTCOME"))):
        outcome = "⚠️ INCONSISTÊNCIA: conclusão NÃO CERTIFICADA"
    top = "🤖 Codex" + label + " — " + outcome + "\n"
    if issue:
        top += "Tarefa #" + issue + "\n"
    top += "Repositório: " + REPO + "\n"
    if issue:
        top += "https://github.com/" + REPO + "/issues/" + issue + "\n"
    if run_url:
        top += run_url + "\n"

    mode = os.environ.get("CODEX_REPORT_MODE", "worker")
    if mode == "status":
        stages = (("PREFLIGHT_OUTCOME", "Pré-validação"),
                  ("STAGE_OUTCOME", "VPS"),
                  ("CODEX_OUTCOME", "Codex"),
                  ("COLLECT_OUTCOME", "Recolha"),
                  ("ARTIFACTS_OUTCOME", "Artefactos"),
                  ("PUBLISH_OUTCOME", "Publicação/CI"))
        allowed = {"success", "failure", "skipped", "cancelled"}
        facts = {key: os.environ[key] for key, _ in stages
                 if os.environ.get(key) in allowed}
        details = [name + ": " + facts[key]
                   for key, name in stages if key in facts]
        if status == "PAUSED_QUOTA":
            proof = os.environ.get("QUOTA_HOLD_OUTCOME", "unknown")
            if proof == "success":
                details.append("Checkpoint da tarefa: registado para decisão do Owner. "
                               "Se houver trabalho parcial, o espaço privado da VPS é preservado.")
            else:
                details.append("ATENÇÃO: checkpoint GitHub ainda NÃO certificado. "
                               "Não reiniciar; verificar primeiro o espaço privado na VPS.")
            details.append("Retoma: apenas após nova ordem autenticada do Owner.")
        suffix = ("\n" + "\n".join(details)) if details else ""
        audit_report = audit.pipeline(issue=issue, run_url=run_url,
                                      worker=worker, status=status, steps=facts)
        # Never include the private worker report in this second notification.
        say(audit_report + top + "\nEstado final do pipeline." + suffix +
            "\nConsulta a tarefa no GitHub.")
        print("TELEGRAM_NOTIFY=SENT")
        return
    if mode != "worker":
        raise RuntimeError("Invalid passive Supervisor message mode")

    report_path = Path(os.environ.get("CODEX_REPORT_PATH", "/nonexistent"))
    if not report_path.is_file() or report_path.is_symlink():
        raise RuntimeError("Supervisor refused an absent or symlink worker report")
    raw_report = report_path.read_bytes()
    if not 1 <= len(raw_report) <= 65536:
        raise RuntimeError("Supervisor refused an invalid-size report")
    report = raw_report.decode("utf-8", errors="replace")
    audit_report = audit.worker_report(
        issue=issue, run_url=run_url, worker=worker, status=status, report=raw_report)
    prefix = audit_report + top
    if len(prefix) + len(report) + 20 <= 4000:
        say(prefix + "\nRELATÓRIO ORIGINAL:\n" + report)
    else:
        say(prefix + "\nEXCERTO DO RELATÓRIO:\n" + report[:1300] +
            "\n\nO relatório completo segue como ficheiro privado, "
            "sem cortes nem alterações.")
        name = "codex-relatorio-" + (issue or "execucao") + (
            "-worker-" + worker if worker else ""
        ) + ".txt"
        # Audited above, and the original *bytes* are attached unchanged.
        telegram("sendDocument", {
            "chat_id": CHAT_ID,
            "caption": "Relatório original integral, conferido pelo Supervisor",
        }, document=(name, raw_report))
    print("TELEGRAM_NOTIFY=SENT")



if __name__ == "__main__":
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "notify":
            notify()
        else:
            raise RuntimeError("Usage: telegram_gateway.py notify")
    except RuntimeError as exc:
        print("SUPERVISOR_TELEGRAM_ERROR=" + str(exc), file=sys.stderr)
        sys.exit(1)
