#!/usr/bin/env python3
"""Passive live observer for the existing Project Leader + Codex pipeline.

Only reads trusted GitHub state and forwards factual summaries to the already
configured private Telegram destination. Never dispatches, merges, retries,
classifies Human Gates, reads private model reports, or orders workers.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import unicodedata

OWNER = "martaxi-boss"
REPOSITORY = OWNER + "/VPS"
ORDER_PREFIXES = ("[coordinator run] ", "[agents run]", "[codex run]")
BOT_USERS = {"github-actions[bot]", "github-actions"}
WORKFLOWS = {
    "Coordinator to existing Codex router (Owner order)": "Coordenador",
    "Agent switch (Owner GitHub order)": "Trabalhadores Codex",
    "Continue original Owner DAG (no repeated Coordinator AI)": "Continuação das fases",
    "Codex autonomous execution (Owner-authorized)": "Trabalhador Codex",
    "Supervisor - Real ChatGPT quota watch (Owner notifications only)": "Vigilância da quota real",
    "Codex - ChatGPT bridge": "Ponte Codex",
}
OUTCOMES = {
    "success": "concluído com sucesso",
    "failure": "falhou",
    "cancelled": "cancelado",
    "timed_out": "tempo limite atingido",
    "action_required": "ação externa necessária",
    "skipped": "ignorado",
}
WORKER_STATES = {
    "MERGED", "NO_CHANGE", "PR_STAGED", "PR_NEEDS_ATTENTION",
    "NO_CHANGE_UNVERIFIED", "NOT_STARTED", "NOT_COMPLETED", "FAILED",
    "PAUSED_QUOTA", "QUOTA_UNVERIFIED",
}
RUN_LINK = re.compile(r"https://github\.com/martaxi-boss/VPS/actions/runs/([1-9][0-9]{0,15})")


def _plain(value: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", value.lower())
                   if not unicodedata.combining(ch))


def parse_request(text: str) -> int | None:
    """Return 0 for live overview, issue id for targeted read, None otherwise."""
    if not isinstance(text, str) or len(text) > 300:
        return None
    plain = " ".join(_plain(text).strip().split())
    command = re.fullmatch(
        r"/(?:supervisor|vigia|estado)(?:@\w+)?"
        r"(?:\s+(?:tarefa\s+)?#?([1-9][0-9]{0,8}))?", plain)
    if command:
        return int(command.group(1)) if command.group(1) else 0
    if not re.match(r"^(?:supervisor|vigia)(?:[,:;.!?\s]|$)", plain):
        return None
    if re.search(r"\b(?:executa|executar|corrige|corrigir|manda|apaga|"
                 r"reinicia|instala|altera|autoriza|aprova|desbloqueia)\b", plain):
        return None
    number = re.search(r"(?:#|\btarefa\s+)([1-9][0-9]{0,8})\b", plain)
    if number:
        return int(number.group(1))
    if re.search(r"\b(?:estado|como|fase|fases|erros?|falhas?|"
                 r"trabalhador(?:es)?|codex|projetos?|projectos?|"
                 r"trabalhos?|ordens?|andam|andamento|progresso|"
                 r"pendente|supervisao|situacao|noticias|ai)\b", plain) or plain in ("supervisor", "vigia"):
        return 0
    return None


def is_addressed_to_supervisor(text: str) -> bool:
    """Fail closed on commands addressed to this observer, even by voice."""
    if not isinstance(text, str):
        return False
    plain = _plain(text.strip())
    return bool(re.match(r"^(?:/(?:supervisor|vigia|estado)|(?:supervisor|vigia))"
                         r"(?:[,:;.!?\s]|$)", plain))


def _get(gh, path: str):
    """Deliberately no POST/PUT/DELETE or direct network client."""
    return gh("GET", path)


def _owner_order(issue: object) -> bool:
    return (isinstance(issue, dict) and not issue.get("pull_request")
            and (issue.get("user") or {}).get("login") == OWNER
            and any(str(issue.get("title", "")).startswith(p)
                    for p in ORDER_PREFIXES)
            and type(issue.get("number")) is int
            and 0 < issue["number"] < 10**9)


def _comments(gh, number: int) -> list[dict]:
    rows = _get(gh, f"issues/{number}/comments?per_page=100")
    if not isinstance(rows, list):
        raise RuntimeError("Não foi possível consultar o histórico da tarefa")
    return [r for r in rows if isinstance(r, dict)
            and (r.get("user") or {}).get("login") in BOT_USERS]


def _progress(rows: list[dict]) -> tuple[str, int | None, int | None]:
    """Only fixed public, bot-authored markers, never model text or Human Gates."""
    state = "sem resultado certificado"
    phases = None
    run = None
    for comment in rows:
        body = str(comment.get("body") or "")[:8000]
        link = RUN_LINK.search(body)
        if link:
            run = int(link.group(1))
        if body.startswith("COORDINATOR_NOT_CERTIFIED:"):
            state = "planeamento não certificado"
        if body.startswith("COORDINATOR_VERIFIED:"):
            found = re.search(r"\bphases ([1-8])\.", body[:300])
            if found:
                phases = int(found.group(1))
            state = "plano validado; execução a acompanhar"
        if body.startswith("Bounded Codex order validated;"):
            state = "trabalhadores encaminhados"
        if body.startswith("PROJECT_LEADER_PHASE_PARTIAL:"):
            state = "fase integrada; restantes em acompanhamento"
        if body.startswith("PROJECT_LEADER_TERMINAL_SUCCESS:"):
            state = "trabalho integrado e terminado"
        match = re.match(r"## Codex execution: ([A-Z_]+)(?:\n|$)", body)
        if match and match.group(1) in WORKER_STATES:
            state = {
                "MERGED": "alterações integradas",
                "NO_CHANGE": "trabalho concluído sem alterações",
                "PR_STAGED": "PR preparada; integração pendente",
                "NOT_STARTED": "trabalhador não iniciado",
                "NOT_COMPLETED": "execução não concluída",
                "FAILED": "execução falhou",
                "PAUSED_QUOTA": "quota real atingida; aguardando decisão do Owner",
                "QUOTA_UNVERIFIED": "quota real não verificada; execução protegida",
            }.get(match.group(1), "validação ou revisão pendente")
    return state, phases, run


def _jobs(gh, run: int) -> str:
    payload = _get(gh, f"actions/runs/{run}/jobs?per_page=100")
    jobs = payload.get("jobs", []) if isinstance(payload, dict) else []
    if not isinstance(jobs, list):
        raise RuntimeError("Resposta de jobs inválida")
    active = [j for j in jobs if isinstance(j, dict)
              and j.get("status") in ("in_progress", "queued", "pending", "waiting")]
    if not active:
        return "Etapas GitHub: nenhuma ativa nesta execução."
    safe = []
    for job in active[:4]:
        name = str(job.get("name") or "etapa")[:90]
        name = re.sub(r"[^A-Za-zÀ-ÿ0-9 /_():.-]", "", name)
        safe.append(name)
    return "Etapas GitHub em curso: " + "; ".join(safe)


def _issue_line(gh, issue: dict, detail: bool = False) -> str:
    number = issue["number"]
    state, phases, run = _progress(_comments(gh, number))
    phase_info = f"; plano de {phases} fase(s)" if phases else ""
    result = f"Tarefa #{number}: {state}{phase_info}."
    if detail:
        result += "\n" + ("GitHub: " + str(issue.get("state", "desconhecido")) + ".")
        if run is not None:
            result += "\n" + _jobs(gh, run)
            result += f"\nhttps://github.com/{REPOSITORY}/actions/runs/{run}"
        result += ("\nHuman Gates e relatórios privados: tratados nas mensagens "
                   "privadas do trabalhador; esta consulta não certifica pendências.")
    return result + f"\nhttps://github.com/{REPOSITORY}/issues/{number}"


def _runs(gh, status: str) -> list[dict]:
    payload = _get(gh, f"actions/runs?status={status}&per_page=100")
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise RuntimeError("Estado GitHub Actions não disponível")
    return [r for r in payload["workflow_runs"] if isinstance(r, dict)
            and r.get("name") in WORKFLOWS
            and r.get("status") == status]


def overview(gh) -> str:
    running = _runs(gh, "in_progress")
    queued = _runs(gh, "queued")
    lines = ["👁️ SUPERVISOR — estado observado no GitHub",
             f"Execuções da cadeia em curso: {len(running)}; em fila: {len(queued)}."]
    for run in (running + queued)[:6]:
        ident = run.get("id")
        if type(ident) is not int or ident < 1:
            continue
        lines.append(f"• {WORKFLOWS[run['name']]} — "
                     f"{'em execução' if run['status'] == 'in_progress' else 'em fila'} "
                     f"https://github.com/{REPOSITORY}/actions/runs/{ident}")
    issues = _get(gh, "issues?state=all&per_page=100&sort=updated&direction=desc")
    if not isinstance(issues, list):
        raise RuntimeError("Tarefas do proprietário indisponíveis")
    selected = [v for v in issues if _owner_order(v)][:3]
    if selected:
        lines.append("Últimas ordens do proprietário:")
        lines.extend(_issue_line(gh, v) for v in selected)
    else:
        lines.append("Sem ordens recentes reconhecidas na amostra consultada.")
    lines.append("Observação apenas de leitura; nenhuma ordem ou reinício efetuado.")
    return "\n".join(lines)[:3350]


def task_status(gh, number: int) -> str:
    if type(number) is not int or not 0 < number < 10**9:
        raise RuntimeError("Número de tarefa inválido")
    issue = _get(gh, f"issues/{number}")
    if not _owner_order(issue):
        return "Não existe uma ordem autenticada do proprietário com esse número."
    return "👁️ SUPERVISOR — tarefa consultada\n" + _issue_line(gh, issue, detail=True)


def observe_event(gh, send, event_name: str, payload: object) -> bool:
    """Notify only from authenticated GitHub metadata, never untrusted text."""
    if not isinstance(payload, dict):
        return False
    if event_name == "issues":
        issue = payload.get("issue")
        if payload.get("action") != "opened" or not _owner_order(issue):
            return False
        actual = _get(gh, f"issues/{issue['number']}")
        if not _owner_order(actual) or actual.get("id") != issue.get("id"):
            return False
        send(f"👁️ Supervisor: ordem #{issue['number']} recebida. "
             "Vou acompanhar o Coordenador e a execução. "
             f"https://github.com/{REPOSITORY}/issues/{issue['number']}")
        return True
    if event_name != "workflow_run" or payload.get("action") not in {
        "requested", "in_progress", "completed"
    }:
        return False
    run = payload.get("workflow_run")
    if not isinstance(run, dict) or run.get("name") not in WORKFLOWS:
        return False
    ident = run.get("id")
    if type(ident) is not int or not 0 < ident < 10**16:
        return False
    actual = _get(gh, f"actions/runs/{ident}")
    if (not isinstance(actual, dict) or actual.get("id") != ident or
            actual.get("name") != run["name"] or
            actual.get("event") in ("pull_request", "pull_request_target") or
            (actual.get("repository") or {}).get("full_name") != REPOSITORY):
        return False
    action = payload["action"]
    # A delayed event must not be presented as live when the run has already
    # moved to a later state. Later events will give the current evidence.
    if action == "requested" and actual.get("status") == "queued":
        send(f"👁️ Supervisor: {WORKFLOWS[run['name']]} — trabalho em fila.\n"
             f"https://github.com/{REPOSITORY}/actions/runs/{ident}")
        return True
    if action == "in_progress" and actual.get("status") == "in_progress":
        send(f"👁️ Supervisor: {WORKFLOWS[run['name']]} — execução iniciada.\n"
             f"https://github.com/{REPOSITORY}/actions/runs/{ident}")
        return True
    if (action != "completed" or actual.get("status") != "completed"
            or actual.get("conclusion") not in OUTCOMES):
        return False
    conclusion = actual["conclusion"]
    # Existing autonomous workers already send a detailed final Telegram notice.
    # Their failures/cancellations still get a separate high-level watcher alert.
    if conclusion == "success" and run["name"] in {
        "Codex autonomous execution (Owner-authorized)",
        "Supervisor - Real ChatGPT quota watch (Owner notifications only)",
        "Codex - ChatGPT bridge",
    }:
        # Successful worker / audit / hourly quota scan have their own
        # reporting paths. Do not generate a repetitive success notice.
        return False
    send(f"👁️ Supervisor: {WORKFLOWS[run['name']]} — "
         f"{OUTCOMES[conclusion]}.\n"
         f"https://github.com/{REPOSITORY}/actions/runs/{ident}\n"
         "Observação de estado; sem ordens aos trabalhadores.")
    return True


def notify_plan(gh, send, number: int, run: int, outcome: str,
                phase_count: str) -> bool:
    """One-time Coordinator milestone; validated fact, not a new plan."""
    if (type(number) is not int or not 0 < number < 10**9 or
            type(run) is not int or not 0 < run < 10**16 or
            outcome not in {"success", "failure", "skipped", "cancelled"}):
        return False
    issue = _get(gh, f"issues/{number}")
    if not _owner_order(issue) or not issue["title"].startswith("[coordinator run] "):
        return False
    if outcome == "success":
        if phase_count not in {str(i) for i in range(1, 9)}:
            return False
        description = (f"Coordenador validou o plano de {phase_count} fase(s). "
                       "A execução prossegue pelos trabalhadores com Project Leader.")
    else:
        description = "Planeamento do Coordenador não certificado; não foi autorizado avanço por esta etapa."
    send(f"👁️ Supervisor: tarefa #{number}. {description}\n"
         f"https://github.com/{REPOSITORY}/actions/runs/{run}")
    return True


def notify_phase(gh, send, number: int, run: int, phase: int,
                 outcome: str) -> bool:
    """Report a scheduled phase; never schedule, approve, or resume work."""
    if (type(number) is not int or not 0 < number < 10**9 or
            type(run) is not int or not 0 < run < 10**16 or
            type(phase) is not int or not 2 <= phase <= 8 or
            outcome not in {"success", "failure", "skipped", "cancelled"}):
        return False
    issue = _get(gh, f"issues/{number}")
    if not _owner_order(issue) or not issue["title"].startswith("[coordinator run] "):
        return False
    if outcome == "success":
        message = f"Fase {phase} do plano original preparada e validada; trabalhadores seguem o Project Leader."
    else:
        message = f"Fase {phase} não foi validada ou não iniciou; consultar a execução."
    send(f"👁️ Supervisor: tarefa #{number}. {message}\n"
         f"https://github.com/{REPOSITORY}/actions/runs/{run}")
    return True



def _private_sender(gateway, message: str, *, source: str = "event") -> None:
    """Audit authenticated observations before using the existing bot."""
    if (not gateway.BOT_TOKEN or
            not re.fullmatch(r"[1-9][0-9]{3,17}", gateway.CHAT_ID or "")):
        raise RuntimeError("Existing private Telegram destination not configured")
    from ops import supervisor_audit
    gateway.say(supervisor_audit.observation(message, source=source))


def main(argv: list[str]) -> int:
    if argv == ["cloud"]:
        # Same passive observer and private Telegram transport, called by its
        # read-only GitHub Actions trigger; no worker/Coordinator dispatch.
        event = os.environ.get("GITHUB_EVENT_NAME", "")
        if (os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
                or event not in ("schedule", "workflow_dispatch",
                                 "push", "workflow_run")
                or event == "push"
                and os.environ.get("GITHUB_REF") != "refs/heads/main"):
            return 2
        from datetime import datetime, timezone
        from ops import supervisor_cloud_source as cloud
        from ops import telegram_gateway as gateway
        stage = "CHECKPOINT"
        try:
            now = datetime.now(timezone.utc)
            since = cloud.last_observed_start(gateway.github, now)
            stage = "CLOUD_READ"
            notices = cloud.messages(
                lambda path: cloud.cloud_get(gateway.GH_TOKEN, path),
                since, now, limit=1 if event == "push" else 5)
            stage = "TELEGRAM"
            for message in notices:
                _private_sender(gateway, message, source="cloud")
            outcome = "FORWARDED" if notices else "NO_CHANGE"
            print(f"SUPERVISOR_CLOUD={outcome}; COUNT={len(notices)}")
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
            # Never print an exception's raw text or private token/chat ID.
            # A fixed pipeline stage and numeric HTTP status suffice for recovery.
            match = re.search(r"\bHTTP ([1-5][0-9]{2})\b", str(exc))
            category = "HTTP_" + match.group(1) if match else type(exc).__name__
            print("SUPERVISOR_CLOUD=OBSERVATION_FAILED:" + stage + ":" +
                  category, file=sys.stderr)
            return 1
    if argv == ["plan"]:
        from ops import telegram_gateway as gateway
        try:
            number = int(os.environ.get("SUPERVISOR_PLAN_ISSUE", ""))
            run = int(os.environ.get("GITHUB_RUN_ID", ""))
            if (os.environ.get("GITHUB_EVENT_NAME") != "issues" or
                    os.environ.get("GITHUB_REPOSITORY") != REPOSITORY):
                return 2
            result = notify_plan(
                gateway.github, lambda m: _private_sender(gateway, m, source="coordinator"), number, run,
                os.environ.get("SUPERVISOR_PLAN_OUTCOME", ""),
                os.environ.get("SUPERVISOR_PLAN_PHASE_COUNT", ""))
            print("SUPERVISOR_COORDINATOR=" + ("FORWARDED" if result else "IGNORED"))
            return 0 if result else 2
        except (ValueError, RuntimeError, OSError):
            print("SUPERVISOR_COORDINATOR=OBSERVATION_FAILED", file=sys.stderr)
            return 1
    if argv == ["phase"]:
        from ops import telegram_gateway as gateway
        try:
            number = int(os.environ.get("SUPERVISOR_PLAN_ISSUE", ""))
            run = int(os.environ.get("GITHUB_RUN_ID", ""))
            phase = int(os.environ.get("SUPERVISOR_PHASE_NUMBER", ""))
            if (os.environ.get("GITHUB_EVENT_NAME") != "issues" or
                    os.environ.get("GITHUB_REPOSITORY") != REPOSITORY):
                return 2
            result = notify_phase(
                gateway.github, lambda m: _private_sender(gateway, m, source="phase"), number, run, phase,
                os.environ.get("SUPERVISOR_PLAN_OUTCOME", ""))
            print("SUPERVISOR_PHASE=" + ("FORWARDED" if result else "IGNORED"))
            return 0 if result else 2
        except (ValueError, RuntimeError, OSError):
            print("SUPERVISOR_PHASE=OBSERVATION_FAILED", file=sys.stderr)
            return 1
    if argv != ["watch"]:
        return 2
    from ops import telegram_gateway as gateway
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    try:
        if event_name in ("issues", "workflow_run"):
            data = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
            result = observe_event(gateway.github, lambda m: _private_sender(gateway, m, source="event"), event_name, data)
            print("SUPERVISOR_EVENT=" + ("FORWARDED" if result else "IGNORED"))
        elif event_name in ("schedule", "workflow_dispatch"):
            if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
                return 2
            running = _runs(gateway.github, "in_progress")
            queued = _runs(gateway.github, "queued")
            print(f"SUPERVISOR_HEARTBEAT=READ_ONLY; ACTIVE={len(running)}; QUEUED={len(queued)}")
            # Extend this SAME Supervisor with read-only evidence from the
            # public Codex Cloud repository. No workers, models or new bot.
            from datetime import datetime, timezone
            from ops import supervisor_cloud_source as cloud
            now = datetime.now(timezone.utc)
            since = cloud.last_observed_start(gateway.github, now)
            notices = cloud.messages(
                lambda path: cloud.cloud_get(gateway.GH_TOKEN, path), since, now)
            for message in notices:
                _private_sender(gateway, message, source="cloud")
            print("SUPERVISOR_CLOUD=FORWARDED; COUNT=" + str(len(notices)))
        else:
            print("SUPERVISOR_EVENT=NOT_APPLICABLE")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print("SUPERVISOR_OBSERVATION_FAILED=" + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
