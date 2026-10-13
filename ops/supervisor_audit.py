#!/usr/bin/env python3
"""Factual, read-only Supervisor audit of information sent to the Owner.

Runs inside existing GitHub Actions/Telegram transports; no AI, dispatch,
merge, Human Gate decision, retry or new credential/service.
"""
from __future__ import annotations

import hashlib
import re

_REPO = "martaxi-boss/VPS"
_RUN = re.compile(r"^https://github\.com/martaxi-boss/VPS/actions/runs/[1-9][0-9]{0,15}$")
_ISSUE = re.compile(r"^[1-9][0-9]{0,8}$")
_WORKER = re.compile(r"^(?:[12]|p[2-8]-[12])?$")
_OUTCOMES = {"success", "failure", "cancelled", "skipped"}
_STAGES = ("PREFLIGHT_OUTCOME", "STAGE_OUTCOME", "CODEX_OUTCOME",
           "COLLECT_OUTCOME", "ARTIFACTS_OUTCOME", "PUBLISH_OUTCOME")
_FINAL = {
    "MERGED": "alterações integradas segundo a publicação verificada",
    "NO_CHANGE": "sem alterações reportadas",
    "PR_STAGED": "PR preparada; integração ainda pendente",
    "PR_NEEDS_ATTENTION": "publicação pendente de revisão",
    "NO_CHANGE_UNVERIFIED": "ausência de alterações ainda não certificada",
    "NOT_STARTED": "execução não iniciada",
    "NOT_COMPLETED": "execução ainda não certificada",
    "FAILED": "falha de execução reportada",
}


def check_delivery(message: str) -> str:
    """One common egress contract for every Telegram text delivery.

    Private-chat authentication takes place before Owner input processing.
    This validation never edits, summarizes or acts on private model content.
    """
    if type(message) is not str or not message.strip():
        raise RuntimeError("Supervisor refused an empty outgoing message")
    if any(ord(char) in range(0, 9) or ord(char) in range(11, 32)
           for char in message):
        raise RuntimeError("Supervisor refused control bytes in outgoing message")
    if len(message) > 4000:
        raise RuntimeError("Supervisor refused truncated outgoing message")
    return message


def _provenance(issue: str, run_url: str) -> str:
    if _ISSUE.fullmatch(issue or "") and _RUN.fullmatch(run_url or ""):
        return f"Tarefa #{issue}; execução GitHub {run_url}"
    return "Proveniência não verificada no contexto desta mensagem"


def _worker_name(worker: str) -> str:
    if not _WORKER.fullmatch(worker or ""):
        raise RuntimeError("Supervisor refused untrusted worker identity")
    if worker.startswith("p"):
        return "Codex fase " + worker[1] + ", trabalhador " + worker[-1]
    return "Codex " + worker if worker else "Codex (identidade não indicada)"


def worker_report(*, issue: str, run_url: str, worker: str,
                  status: str, report: str) -> str:
    """Audit the *receipt*, length and hash; never decide worker Human Gates."""
    if (type(report) is not str or not report.strip() or
            len(report.encode("utf-8")) > 65536):
        raise RuntimeError("Supervisor cannot certify an absent or oversized report")
    name = _worker_name(worker)
    checksum = hashlib.sha256(report.encode("utf-8")).hexdigest()
    result = ("relatório recebido, ainda sem certificação final do pipeline"
              if status == "WORKER_REPORT_RECEIVED"
              else "estado comunicado pelo trabalhador; verificar resultado do pipeline")
    return (
        "👁️ SUPERVISOR — AUDITORIA DO RELATÓRIO\n"
        f"Origem: {name}, Project Leader do trabalhador.\n"
        f"Referência: {_provenance(issue, run_url)}\n"
        "Verificação: conteúdo privado recebido e íntegro nesta entrega; "
        f"{len(report.encode('utf-8'))} bytes; SHA-256 {checksum[:16]}…\n"
        f"Conclusão verificada: {result}.\n"
        "Human Gate: a decisão e o texto pertencem exclusivamente ao "
        "Project Leader original; o Supervisor não os altera nem os valida.\n"
        "RELATÓRIO ORIGINAL: reproduzido abaixo ou enviado integralmente em ficheiro.\n\n"
    )


def pipeline(*, issue: str, run_url: str, worker: str, status: str,
             steps: dict[str, str]) -> str:
    """Audit trusted CI step outcomes without reading the model's private text."""
    name = _worker_name(worker)
    if status not in _FINAL:
        # Existing direct tests also call notify with nonterminal shorthand.
        description = "estado ainda sem conclusão certificada"
    else:
        description = _FINAL[status]
    valid = {key: steps[key] for key in _STAGES if steps.get(key) in _OUTCOMES}
    failing = [key for key, value in valid.items()
               if value in ("failure", "cancelled")]
    mismatch = (status in ("MERGED", "NO_CHANGE") and bool(failing))
    if mismatch:
        conclusion = ("INCONSISTÊNCIA: estado declarado como concluído, "
                      "mas existem etapas com falha/cancelamento; não certificar sucesso.")
    elif failing or status in ("NOT_STARTED", "NOT_COMPLETED", "FAILED",
                               "PR_NEEDS_ATTENTION", "NO_CHANGE_UNVERIFIED"):
        conclusion = "ATENÇÃO: trabalho não certificado como concluído."
    elif status == "PR_STAGED":
        conclusion = "PR ainda não integrada; não apresentar como finalizado."
    elif status in ("MERGED", "NO_CHANGE"):
        conclusion = "Estado final comunicado pela publicação; consultar prova no GitHub."
    else:
        conclusion = "Resultado a verificar na execução original."
    return (
        "👁️ SUPERVISOR — AUDITORIA DO RESULTADO\n"
        f"Origem: {name}; etapa de publicação/CI.\n"
        f"Referência: {_provenance(issue, run_url)}\n"
        f"Estado recebido: {status}; {description}.\n"
        f"Etapas autenticadas: {len(valid)}; com falha/cancelamento: {len(failing)}.\n"
        f"Conclusão da auditoria: {conclusion}\n"
        "Intervenção do Owner: só quando o Project Leader original "
        "declarar um Human Gate ou houver decisão material a tomar.\n\n"
    )


def observation(message: str, *, source: str) -> str:
    """Audit already-authenticated owner-event/coordinator/phase observations."""
    if source not in {"event", "coordinator", "phase", "owner_query"}:
        raise RuntimeError("Supervisor rejected unknown observation source")
    original = check_delivery(message)
    if source != "owner_query" and (
            "https://github.com/martaxi-boss/VPS/" not in original or
            "\n" in original and len(original) > 1200):
        raise RuntimeError("Supervisor refused unauthenticated event reference")
    attention = any(item in original.casefold() for item in
                    ("falhou", "não certificado", "nao certificado",
                     "não foi validada", "não foi validado", "cancelado"))
    nature = {
        "event": "GitHub, evento validado pelo observador",
        "coordinator": "Coordenador, resultado validado da fase de planeamento",
        "phase": "Fase do plano original, transição autenticada",
        "owner_query": "Consulta privada autorizada, estado obtido do GitHub",
    }[source]
    verdict = ("Atenção: ocorrência/limite comunicado, consultar a referência."
               if attention else
               "Informação de estado recebida; não equivale a autorização ou conclusão adicional.")
    header = (
        "👁️ SUPERVISOR — AUDITORIA OPERACIONAL\n"
        f"Origem verificada: {nature}.\n"
        f"Verificação: {verdict}\n"
        "Ação do Supervisor: informar o Owner; nenhuma ordem aos trabalhadores.\n\n"
    )
    return check_delivery(header + original)
