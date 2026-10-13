"""Transport for true Project Leader Human Gates, NOT a new gate policy.

The canonical Project Leader skill alone decides if Owner intervention is
indispensable. This is an unprivileged, deterministic message/authorization
protocol. Public GitHub state stores only digests and bounded identity metadata;
the actual request is delivered to the already configured private Telegram.
"""
from __future__ import annotations

import hashlib
import json
import re

HEADER = "PROJECT_LEADER_HUMAN_GATE_V1"
PENDING = "PROJECT_LEADER_GATE_TICKET_V1"
RESPONSE = "PROJECT_LEADER_GATE_RESPONSE_V1"
DISPATCH = "PROJECT_LEADER_GATE_DISPATCH_V1"
CONDITIONS = frozenset({
    "EXCLUSIVE_HUMAN_INTERVENTION",
    "NEW_UNCOVERED_MATERIAL_DECISION",
})
SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENTITY = re.compile(r"(?:1|2|p[2-8]-[12])?\Z")
TICKET = re.compile(r"hg-[0-9a-f]{24}\Z")
ISSUE = re.compile(r"[1-9][0-9]{0,15}\Z")
JOB = re.compile(r"[1-9][0-9]{5,15}-[1-9][0-9]*(?:-(?:[12]|p[2-8]-[12]))?\Z")
OBVIOUS_SECRET = re.compile(
    r"(?i)(?:-----BEGIN .*PRIVATE KEY-----|"
    r"\b(?:password|senha|token|api.key|otp|c[oó]digo de recupera[cç][aã]o)"
    r"\s*[:=]\s*\S{6,}|gh[pousr]_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9_-]{12,})"
)


class HumanGateError(ValueError):
    pass


def parse_report(raw: str) -> dict | None:
    """Return a gate only for an explicit, strictly bounded model signal.

    No free-text mentions of 'Human Gate' can trigger an authorization.
    Malformed explicit gate markers fail closed rather than publishing a PR.
    """
    if not isinstance(raw, str):
        raise HumanGateError("Malformed Codex report")
    if not raw.startswith(HEADER):
        return None
    if not 35 <= len(raw.encode("utf-8")) <= 3200:
        raise HumanGateError("Invalid gate request size")
    lines = raw.strip().splitlines()
    if len(lines) != 2 or lines[0] != HEADER:
        raise HumanGateError("Gate must be a strict two-line event")
    try:
        body = json.loads(lines[1])
    except ValueError:
        raise HumanGateError("Gate payload invalid") from None
    if (not isinstance(body, dict) or
            set(body) != {"condition", "action", "needed_from_owner"} or
            body["condition"] not in CONDITIONS):
        raise HumanGateError("Gate condition/scope invalid")
    for field, lower, upper in [
        ("action", 12, 220), ("needed_from_owner", 12, 600)
    ]:
        item = body[field]
        if (type(item) is not str or not lower <= len(item) <= upper or
                "\n" in item or "\r" in item or "\x00" in item or
                OBVIOUS_SECRET.search(item)):
            raise HumanGateError("Gate action/instructions unsafe")
    return body


def classify_report(raw: str) -> str:
    return "HUMAN_GATE_PENDING" if parse_report(raw) is not None else "NO_GATE"


def create_ticket(report: str, issue: str, job: str, base_sha: str,
                  worker: str = "") -> dict:
    gate = parse_report(report)
    if gate is None:
        raise HumanGateError("No true Human Gate signal")
    if (not ISSUE.fullmatch(issue) or not JOB.fullmatch(job) or
            not SHA.fullmatch(base_sha) or
            not IDENTITY.fullmatch(worker)):
        raise HumanGateError("Invalid trusted worker/Owner identity")
    if worker and not job.endswith("-" + worker):
        raise HumanGateError("Worker/job identity mismatch")
    report_digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
    scope_digest = hashlib.sha256(json.dumps(
        gate, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")).hexdigest()
    key_material = (issue + "|" + job + "|" + base_sha + "|" +
                    report_digest + "|" + scope_digest)
    gate_id = "hg-" + hashlib.sha256(key_material.encode("ascii")).hexdigest()[:24]
    return {
        "gate_id": gate_id, "issue": int(issue), "job": job,
        "base_sha": base_sha, "report_sha": report_digest,
        "scope_sha": scope_digest, "worker": worker,
        "condition": gate["condition"], "status": "PENDING",
    }


def message(ticket: dict, report: str) -> str:
    gate = parse_report(report)
    if gate is None:
        raise HumanGateError("No true Human Gate")
    return (
        "🔒 PROJECT LEADER — HUMAN GATE\n\n"
        "Tarefa original #" + str(ticket["issue"]) + "\n"
        "Pedido: " + ticket["gate_id"] + "\n"
        "Motivo: " + gate["action"] + "\n"
        "O que depende de ti: " + gate["needed_from_owner"] + "\n\n"
        "Este pedido só diz respeito à ação acima.\n"
        "Depois de resolveres a intervenção pessoal:\n"
        "/gate resolvido " + str(ticket["issue"]) + " " + ticket["gate_id"] + "\n"
        "Para recusar:\n"
        "/gate recusar " + str(ticket["issue"]) + " " + ticket["gate_id"] + "\n\n"
        "Não envies palavras-passe, PINs, tokens ou códigos pelo bot. "
        "As outras tarefas independentes podem continuar."
    )


def entry(prefix: str, payload: dict) -> str:
    return prefix + "\n" + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_entry(body: object, prefix: str) -> dict | None:
    if type(body) is not str or not body.startswith(prefix + "\n"):
        return None
    if len(body) > 1900 or body.count("\n") != 1:
        return None
    try:
        data = json.loads(body.split("\n", 1)[1])
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def trusted_entries(comments: list, prefix: str) -> list[dict]:
    if type(comments) is not list or len(comments) > 100:
        raise HumanGateError("Unbounded gate journal")
    result = []
    for record in comments:
        if not isinstance(record, dict):
            continue
        user = (record.get("user") or {}).get("login")
        if user not in ("github-actions[bot]", "github-actions"):
            continue
        parsed = parse_entry(record.get("body"), prefix)
        if parsed is not None:
            result.append(parsed)
    return result


def pending_ticket(comments: list, ticket_id: str, issue: int) -> dict:
    if not TICKET.fullmatch(ticket_id) or type(issue) is not int or issue <= 0:
        raise HumanGateError("Invalid scoped gate reference")
    pending = [
        p for p in trusted_entries(comments, PENDING)
        if p.get("gate_id") == ticket_id and p.get("issue") == issue
    ]
    if len(pending) != 1:
        raise HumanGateError("Gate not uniquely issued by trusted supervisor")
    t = pending[0]
    if (t.get("status") != "PENDING" or
            not SHA.fullmatch(str(t.get("base_sha", ""))) or
            not SHA.fullmatch(str(t.get("report_sha", ""))) or
            not SHA.fullmatch(str(t.get("scope_sha", ""))) or
            not JOB.fullmatch(str(t.get("job", ""))) or
            not IDENTITY.fullmatch(str(t.get("worker", ""))) or
            t.get("condition") not in CONDITIONS):
        raise HumanGateError("Gate scope/provenance invalid")
    return t


def approved_response(comments: list, ticket_id: str, issue: int) -> dict | None:
    pending_ticket(comments, ticket_id, issue)
    responses = [
        r for r in trusted_entries(comments, RESPONSE)
        if r.get("gate_id") == ticket_id and r.get("issue") == issue
    ]
    if len(responses) > 1:
        raise HumanGateError("Duplicate gate replies; reconciliation required")
    if not responses:
        return None
    response = responses[0]
    if (set(response) != {"gate_id", "issue", "decision", "telegram_update"}
            or response["decision"] not in ("RESOLVED", "REJECTED")
            or type(response["telegram_update"]) is not int
            or response["telegram_update"] <= 0):
        raise HumanGateError("Gate response invalid")
    return response


def parse_telegram_answer(text: str) -> tuple[str, int, str] | None:
    if not isinstance(text, str):
        return None
    found = re.fullmatch(
        r"/gate(?:@\w+)?\s+(resolvido|recusar)\s+"
        r"([1-9][0-9]{0,15})\s+(hg-[0-9a-f]{24})\s*",
        text.strip(), re.IGNORECASE)
    if not found:
        return None
    return ("RESOLVED" if found[1].lower() == "resolvido" else "REJECTED",
            int(found[2]), found[3])
