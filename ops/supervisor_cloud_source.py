#!/usr/bin/env python3
"""GitHub read-only Cloud evidence adapter for the *existing* passive Supervisor.

This is NOT a second Supervisor and never runs, routes or approves Cloud work.
Only public, fixed-repository PR/CI metadata can reach the private notifier.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CLOUD_REPOSITORY = "martaxi-boss/Project-leader-codex"
PARENT_REPOSITORY = "martaxi-boss/VPS"
WORKFLOW = "Existing passive Supervisor - Cloud GitHub evidence"
PULLS_PATH = "pulls?state=all&sort=updated&direction=desc&per_page=8"
CHECKS_PATH = re.compile(r"commits/[0-9a-f]{40}/check-runs\?per_page=50\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid GitHub timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timezone required")
    return parsed.astimezone(timezone.utc)


def last_observed_start(vps_get, now: datetime) -> datetime:
    """Last successful observer run is the read-only cursor.

    Failed previous polls are deliberately excluded so events can be recovered.
    On initial activation inspect only the recent past, never the full history.
    """
    result = vps_get(
        "GET",
        "actions/workflows/cloud-supervisor-observation.yml/runs?"
        "status=success&per_page=50",
    )
    if not isinstance(result, dict) or not isinstance(result.get("workflow_runs"), list):
        raise RuntimeError("Supervisor GitHub observation history unavailable")
    candidates = []
    for run in result["workflow_runs"][:50]:
        if not isinstance(run, dict):
            continue
        if (run.get("name") != WORKFLOW
                or run.get("event") not in ("schedule", "workflow_dispatch",
                                            "push", "workflow_run")
                or run.get("conclusion") != "success"
                or run.get("status") != "completed"):
            continue
        try:
            created = _time(run.get("created_at"))
        except (ValueError, TypeError):
            continue
        if now - timedelta(days=7) <= created < now:
            candidates.append(created)
    return max(candidates) if candidates else now - timedelta(hours=6)


def cloud_get(token: str, path: str) -> object:
    """Only GET two fixed public GitHub endpoint shapes; never forward URLs/data."""
    if (not isinstance(token, str) or not token or len(token) > 1024
            or path != PULLS_PATH and CHECKS_PATH.fullmatch(path) is None):
        raise RuntimeError("Untrusted Cloud observation request")
    url = "https://api.github.com/repos/" + CLOUD_REPOSITORY + "/" + path
    req = Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Project-Leader-Passive-Cloud-Observer",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=20) as response:
            raw = response.read(500001)
            if len(raw) > 500000:
                raise RuntimeError("Cloud evidence exceeded limit")
            return json.loads(raw.decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Verified Cloud GitHub observation unavailable") from None


def _owner_pr(pr: object) -> bool:
    """PR body/title are untrusted and intentionally never used as instructions."""
    return (isinstance(pr, dict)
            and type(pr.get("number")) is int and 0 < pr["number"] < 10**9
            and pr.get("state") in ("open", "closed")
            and (pr.get("user") or {}).get("login") == "martaxi-boss"
            and (pr.get("base") or {}).get("ref") == "main"
            and ((pr.get("base") or {}).get("repo") or {}).get("full_name")
                == CLOUD_REPOSITORY
            and ((pr.get("head") or {}).get("repo") or {}).get("full_name")
                == CLOUD_REPOSITORY
            and type((pr.get("head") or {}).get("sha")) is str
            and SHA.fullmatch(pr["head"]["sha"]) is not None)


def _checks_summary(rows: list[dict]) -> str:
    if not rows:
        return "CI ainda sem verificações observadas"
    total = len(rows)
    passed = sum(x.get("status") == "completed" and
                 x.get("conclusion") == "success" for x in rows)
    failures = sum(x.get("status") == "completed" and
                   x.get("conclusion") in ("failure", "cancelled", "timed_out",
                                          "action_required") for x in rows)
    if failures:
        return f"CI: {failures} verificação(ões) com falha/atenção; {passed}/{total} passaram"
    if passed == total:
        return f"CI: {passed}/{total} verificações concluídas com sucesso"
    return f"CI: {passed}/{total} verificações aprovadas; ainda não certificada"


def messages(cloud_read, since: datetime, now: datetime,
             *, limit: int = 5) -> list[str]:
    """Only authenticated owner PR identifiers, fixed links and bounded CI facts."""
    if type(limit) is not int or not 1 <= limit <= 5:
        raise ValueError("Cloud report limit outside trusted bounds")
    prs = cloud_read(PULLS_PATH)
    if not isinstance(prs, list):
        raise RuntimeError("Cloud PR listing unavailable")
    output = []
    for pr in prs[:8]:
        if not _owner_pr(pr):
            continue
        try:
            updated = _time(pr.get("updated_at"))
            created = _time(pr.get("created_at"))
        except (ValueError, TypeError):
            continue
        if updated > now + timedelta(minutes=3):
            continue
        recent_pr = since < updated <= now
        # Also catch CI completion after the PR was last updated.
        if not recent_pr and (pr["state"] != "open"
                              or updated < now - timedelta(days=2)):
            continue
        head = pr["head"]["sha"]
        checks = cloud_read(f"commits/{head}/check-runs?per_page=50")
        if not isinstance(checks, dict) or not isinstance(checks.get("check_runs"), list):
            raise RuntimeError("Cloud CI evidence unavailable")
        rows = checks["check_runs"][:50]
        valid = [x for x in rows if isinstance(x, dict)
                 and x.get("status") in ("queued", "in_progress", "completed")]
        ci_finished = any(
            x.get("status") == "completed"
            and x.get("completed_at") is not None
            and since < _time(x["completed_at"]) <= now
            for x in valid if x.get("completed_at") is not None
        )
        if not recent_pr and not ci_finished:
            continue
        status = ("integrada" if pr.get("merged_at") else
                  "fechada, não integrada" if pr["state"] == "closed" else
                  "rascunho, sem merge" if pr.get("draft") is True else
                  "aberta, sem merge")
        event = ("PR criada" if since < created <= now else
                 "PR atualizada" if recent_pr else "CI atualizada")
        number = pr["number"]
        message = (
            f"👁️ Supervisor: Codex Cloud — {event} #{number}.\n"
            f"Estado GitHub: {status}. {_checks_summary(valid)}.\n"
            f"Head verificado: {head[:12]}.\n"
            f"https://github.com/{CLOUD_REPOSITORY}/pull/{number}\n"
            "Observação GitHub; não certifica execução privada nem paralelismo."
        )
        output.append(message)
        if len(output) == limit:
            break
    return output
