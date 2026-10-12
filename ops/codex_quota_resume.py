#!/usr/bin/env python3
"""Fail-closed Codex provider-quota detection and authorized stage continuation.

Provider availability is not guessed from the local token ledger. Only fixed,
trusted quota errors from Codex CLI can schedule a later attempt. GitHub Issues
supply durable, bounded checkpoints; no successful stage is replayed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = "martaxi-boss"
REPO = OWNER + "/VPS"
API_ROOT = "https://api.github.com/repos/" + REPO
BOT = "github-actions[bot]"
PAUSE = "<!-- CODEX_QUOTA_PAUSED_V1 -->"
CLAIM = "<!-- CODEX_QUOTA_CLAIM_V1 -->"
LABEL = "codex-quota-paused"
MAX_COMMENTS = 500
MAX_ISSUES = 300
ERROR_CODES = {"insufficient_quota", "usage_limit_reached",
               "quota_exceeded", "usage_limit_exceeded",
               "codex_usage_limit_reached"}
QUOTA_WORDS = re.compile(
    r"\b(?:insufficient[_ -]quota|quota (?:is )?(?:exhausted|exceeded|reached)|"
    r"(?:weekly|daily|account|chatgpt|codex) (?:usage )?limit (?:reached|exceeded)|"
    r"usage limit (?:has been )?(?:reached|exceeded)|"
    r"you(?:'| ha)?ve reached your (?:usage |weekly |daily )?limit|"
    r"you have reached your (?:usage |weekly |daily )?limit|"
    r"usage[_ -]limit[_ -](?:reached|exceeded))\b", re.I,
)


class QuotaResumeError(ValueError):
    pass


def quota_error(jsonl: Path, stderr: Path) -> bool:
    """Classify actual CLI error events only, never model text or plain 429s."""
    if jsonl.is_file() and not jsonl.is_symlink() and jsonl.stat().st_size <= 2_000_000:
        try:
            with jsonl.open("r", encoding="utf-8", errors="replace") as reader:
                for index, line in enumerate(reader):
                    if index >= 5000:
                        break
                    try:
                        event = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(event, dict) or event.get("type") not in ("error", "turn.failed"):
                        continue
                    error = event.get("error")
                    value = error if isinstance(error, dict) else {}
                    code = value.get("code", event.get("code"))
                    msg = value.get("message", event.get("message", ""))
                    if type(code) is str and code.lower() in ERROR_CODES:
                        return True
                    if type(msg) is str and QUOTA_WORDS.search(msg[:1600]):
                        return True
        except OSError:
            pass
    # Stderr is a *secondary* signal, only canonical CLI error lines count.
    if stderr.is_file() and not stderr.is_symlink() and stderr.stat().st_size <= 100_000:
        try:
            for line in stderr.read_text(encoding="utf-8", errors="replace").splitlines()[-150:]:
                if re.match(r"^\s*(?:error|Error|API error|Request failed|codex error)\b", line):
                    if QUOTA_WORDS.search(line[:1600]):
                        return True
        except OSError:
            pass
    return False


def delay_seconds(attempt: int) -> int:
    """Exponential no-spend waiting, max one provider attempt per day."""
    if type(attempt) is not int or not 0 <= attempt <= 1000:
        raise QuotaResumeError("Invalid retry count")
    return min(86400, 7200 * (2 ** min(attempt, 4)))


def _api(method: str, path: str, payload: object = None) -> object:
    token = os.environ.get("GH_TOKEN", "")
    if not token or not re.fullmatch(r"[A-Za-z0-9_!-]{10,512}", token):
        raise QuotaResumeError("GitHub App authentication unavailable")
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        API_ROOT + path, data=body, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            content = response.read(1_000_001)
            if len(content) > 1_000_000:
                raise QuotaResumeError("Unbounded GitHub response")
            return json.loads(content) if content else {}
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
        # An error may include private URL or token details: never propagate it.
        raise QuotaResumeError("GitHub quota checkpoint transport failed") from None


def issue(number: int) -> dict:
    value = _api("GET", "/issues/" + str(number))
    if not isinstance(value, dict) or value.get("number") != number:
        raise QuotaResumeError("Owner issue unavailable")
    if value.get("user", {}).get("login") != OWNER or value.get("state") != "open":
        raise QuotaResumeError("Owner-authored open issue required")
    if not value.get("title", "").startswith("[agents run]"):
        raise QuotaResumeError("Original issue is not a Codex order")
    return value


def comments(number: int) -> list:
    found = []
    for page in range(1, 6):
        query = f"/issues/{number}/comments?per_page=100&page={page}"
        rows = _api("GET", query)
        if not isinstance(rows, list):
            raise QuotaResumeError("Invalid GitHub comments")
        found.extend(rows)
        if len(found) > MAX_COMMENTS:
            raise QuotaResumeError("Too many checkpoint comments")
        if len(rows) < 100:
            break
    return found


def parsed_comments(rows: list, marker: str) -> list:
    result = []
    for item in rows:
        if not isinstance(item, dict) or item.get("user", {}).get("login") != BOT:
            continue
        body = item.get("body")
        if type(body) is not str or not body.startswith(marker + "\n") or len(body) > 1600:
            continue
        try:
            record = json.loads(body[len(marker) + 1:])
        except (ValueError, TypeError):
            continue
        if isinstance(record, dict):
            result.append({**record, "_comment_id": item.get("id")})
    return result


def _order(raw: str) -> dict:
    try:
        from ops import agent_switch
    except ModuleNotFoundError:
        import agent_switch
    return agent_switch.parse_order(raw)


def _valid_stage(order: dict, stage: int) -> bool:
    return type(stage) is int and 1 <= stage <= len(order["tasks"]) <= 2


def _validated_pause(rows: list, run_id: int, stage: int, attempt: int) -> dict:
    checkpoints = parsed_comments(rows, PAUSE)
    matches = [p for p in checkpoints if p.get("run_id") == run_id
               and p.get("stage") == stage and p.get("attempt") == attempt]
    if len(matches) != 1:
        raise QuotaResumeError("Missing unambiguous quota checkpoint")
    p = matches[0]
    if type(p.get("retry_at")) is not int or type(p.get("source_issue")) is not int:
        raise QuotaResumeError("Malformed quota checkpoint")
    return p


def verify_resume(payload: dict, *, now: int | None = None) -> tuple[dict, int]:
    """Repository-dispatch payload is untrusted: verify Owner order and bot proof."""
    if not isinstance(payload, dict) or set(payload) != {
        "source_issue", "stage", "paused_run", "attempt", "claim_comment"
    }:
        raise QuotaResumeError("Invalid dispatch envelope")
    source = payload["source_issue"]
    stage = payload["stage"]
    run_id = payload["paused_run"]
    attempt = payload["attempt"]
    claim_id = payload["claim_comment"]
    if any(type(v) is not int or v <= 0 for v in
           (source, stage, run_id, attempt, claim_id)):
        raise QuotaResumeError("Invalid dispatch identity")
    original = issue(source)
    order = _order(original.get("body", ""))
    if not _valid_stage(order, stage):
        raise QuotaResumeError("Unrecognized or out-of-range stage")
    all_comments = comments(source)
    pause = _validated_pause(all_comments, run_id, stage, attempt - 1)
    if pause["source_issue"] != source or (now or int(time.time())) < pause["retry_at"]:
        raise QuotaResumeError("Quota has not reached retry interval")
    claims = parsed_comments(all_comments, CLAIM)
    claim = [c for c in claims if c.get("_comment_id") == claim_id
             and c.get("run_id") == run_id and c.get("stage") == stage
             and c.get("attempt") == attempt]
    if len(claim) != 1:
        raise QuotaResumeError("No matching durable dispatch claim")
    # Verify the failed run belongs to the actual trusted Actions workflow;
    # a claimant cannot synthesize quota evidence in a plain Owner issue.
    run = _api("GET", "/actions/runs/" + str(run_id))
    if (not isinstance(run, dict) or run.get("id") != run_id or
            run.get("name") != "Agent switch (Owner GitHub order)" or
            run.get("status") != "completed" or run.get("conclusion") != "failure"):
        raise QuotaResumeError("Provider quota checkpoint run not verified failed")
    # Only the *uncompleted* bounded task is replayed. Never repeat stage 1
    # when the second of two workers failed; never substitute a vendor.
    single = {"target_repository": order["target_repository"],
              "mode": "serial",
              "tasks": [order["tasks"][stage - 1]]}
    return _order(json.dumps(single)), source


def pause_owner_issue(source: int, stage: int, run_id: int,
                      attempt: int, *, now: int | None = None) -> dict:
    original = issue(source)
    order = _order(original.get("body", ""))
    if not _valid_stage(order, stage) or type(attempt) is not int or attempt < 0:
        raise QuotaResumeError("Invalid quota stage")
    if type(run_id) is not int or run_id <= 0:
        raise QuotaResumeError("Invalid Actions run ID")
    clock = int(time.time()) if now is None else now
    marker = {"version": 1, "source_issue": source, "stage": stage,
              "run_id": run_id, "attempt": attempt,
              "retry_at": clock + delay_seconds(attempt),
              "quota": "provider_error_not_local_ledger"}
    text = PAUSE + "\n" + json.dumps(marker, sort_keys=True, separators=(",", ":"))
    prior = parsed_comments(comments(source), PAUSE)
    if any(x.get("run_id") == run_id and x.get("stage") == stage for x in prior):
        return marker
    _api("POST", f"/issues/{source}/comments", {"body": text})
    # First use may require installing the repo label; both operations are
    # bounded repository metadata writes, not source/branch changes.
    try:
        _api("POST", "/labels",
             {"name": LABEL, "color": "737373",
              "description": "Await Codex subscription quota renewal"})
    except QuotaResumeError:
        # Existing labels return 422, which is fine only if confirmed.
        label = _api("GET", "/labels/" + urllib.parse.quote(LABEL, safe=""))
        if not isinstance(label, dict) or label.get("name") != LABEL:
            raise
    _api("POST", f"/issues/{source}/labels", {"labels": [LABEL]})
    return marker


def due_pauses(rows: list, *, now: int) -> list[dict]:
    """Select only the latest as-yet-unclaimed block for each worker stage."""
    pauses = parsed_comments(rows, PAUSE)
    claims = parsed_comments(rows, CLAIM)
    newest = {}
    for pause in pauses:
        key = pause.get("stage")
        if type(key) is int and key in (1, 2):
            if key not in newest or pause.get("_comment_id", 0) > newest[key].get("_comment_id", 0):
                newest[key] = pause
    due = []
    for p in newest.values():
        if type(p.get("retry_at")) is not int or p["retry_at"] > now:
            continue
        run_id, stage, attempt = p.get("run_id"), p.get("stage"), p.get("attempt")
        if (type(run_id) is not int or type(attempt) is not int or attempt < 0
                or attempt > 1000):
            continue
        if any(c.get("run_id") == run_id and c.get("stage") == stage for c in claims):
            continue
        due.append(p)
    return sorted(due, key=lambda p: p["retry_at"])


def schedule_due(*, now: int | None = None) -> int:
    clock = int(time.time()) if now is None else now
    sent = 0
    for page in range(1, 4):
        records = _api("GET", f"/issues?state=open&labels={LABEL}&per_page=100&page={page}")
        if not isinstance(records, list):
            raise QuotaResumeError("Invalid paused issue listing")
        for current in records:
            if current.get("pull_request") or current.get("user", {}).get("login") != OWNER:
                continue
            number = current.get("number")
            if type(number) is not int or number <= 0:
                continue
            try:
                owned = issue(number)
                order = _order(owned.get("body", ""))
                candidates = due_pauses(comments(number), now=clock)
            except (QuotaResumeError, ValueError):
                continue
            for paused in candidates:
                if sent >= 3:
                    return sent
                if not _valid_stage(order, paused["stage"]) or paused.get("source_issue") != number:
                    continue
                run_id = paused["run_id"]
                run = _api("GET", "/actions/runs/" + str(run_id))
                if (run.get("status") != "completed" or run.get("conclusion") != "failure" or
                        run.get("name") != "Agent switch (Owner GitHub order)"):
                    continue
                claim = {"version": 1, "source_issue": number,
                         "stage": paused["stage"], "run_id": run_id,
                         "attempt": paused["attempt"] + 1}
                result = _api("POST", f"/issues/{number}/comments",
                              {"body": CLAIM + "\n" + json.dumps(claim, sort_keys=True, separators=(",", ":"))})
                comment_id = result.get("id")
                if type(comment_id) is not int:
                    raise QuotaResumeError("Dispatch claim not durable; refuse dispatch")
                _api("POST", "/dispatches", {
                    "event_type": "codex_quota_resume",
                    "client_payload": {"source_issue": number,
                                       "stage": paused["stage"],
                                       "paused_run": run_id,
                                       "attempt": paused["attempt"] + 1,
                                       "claim_comment": comment_id},
                })
                sent += 1
        if len(records) < 100:
            break
    return sent


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "classify":
            print("QUOTA_BLOCKED" if quota_error(Path(argv[2]), Path(argv[3])) else "OTHER_ERROR")
            return 0
        if len(argv) == 6 and argv[1] == "pause":
            value = pause_owner_issue(int(argv[2]), int(argv[3]),
                                      int(argv[4]), int(argv[5]))
            print("QUOTA_CHECKPOINT_SAVED_" + str(value["attempt"]))
            return 0
        if argv == ["quota", "scan"]:
            print("QUOTA_RESUMES_DISPATCHED=" + str(schedule_due()))
            return 0
    except (QuotaResumeError, ValueError, OSError):
        print("QUOTA_LIFECYCLE_FAIL_CLOSED", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
