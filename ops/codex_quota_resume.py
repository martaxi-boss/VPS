#!/usr/bin/env python3
"""Provider quota error detection and Owner-only pause checkpoints.

Historical V1 PAUSE/READY/CLAIM records and validation functions are preserved
read-only for audit compatibility, but their legacy CLI entrypoints and
automatic retry scheduler are disabled. Only classify and Owner-only hold are
active. No quota restoration authorizes another model call or worker dispatch.
"""
from __future__ import annotations

import hashlib
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
READY = "<!-- CODEX_STAGE_READY_V1 -->"
CLAIM = "<!-- CODEX_QUOTA_CLAIM_V1 -->"
STARTED = "<!-- CODEX_QUOTA_STARTED_V1 -->"
LABEL = "codex-quota-paused"
HOLD_V2 = "<!-- CODEX_PROVIDER_QUOTA_HOLD_OWNER_ONLY_V2 -->"
MAX_COMMENTS = 500
MAX_ISSUES = 10_000  # Fail closed rather than silently losing any older paused issue
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
    # Keep the same first-wave router and complete Owner-manifest digest as
    # the original issue preflight. Otherwise a later edit of held stages
    # could reuse an old quota lease for an unchanged first stage.
    return agent_switch.parse_owner_envelope(raw)[0]


def order_digest(order: dict) -> str:
    """Bind retries to the exact authenticated Owner order, not editable text."""
    normalized = json.dumps(order, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ensure_label(source: int) -> None:
    try:
        _api("POST", "/labels",
             {"name": LABEL, "color": "737373",
              "description": "Await Codex subscription quota renewal"})
    except QuotaResumeError:
        existing = _api("GET", "/labels/" + urllib.parse.quote(LABEL, safe=""))
        if not isinstance(existing, dict) or existing.get("name") != LABEL:
            raise
    _api("POST", f"/issues/{source}/labels", {"labels": [LABEL]})


def _valid_stage(order: dict, stage: int) -> bool:
    return type(stage) is int and 1 <= stage <= len(order["tasks"]) <= 2


def _validated_checkpoint(rows: list, run_id: int, stage: int, attempt: int) -> dict:
    checkpoints = ({**p, "_source_kind": "quota"} for p in parsed_comments(rows, PAUSE))
    ready = ({**p, "_source_kind": "ready"} for p in parsed_comments(rows, READY))
    matches = [p for p in [*checkpoints, *ready] if p.get("run_id") == run_id
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
    pause = _validated_checkpoint(all_comments, run_id, stage, attempt - 1)
    if (pause["source_issue"] != source or
            pause.get("order_digest") != order_digest(order) or
            (now if now is not None else int(time.time())) < pause["retry_at"]):
        raise QuotaResumeError("Checkpoint no longer matches Owner order or retry interval")
    claims = parsed_comments(all_comments, CLAIM)
    relevant = [c for c in claims if c.get("run_id") == run_id
                and c.get("stage") == stage]
    if (not relevant or
            max(relevant, key=lambda c: c.get("_comment_id", 0)).get("_comment_id") != claim_id or
            len([c for c in relevant if c.get("_comment_id") == claim_id
                 and c.get("attempt") == attempt]) != 1):
        raise QuotaResumeError("Dispatch claim is not the newest attested lease")
    started = parsed_comments(all_comments, STARTED)
    if any(z.get("claim_comment") == claim_id and z.get("run_id") == run_id
           and z.get("stage") == stage for z in started):
        raise QuotaResumeError("Dispatch already started; no replay")
    # Verify the failed run belongs to the actual trusted Actions workflow;
    # a claimant cannot synthesize quota evidence in a plain Owner issue.
    run = _api("GET", "/actions/runs/" + str(run_id))
    expected_conclusion = "success" if pause["_source_kind"] == "ready" else "failure"
    if (not isinstance(run, dict) or run.get("id") != run_id or
            run.get("name") != "Agent switch (Owner GitHub order)" or
            run.get("status") != "completed" or
            run.get("conclusion") != expected_conclusion):
        raise QuotaResumeError("Trusted predecessor workflow outcome not verified")
    if pause["_source_kind"] == "ready" and (
            stage != 2 or order["mode"] != "serial" or len(order["tasks"]) != 2):
        raise QuotaResumeError("Invalid serial phase readiness")
    # Preserve the complete immutable Owner order for the trusted router.
    # The attested stage is passed separately to workflow_values(), which
    # enables *only* that worker. Truncating this order to one task would
    # misidentify stage 2 and bypass the live serial/parallel job selection.
    return order, source


def record_start(payload: dict) -> None:
    """Durably prove dispatch reached the trusted gate, before any model call."""
    _, source = verify_resume(payload)
    marker = {"source_issue": source, "stage": payload["stage"],
              "run_id": payload["paused_run"],
              "attempt": payload["attempt"],
              "claim_comment": payload["claim_comment"]}
    response = _api(
        "POST", f"/issues/{source}/comments",
        {"body": STARTED + "\n" + json.dumps(marker, sort_keys=True, separators=(",", ":"))},
    )
    if type(response.get("id")) is not int:
        raise QuotaResumeError("Unconfirmed start checkpoint; no model allowed")


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
              "order_digest": order_digest(order),
              "quota": "provider_error_not_local_ledger"}
    text = PAUSE + "\n" + json.dumps(marker, sort_keys=True, separators=(",", ":"))
    prior = parsed_comments(comments(source), PAUSE)
    existing = next((x for x in prior if x.get("run_id") == run_id
                     and x.get("stage") == stage), None)
    if existing is None:
        _api("POST", f"/issues/{source}/comments", {"body": text})
    elif existing.get("order_digest") != marker["order_digest"]:
        raise QuotaResumeError("Replay does not match initial authenticated order")
    # Even when the comment already exists, repair a failed label write.
    _ensure_label(source)
    return existing if existing is not None else marker


def ready_after_first_serial_stage(source: int, run_id: int, result_path: Path,
                                   *, now: int | None = None) -> bool:
    """Advance only a fully verified serial predecessor; never merge a Codex PR."""
    owner = issue(source)
    order = _order(owner.get("body", ""))
    if order["mode"] != "serial" or len(order["tasks"]) != 2:
        return False
    if (not result_path.is_file() or result_path.is_symlink()
            or result_path.stat().st_size > 16_000):
        raise QuotaResumeError("Missing bounded publication evidence")
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise QuotaResumeError("Invalid publisher result")
    if not isinstance(result, dict) or result.get("repository") != order["target_repository"]:
        raise QuotaResumeError("Publication target does not match Owner order")
    state = result.get("status")
    if state not in ("MERGED", "NO_CHANGE") and not (
            state == "PR_STAGED" and order.get("serial_independent") is True):
        # A PR from a dependent serial phase is not yet on main.
        return False
    if type(run_id) is not int or run_id <= 0:
        raise QuotaResumeError("Invalid first stage run")
    prior = parsed_comments(comments(source), READY)
    existing = next((p for p in prior if p.get("run_id") == run_id), None)
    ready = {"version": 1, "source_issue": source, "stage": 2,
             "run_id": run_id, "attempt": 0,
             "retry_at": int(time.time()) if now is None else now,
             "order_digest": order_digest(order),
             "preceding_status": state}
    if existing is None:
        _api("POST", f"/issues/{source}/comments",
             {"body": READY + "\n" + json.dumps(ready, sort_keys=True, separators=(",", ":"))})
    elif existing.get("order_digest") != ready["order_digest"]:
        raise QuotaResumeError("Serial readiness order was edited")
    _ensure_label(source)
    return True


def due_pauses(rows: list, *, now: int) -> list[dict]:
    """Select latest paused or safe-ready unclaimed task for each stage."""
    pauses = ([{**p, "_source_kind": "quota"} for p in parsed_comments(rows, PAUSE)]
              + [{**p, "_source_kind": "ready"} for p in parsed_comments(rows, READY)])
    claims = parsed_comments(rows, CLAIM)
    starts = parsed_comments(rows, STARTED)
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
        relevant_claims = [c for c in claims if c.get("run_id") == run_id
                           and c.get("stage") == stage]
        if relevant_claims:
            latest = max(relevant_claims, key=lambda c: c.get("_comment_id", 0))
            if any(z.get("run_id") == run_id and z.get("stage") == stage
                   for z in starts):
                # Once ANY claim started this immutable stage, do not replay
                # it even if a later dispatch request became ambiguous.
                continue
            stamped = latest.get("claimed_at")
            if type(stamped) is not int or now - stamped < 5400:
                # Reconcile ambiguous dispatch only after 90 min. An old
                # event arriving later must fail the newest-claim check.
                continue
        due.append(p)
    return sorted(due, key=lambda p: p["retry_at"])


def schedule_due(*, now: int | None = None) -> int:
    """Legacy automatic dispatch prohibited: only a new Owner order may resume.

    Existing authenticated checkpoints remain durable evidence of paused
    stages, but no internal timer, retry lease or quota reset is authorization.
    """
    raise QuotaResumeError("QUOTA_AUTO_RESUME_DISABLED_OWNER_ONLY")



def owner_only_hold(source: int, worker: str, run_id: int,
                    workspace_key: str) -> dict:
    """Durably freeze ANY authenticated Owner task, including Coordinator DAGs.

    The record permits NO automatic model execution or resumed dispatch.
    The Owner must issue a separate new authenticated instruction.
    """
    if (type(source) is not int or not 0 < source < 10**9 or
            type(run_id) is not int or not 0 < run_id < 10**16 or
            not isinstance(worker, str) or
            not re.fullmatch(r"(?:[12]|p[2-8]-[12])", worker)):
        raise QuotaResumeError("Quota hold identity unavailable")
    # The saved private checkout is identified by the exact runner job key,
    # not by an inferred attempt or a mutable Owner-supplied path.
    if (type(workspace_key) is not str or
            not re.fullmatch(rf"{run_id}-[1-9][0-9]{{0,3}}(?:-{re.escape(worker)})?",
                             workspace_key) or
            (worker.startswith("p") and not workspace_key.endswith("-" + worker))):
        raise QuotaResumeError("Quota hold workspace identity unavailable")
    item = _api("GET", "/issues/" + str(source))
    if (not isinstance(item, dict) or item.get("number") != source
            or item.get("pull_request") or item.get("state") != "open"
            or (item.get("user") or {}).get("login") != OWNER
            or not any(str(item.get("title", "")).startswith(prefix)
                       for prefix in ("[agents run]", "[coordinator run] ",
                                      "[codex run]", "[codex audit] "))):
        raise QuotaResumeError("Authenticated original Owner order unavailable")
    body = item.get("body")
    if type(body) is not str or not body.strip():
        raise QuotaResumeError("Original Owner instruction unavailable")
    run = _api("GET", "/actions/runs/" + str(run_id))
    if (not isinstance(run, dict) or run.get("id") != run_id or
            run.get("name") not in (
                "Agent switch (Owner GitHub order)",
                "Coordinator to existing Codex router (Owner order)",
                "Codex autonomous execution (Owner-authorized)",
                "Codex - ChatGPT bridge") or
            (run.get("repository") or {}).get("full_name") != REPO):
        raise QuotaResumeError("Worker source execution could not be verified")
    metadata = {
        "version": 2, "source_issue": source,
        "run_id": run_id, "worker": worker, "workspace_key": workspace_key,
        "source": "codex_provider_quota",
        "owner_order_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "resumption": "REQUIRES_NEW_OWNER_ORDER",
    }
    note = HOLD_V2 + "\n" + json.dumps(
        metadata, sort_keys=True, separators=(",", ":"))
    historical = comments(source)
    prior = parsed_comments(historical, HOLD_V2)
    similar = [x for x in prior if
               x.get("run_id") == run_id and x.get("worker") == worker]
    if similar:
        if len(similar) != 1 or any(
                similar[0].get(key) != value for key, value in metadata.items()):
            raise QuotaResumeError("Quota checkpoint differs from original Owner order")
    else:
        saved = _api("POST", f"/issues/{source}/comments", {"body": note})
        if type(saved.get("id")) is not int:
            raise QuotaResumeError("Quota checkpoint not confirmed")
    _ensure_label(source)
    return metadata


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "classify":
            print("QUOTA_BLOCKED" if quota_error(Path(argv[2]), Path(argv[3])) else "OTHER_ERROR")
            return 0
        if len(argv) >= 2 and argv[1] in ("pause", "ready"):
            # Historical entrypoints must never mutate old checkpoints or
            # declare a new stage ready without a fresh Owner instruction.
            print("QUOTA_LEGACY_ROUTE=DISABLED_OWNER_ONLY")
            return 3
        if len(argv) == 6 and argv[1] == "hold":
            meta = owner_only_hold(int(argv[2]), argv[3], int(argv[4]), argv[5])
            print("QUOTA_OWNER_ONLY_CHECKPOINT_SAVED=" + meta["worker"])
            return 0
        if len(argv) == 2 and argv[1] == "scan":
            # Keep old entrypoint harmless for external scheduled callers.
            print("QUOTA_AUTO_RESUME=DISABLED_OWNER_DECIDES")
            return 0
    except (QuotaResumeError, ValueError, OSError):
        print("QUOTA_LIFECYCLE_FAIL_CLOSED", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
