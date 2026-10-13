#!/usr/bin/env python3
"""Authenticated phase-to-phase continuation of the EXISTING Codex Coordinator.

Project Leader is mandatory for *workers*, never loaded by this module or the
Coordinator AI. No model is started here. Only a previous independently
merged/CI-verified Owner run may schedule the next read-only audit. No stale
Codex audit is ever used for dispatch across changed Git HEADs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

CONTROL = "martaxi-boss/VPS"
TARGET = "martaxi-boss/Project-leader-codex"
OWNER = "martaxi-boss"
BOT = "github-actions[bot]"
API = "https://api.github.com/repos/" + CONTROL
READY = "<!-- PL_COORDINATOR_PHASE_READY_V1 -->"
STARTED = "<!-- PL_COORDINATOR_PHASE_STARTED_V1 -->"
EVENT = "coordinator_next_phase"
RUN_NAME = "Coordinator to existing Codex router (Owner order)"
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_BODY = 8000
MAX_COMMENTS = 500


class PhaseHold(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _number(v: object, code: str, cap: int = 10**16) -> int:
    if type(v) is not int or not 0 < v <= cap:
        raise PhaseHold("INVALID_" + code)
    return v


def _api(method: str, route: str, payload: object = None) -> object:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise PhaseHold("AUTH_UNAVAILABLE")
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            if payload is not None else None)
    req = urllib.request.Request(API + route, method=method, data=data,
                                 headers={
                                     "Authorization": "Bearer " + token,
                                     "Accept": "application/vnd.github+json",
                                     "X-GitHub-Api-Version": "2022-11-28",
                                     "Content-Type": "application/json",
                                     "User-Agent": "Project-Leader-Phase-Continuation"})
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read(200_001)
            if len(raw) > 200_000:
                raise PhaseHold("API_RESPONSE_OVERSIZED")
            return json.loads(raw) if raw else {}
    except (urllib.error.URLError, OSError, ValueError):
        raise PhaseHold("API_UNVERIFIED") from None


def _issue(number: int) -> dict:
    issue = _api("GET", f"/issues/{number}")
    if (not isinstance(issue, dict) or issue.get("number") != number or
            issue.get("state") != "open" or
            issue.get("user", {}).get("login") != OWNER or
            not issue.get("title", "").startswith("[coordinator run] ")):
        raise PhaseHold("OWNER_ISSUE_UNVERIFIED")
    body = issue.get("body")
    if (type(body) is not str or
            not 50 <= len(body.encode("utf-8")) <= MAX_BODY or
            not body.startswith("TARGET_REPOSITORY=" + TARGET + "\n")):
        raise PhaseHold("OWNER_ORDER_UNVERIFIED")
    return issue


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _main() -> str:
    # Target is explicitly fixed: never trust a repository path from an event.
    token = os.environ.get("CODEX_GITHUB_TOKEN", "")
    if not token:
        raise PhaseHold("TARGET_READ_AUTH_UNAVAILABLE")
    req = urllib.request.Request(
        "https://api.github.com/repos/" + TARGET + "/git/ref/heads/main",
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "Project-Leader-Phase-Continuation"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            value = json.load(response)
    except (urllib.error.URLError, OSError, ValueError):
        raise PhaseHold("TARGET_HEAD_UNAVAILABLE") from None
    sha = value.get("object", {}).get("sha", "")
    if not SHA.fullmatch(sha):
        raise PhaseHold("TARGET_HEAD_UNVERIFIED")
    return sha


def _marker(marker: str, record: dict) -> str:
    return marker + "\n" + json.dumps(record, sort_keys=True, separators=(",", ":"))


def request_next(issue: int, previous_run: int, phase: int,
                 maximum: int, merged_sha: str) -> int:
    """One durable bot checkpoint, then one repository_dispatch; no model."""
    _number(issue, "ISSUE")
    _number(previous_run, "RUN")
    _number(phase, "PHASE", 8)
    _number(maximum, "MAX_PHASES", 8)
    if phase >= maximum or not SHA.fullmatch(merged_sha):
        raise PhaseHold("NO_AUTHORIZED_NEXT_PHASE")
    owner = _issue(issue)
    if _main() != merged_sha:
        raise PhaseHold("MERGED_HEAD_CHANGED")
    record = {
        "version": 1, "source_issue": issue, "previous_run": previous_run,
        "next_phase": phase + 1, "total_phases": maximum,
        "expected_sha": merged_sha, "owner_digest": _digest(owner["body"]),
    }
    posted = _api("POST", f"/issues/{issue}/comments",
                  {"body": _marker(READY, record)})
    cid = posted.get("id")
    _number(cid, "CHECKPOINT")
    # If this dispatch fails after the checkpoint write, do not silently retry;
    # the durable comment permits independent reconciliation.
    _api("POST", "/dispatches", {
        "event_type": EVENT,
        "client_payload": {**record, "checkpoint_comment": cid}
    })
    return cid


def _comments(number: int) -> list:
    result = []
    for page in range(1, 6):
        found = _api("GET", f"/issues/{number}/comments?per_page=100&page={page}")
        if not isinstance(found, list):
            raise PhaseHold("COMMENTS_UNVERIFIED")
        result.extend(found)
        if len(result) > MAX_COMMENTS:
            raise PhaseHold("COMMENTS_UNBOUNDED")
        if len(found) < 100:
            return result
    raise PhaseHold("COMMENTS_UNBOUNDED")


def verify_dispatch(payload: object) -> dict:
    """Verify bot-made attestation + original Owner order + one-time lease."""
    fields = {"version", "source_issue", "previous_run", "next_phase",
              "total_phases", "expected_sha", "owner_digest", "checkpoint_comment"}
    if not isinstance(payload, dict) or set(payload) != fields or payload["version"] != 1:
        raise PhaseHold("PHASE_ENVELOPE_INVALID")
    issue_id = _number(payload["source_issue"], "ISSUE")
    prev_run = _number(payload["previous_run"], "RUN")
    phase = _number(payload["next_phase"], "PHASE", 8)
    maximum = _number(payload["total_phases"], "MAX_PHASES", 8)
    comment_id = _number(payload["checkpoint_comment"], "CHECKPOINT")
    sha, digest = payload["expected_sha"], payload["owner_digest"]
    if (phase < 2 or phase > maximum or type(sha) is not str or
            not SHA.fullmatch(sha) or type(digest) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise PhaseHold("PHASE_BOUNDS_INVALID")
    owner = _issue(issue_id)
    if _digest(owner["body"]) != digest:
        raise PhaseHold("OWNER_ORDER_CHANGED")
    checkpoint = _api("GET", f"/issues/comments/{comment_id}")
    record = {k: payload[k] for k in fields if k != "checkpoint_comment"}
    if (not isinstance(checkpoint, dict) or
            checkpoint.get("user", {}).get("login") != BOT or
            checkpoint.get("issue_url") != API + f"/issues/{issue_id}" or
            checkpoint.get("body") != _marker(READY, record)):
        raise PhaseHold("BOT_CHECKPOINT_UNVERIFIED")
    if _main() != sha:
        raise PhaseHold("TARGET_MAIN_DRIFT")
    # The preceding Supervisor must have finished successfully. Its merged
    # SHA is the exact live main bound to the bot checkpoint above.
    deadline = time.monotonic() + 100
    while True:
        previous = _api("GET", f"/actions/runs/{prev_run}")
        if (previous.get("name") != RUN_NAME or
                previous.get("event") not in ("issues", "repository_dispatch") or
                previous.get("repository", {}).get("full_name") != CONTROL):
            raise PhaseHold("PREVIOUS_RUN_IDENTITY_UNVERIFIED")
        if previous.get("status") == "completed":
            if previous.get("conclusion") != "success":
                raise PhaseHold("PREVIOUS_RUN_NOT_CERTIFIED")
            break
        if time.monotonic() >= deadline:
            raise PhaseHold("PREVIOUS_RUN_STILL_ACTIVE")
        time.sleep(4)
    rows = _comments(issue_id)
    for item in rows:
        if (item.get("user", {}).get("login") == BOT and
                isinstance(item.get("body"), str) and
                item["body"].startswith(STARTED + "\n")):
            try:
                started = json.loads(item["body"].split("\n", 1)[1])
            except ValueError:
                raise PhaseHold("STARTED_CHECKPOINT_CORRUPT") from None
            if started.get("checkpoint_comment") == comment_id:
                raise PhaseHold("CONTINUATION_ALREADY_STARTED")
    # Mark irreversible one-attempt dispatch BEFORE invoking Codex planning.
    ack = _api("POST", f"/issues/{issue_id}/comments", {
        "body": _marker(STARTED, {
            "checkpoint_comment": comment_id, "next_phase": phase,
            "previous_run": prev_run,
        })
    })
    _number(ack.get("id"), "STARTED_LEASE")
    orig_id = _number(owner.get("id"), "ORIGINAL_ISSUE_ID")
    return {"issue_number": issue_id, "issue_id": orig_id,
            "phase_index": phase, "max_phases": maximum,
            "owner_order_b64": base64.b64encode(
                owner["body"].encode("utf-8")).decode("ascii")}
