"""GitHub-side trusted Telegram order bridge; only creates verified Owner Issues.

Runs after the private Telegram gateway signs an exact text/voice order. The
Publisher PAT is never exposed to the Telegram input parser or Codex. GitHub's
existing Owner-only Coordinator Issue path remains the sole execution trigger.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from ops.telegram_coordinator_authority import OrderRefused, verify_claim

OWNER = "martaxi-boss"
BRIDGE = OWNER + "/VPS"
MAX_ISSUE_PAGES = 10


class BridgeRefused(ValueError):
    pass


def github(method: str, route: str, token: str, payload: dict | None = None):
    if not token:
        raise BridgeRefused("GITHUB_CREDENTIAL_NOT_CONFIGURED")
    body = None if payload is None else json.dumps(
        payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "Project-Leader-Telegram-Owner-Claim",
    }
    req = urllib.request.Request("https://api.github.com/" + route.lstrip("/"),
                                 data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read(500_001)
        if len(raw) > 500_000:
            raise BridgeRefused("GITHUB_RESPONSE_OVERSIZED")
        return json.loads(raw) if raw else {}
    except (OSError, ValueError, urllib.error.HTTPError):
        raise BridgeRefused("GITHUB_OWNER_AUTH_OR_TRANSPORT_UNVERIFIED") from None


def verify_public_owner_target(target: str, publisher_token: str,
                               get: Callable = github) -> None:
    from ops.project_target import is_managed_target
    if not is_managed_target(target):
        raise BridgeRefused("TARGET_NOT_MANAGED")
    user = get("GET", "user", publisher_token)
    if type(user) is not dict or user.get("login") != OWNER:
        raise BridgeRefused("PUBLISHER_IS_NOT_OWNER")
    metadata = get("GET", "repos/" + target, publisher_token)
    if (type(metadata) is not dict or
            metadata.get("full_name") != target or
            metadata.get("owner", {}).get("login") != OWNER or
            metadata.get("private") is not False or
            metadata.get("archived") is not False or
            metadata.get("default_branch") != "main" or
            metadata.get("permissions", {}).get("push") is not True):
        raise BridgeRefused("TARGET_REPOSITORY_WRITE_NOT_VERIFIED")


def find_issue(title: str, body: str, token: str,
               get: Callable = github) -> int | None:
    """Verify ambiguous writes and deny collisions before replaying."""
    for page in range(1, MAX_ISSUE_PAGES + 1):
        rows = get("GET", "repos/" + BRIDGE + "/issues?" +
                   urllib.parse.urlencode({"state": "all", "per_page": 100,
                                           "page": page, "sort": "created",
                                           "direction": "desc"}), token)
        if type(rows) is not list or len(rows) > 100:
            raise BridgeRefused("ISSUE_HISTORY_UNVERIFIED")
        for item in rows:
            if item.get("title") != title:
                continue
            if (item.get("user", {}).get("login") != OWNER or
                    item.get("body") != body or
                    "pull_request" in item):
                raise BridgeRefused("TELEGRAM_ORDER_ID_COLLISION")
            number = item.get("number")
            if type(number) is not int or number < 1:
                raise BridgeRefused("ISSUE_ID_UNVERIFIED")
            return number
        if len(rows) < 100:
            return None
    raise BridgeRefused("ISSUE_HISTORY_BOUND_EXCEEDED")


def issue_from_claim(signed: str, signature: str, telegram_token: str,
                     publisher_token: str, *,
                     get: Callable = github, now: int | None = None) -> tuple[int, bool]:
    try:
        claim = verify_claim(telegram_token, signed, signature, now=now)
    except OrderRefused:
        raise BridgeRefused("TELEGRAM_SIGNATURE_UNVERIFIED") from None
    target = claim["target"]
    verify_public_owner_target(target, publisher_token, get=get)
    number = claim["update_id"]
    title = "[coordinator run] Telegram " + str(number)
    body = ("TARGET_REPOSITORY=" + target + "\n\n" +
            claim["task"].strip())
    prior = find_issue(title, body, publisher_token, get=get)
    if prior is not None:
        return prior, False
    try:
        result = get("POST", "repos/" + BRIDGE + "/issues", publisher_token,
                     {"title": title, "body": body})
    except BridgeRefused:
        # An uncertain POST might already have succeeded. Inspect before retry.
        found = find_issue(title, body, publisher_token, get=get)
        if found is not None:
            return found, False
        raise
    if (type(result) is not dict or result.get("title") != title or
            result.get("body") != body or
            result.get("user", {}).get("login") != OWNER or
            type(result.get("number")) is not int or result["number"] < 1):
        raise BridgeRefused("OWNER_ISSUE_CREATION_UNVERIFIED")
    return result["number"], True


def main() -> int:
    try:
        number, created = issue_from_claim(
            os.environ.get("TELEGRAM_SIGNED_ORDER", ""),
            os.environ.get("TELEGRAM_SIGNED_MAC", ""),
            os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            os.environ.get("CODEX_GITHUB_TOKEN", ""))
    except BridgeRefused as exc:
        print("TELEGRAM_COORDINATOR_NOT_STARTED:" + str(exc))
        return 2
    print("TELEGRAM_COORDINATOR_OWNER_ISSUE=" +
          ("CREATED" if created else "ALREADY_EXISTS") + " #" + str(number))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
