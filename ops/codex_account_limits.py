#!/usr/bin/env python3
"""Read real ChatGPT Codex quota, via the already signed-in Codex app-server.

Read-only JSON-RPC calls only: initialize, account/read, account/rateLimits/read.
No inference calls, no OAuth tokens, no scraping, no fabricated quota counters.
Output is a bounded sanitized provider snapshot without account identifiers.
"""
from __future__ import annotations

import json
import os
import re
import select
import subprocess
import sys
import time

SOURCE = "codex_app_server"
STATES = {"AVAILABLE", "BLOCKED", "UNKNOWN"}
MAX_RESPONSE = 128_000


class ProbeError(RuntimeError):
    pass


def _window(name: str, raw: object) -> dict | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProbeError("WINDOW_INVALID")
    value = raw.get("usedPercent")
    if type(value) is not int or not 0 <= value <= 100:
        raise ProbeError("PERCENT_INVALID")
    minutes = raw.get("windowDurationMins")
    if minutes is not None and (type(minutes) is not int or not 1 <= minutes <= 100800):
        raise ProbeError("WINDOW_DURATION_INVALID")
    reset = raw.get("resetsAt")
    if reset is not None and (type(reset) is not int or not 1_500_000_000 <= reset < 4_102_444_800):
        raise ProbeError("RESET_INVALID")
    return {"window": name, "used_percent": value,
            "duration_mins": minutes, "resets_at": reset}


def summarize(account: dict, response: dict, *, now: int | None = None) -> dict:
    """Only the literal Codex shared quota, not an arbitrary local ledger."""
    if (not isinstance(account, dict) or
            not isinstance(account.get("account"), dict) or
            account["account"].get("type") != "chatgpt"):
        raise ProbeError("CHATGPT_LOGIN_NOT_VERIFIED")
    if not isinstance(response, dict):
        raise ProbeError("QUOTA_RESPONSE_INVALID")
    rate = response.get("rateLimits")
    by_id = response.get("rateLimitsByLimitId")
    if isinstance(by_id, dict) and "codex" in by_id:
        rate = by_id["codex"]
    if not isinstance(rate, dict) or rate.get("limitId") != "codex":
        raise ProbeError("CODEX_BUCKET_UNAVAILABLE")
    windows = [_window(n, rate.get(n)) for n in ("primary", "secondary")]
    windows = [w for w in windows if w is not None]
    if not windows:
        raise ProbeError("QUOTA_WINDOWS_UNAVAILABLE")
    classified = rate.get("rateLimitReachedType")
    if classified is not None and not isinstance(classified, (dict, str)):
        raise ProbeError("LIMIT_TYPE_UNVERIFIED")
    spend = rate.get("spendControlReached")
    if spend is not None and type(spend) is not bool:
        raise ProbeError("SPEND_LIMIT_INVALID")
    allowed = response.get("ordinaryUsageAllowed")
    if allowed is not None and type(allowed) is not bool:
        raise ProbeError("AVAILABILITY_INVALID")
    blocked = (any(w["used_percent"] >= 100 for w in windows)
               or classified is not None or spend is True or allowed is False)
    # The official Codex protocol explicitly says that absent/null
    # ordinaryUsageAllowed does NOT prove that quota is available, even
    # when percentages are below 100 or a reset timestamp has elapsed.
    if not blocked and allowed is not True:
        raise ProbeError("QUOTA_AVAILABILITY_UNVERIFIED")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 1_500_000_000:
        raise ProbeError("CLOCK_INVALID")
    # No model-specific bucket mapping is assumed. AVAILABLE means the
    # confirmed shared Codex quota bucket is available, not a promise that
    # any selected model will accept a new request.
    return {"version": 1, "source": SOURCE, "auth": "chatgpt",
            "status": "BLOCKED" if blocked else "AVAILABLE",
            "checked_at": current, "bucket": "codex", "windows": windows,
            "model_specific_state": "NOT_VERIFIED",
            "owner_resumption": "REQUIRES_NEW_OWNER_ORDER"}


class _RPC:
    """Nonblocking bounded stdio transport, never echo provider JSON or tokens."""

    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self.pending = b""

    def send(self, message: dict) -> None:
        payload = (json.dumps(message, separators=(",", ":")) + "\n").encode()
        if not self.proc.stdin:
            raise ProbeError("CODEX_STDIN_CLOSED")
        try:
            self.proc.stdin.write(payload)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise ProbeError("CODEX_STDIN_UNAVAILABLE") from None

    def reply(self, request_id: int, *, seconds: int = 18) -> dict:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                if not line:
                    continue
                try:
                    response = json.loads(line)
                except (ValueError, UnicodeError):
                    raise ProbeError("CODEX_PROTOCOL_INVALID") from None
                if isinstance(response, dict) and response.get("id") == request_id:
                    if "error" in response or not isinstance(response.get("result"), dict):
                        raise ProbeError("CODEX_RPC_FAILED")
                    return response["result"]
            if len(self.pending) > MAX_RESPONSE:
                raise ProbeError("CODEX_PROTOCOL_TOO_LARGE")
            if not self.proc.stdout:
                raise ProbeError("CODEX_STDOUT_UNAVAILABLE")
            ready, _, _ = select.select([self.proc.stdout.fileno()], [],
                                        [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            part = os.read(self.proc.stdout.fileno(), 8192)
            if not part:
                raise ProbeError("CODEX_APP_SERVER_EXITED")
            self.pending += part
        raise ProbeError("CODEX_APP_SERVER_TIMEOUT")


def read_provider(cli: str, *, now: int | None = None) -> dict:
    if not isinstance(cli, str) or not cli.startswith("/") or not os.access(cli, os.X_OK):
        raise ProbeError("CODEX_CLI_NOT_AVAILABLE")
    # Never fall back to API key billing; the Owner requested the ChatGPT plan.
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_API_KEY"):
        raise ProbeError("API_KEY_BILLING_REFUSED")
    env = {k: v for k, v in os.environ.items()
           if k not in ("OPENAI_API_KEY", "CODEX_API_KEY")}
    try:
        login = subprocess.run([cli, "login", "status"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, timeout=12,
                               env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeError("LOGIN_STATUS_UNAVAILABLE") from None
    if login.returncode != 0 or login.stdout.strip() != "Logged in using ChatGPT":
        raise ProbeError("CHATGPT_LOGIN_NOT_VERIFIED")
    try:
        proc = subprocess.Popen([cli, "app-server", "--stdio"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env)
    except OSError:
        raise ProbeError("CODEX_APP_SERVER_UNAVAILABLE") from None
    try:
        rpc = _RPC(proc)
        rpc.send({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "project_leader_quota_observer",
                           "title": "Project Leader read-only quota observer",
                           "version": "1.0.0"},
            "capabilities": {}}})
        rpc.reply(1)
        rpc.send({"method": "initialized", "params": {}})
        rpc.send({"id": 2, "method": "account/read", "params": {
            "refreshToken": False}})
        account = rpc.reply(2)
        if not isinstance(account.get("account"), dict) or account["account"].get("type") != "chatgpt":
            raise ProbeError("CHATGPT_LOGIN_NOT_VERIFIED")
        rpc.send({"id": 3, "method": "account/rateLimits/read"})
        response = rpc.reply(3)
        return summarize(account, response, now=now)
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=3)


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "read":
        print("Usage: codex_account_limits.py read /absolute/codex", file=sys.stderr)
        return 2
    try:
        data = read_provider(argv[2])
        print(json.dumps(data, separators=(",", ":"), sort_keys=True))
        return 0
    except ProbeError as exc:
        # Only our own fixed enum is returned. No raw provider responses,
        # account identifiers, access tokens, emails or process stderr.
        reason = str(exc)
        if not re.fullmatch(r"[A-Z_]{3,64}", reason):
            reason = "UNVERIFIED"
        print(json.dumps({"version": 1, "source": SOURCE, "auth": "unverified",
                          "status": "UNKNOWN", "reason": reason,
                          "owner_resumption": "REQUIRES_NEW_OWNER_ORDER"},
                         separators=(",", ":"), sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
