#!/usr/bin/env python3
"""Read only visible Codex model metadata from VPS; never emit raw CLI output.

No Codex inference, cache refresh, auth data or private instruction templates leave
this process. Runs as the existing non-root account via pinned GitHub Actions SSH.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

CLI = Path.home() / "codex-agent/node_modules/.bin/codex"
SLUG = re.compile(r"gpt-[a-zA-Z0-9._-]{1,55}\Z")
VERSION = re.compile(r"codex-cli\s+v?(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)\Z")
EFFORTS = {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
ALLOWED_VISIBILITY = {"list", "hidden", "hide", "none", "unknown"}
MAX_CATALOG_BYTES = 6_000_000


def _execute(args: list[str], timeout: int = 30) -> tuple[str, str]:
    """Never print raw CLI output. Only return stdout internally."""
    env = os.environ.copy()
    for key in ("OPENAI_API_KEY", "CODEX_API_KEY"):
        env.pop(key, None)
    # The Codex CLI prints successful 'login status' on stderr (eprintln!).
    # Capture it only in memory for that exact command; never publish it.
    login_probe = args == ["login", "status"]
    try:
        result = subprocess.run(
            [str(CLI), *args], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if login_probe else subprocess.DEVNULL,
            env=env, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except (OSError, ValueError):
        return "unavailable", ""
    if result.returncode:
        return "command_failed", ""
    private_output = result.stdout + ((result.stderr or b"") if login_probe else b"")
    if len(private_output) > MAX_CATALOG_BYTES:
        return "oversized", ""
    return "ok", private_output.decode("utf-8", errors="replace")


def _read_cache() -> tuple[str, str]:
    """Inspect only the exact existing models cache; never invoke catalog refresh."""
    directory = Path.home() / ".codex"
    if directory.is_symlink():
        return "unavailable", ""
    cache = directory / "models_cache.json"
    try:
        descriptor = os.open(cache, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(MAX_CATALOG_BYTES + 1)
    except FileNotFoundError:
        return "missing", ""
    except (OSError, ValueError):
        return "unavailable", ""
    if len(data) > MAX_CATALOG_BYTES:
        return "oversized", ""
    return "ok", data.decode("utf-8", errors="replace")


def _efforts(item: object) -> list[str]:
    if not isinstance(item, dict):
        return []
    values = (item.get("supported_reasoning_levels")
              or item.get("supported_reasoning_efforts")
              or item.get("supportedReasoningEfforts")
              or [])
    if not isinstance(values, list):
        return []
    found = set()
    for v in values:
        if isinstance(v, str):
            name = v
        elif isinstance(v, dict):
            name = (v.get("effort") or v.get("reasoningEffort")
                    or v.get("reasoning_effort") or v.get("level"))
        else:
            continue
        if isinstance(name, str) and name in EFFORTS:
            found.add(name)
    return sorted(found, key=lambda z: ("minimal", "low", "medium", "high", "xhigh", "max", "ultra").index(z))


def _parse_catalog(text: str) -> list[dict]:
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return []
    entries = parsed.get("models") if isinstance(parsed, dict) else None
    if not isinstance(entries, list) or len(entries) > 120:
        return []
    result = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        slug = item.get("slug") or item.get("model") or item.get("id")
        if not isinstance(slug, str) or not SLUG.fullmatch(slug):
            continue
        visibility = item.get("visibility", "unknown")
        if visibility not in ALLOWED_VISIBILITY:
            visibility = "unknown"
        if visibility in {"hidden", "hide", "none"}:
            continue
        result.append({"slug": slug, "efforts": _efforts(item),
                       "visibility": visibility})
    # Stable output; never include full templates, prompts or other metadata.
    unique = {m["slug"]: m for m in result}
    return [unique[k] for k in sorted(unique)[:35]]


def inspect() -> dict:
    outcome = {"status": "INCONCLUSIVE", "cli_version": "unknown",
               "auth_mode": "unknown", "catalog_source": "none", "models": []}
    if not CLI.is_file() or not os.access(CLI, os.X_OK):
        outcome["status"] = "CLI_MISSING"
        return outcome
    status, ver = _execute(["--version"], timeout=10)
    if status == "ok":
        m = VERSION.fullmatch(ver.strip())
        if m:
            outcome["cli_version"] = m.group(1)
    status, login = _execute(["login", "status"], timeout=15)
    if status == "ok" and login.strip() == "Logged in using ChatGPT":
        outcome["auth_mode"] = "chatgpt"
    else:
        outcome["status"] = "AUTH_UNVERIFIED"
        return outcome
    # The official debug models command may refresh and WRITE models_cache.json.
    # Read only the existing cache, therefore do not claim real-time entitlement.
    status, catalog = _read_cache()
    if status != "ok":
        outcome["status"] = "CACHE_" + status.upper()
        return outcome
    models = _parse_catalog(catalog)
    if not models:
        outcome["status"] = "CACHE_UNPARSEABLE"
        return outcome
    outcome.update({"status": "CACHE_READ", "catalog_source": "local_cache",
                    "models": models})
    return outcome


if __name__ == "__main__":
    # Prints only filtered metadata, including on failure.
    try:
        print(json.dumps(inspect(), sort_keys=True, separators=(",", ":")))
    except Exception:
        print(json.dumps({"status": "INCONCLUSIVE", "models": [],
                          "auth_mode": "unknown", "cli_version": "unknown",
                          "catalog_source": "none"}))
