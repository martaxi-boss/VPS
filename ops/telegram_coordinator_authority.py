"""Authenticated Telegram Owner order data; never a Codex dispatcher.

Only a private allowlisted Telegram update may produce a short-lived HMAC claim.
A separate trusted GitHub Actions job checks this claim, GitHub Owner identity
and repository-scoped permissions before creating an Owner-authored Issue.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import unicodedata
from typing import Iterable

try:
    from ops.project_target import is_managed_target
except ModuleNotFoundError:
    from project_target import is_managed_target

VERSION = 1
MAX_AGE_SECONDS = 7200
MAX_TASK = 3800
_SAFE_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET = re.compile(
    r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9_-]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY|"
    r"(?:password|senha|access[_-]?token|api[_-]?key|secret)"
    r"\s*[:=]\s*\S{8,})"
)
_ACTION = re.compile(
    r"(?i)\b(?:corrige|corrigir|corrijam|corrijas|resolve|resolver|resolva|resolvas|resolvam|"
    r"implementa|implementar|conserta|consertar|altera|alterar|"
    r"repara|reparar|arranja|arranjar|melhora|melhorar|cria|criar|executa|executar)\b"
)


class OrderRefused(ValueError):
    pass


def is_execution_request(text: object) -> bool:
    return type(text) is str and _ACTION.search(text) is not None


def _slug(value: str) -> str:
    value = unicodedata.normalize("NFKD", value.casefold())
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-")


def resolve_target(text: str, candidates: Iterable[str]) -> str:
    """Require exactly one mentioned owner repository; never guess a default."""
    words = "-" + _slug(text) + "-"
    matches = sorted({
        name for name in candidates
        if is_managed_target(name)
        and "-" + _slug(name.split("/", 1)[1]) + "-" in words
    })
    if len(matches) != 1:
        raise OrderRefused("Name exactly one identifiable Owner repository")
    return matches[0]


def _claim_bytes(update_id: int, target: str, task: str, issued_at: int) -> bytes:
    if (type(update_id) is not int or not 0 < update_id < 10**16 or
            not is_managed_target(target) or
            type(task) is not str or not 12 <= len(task) <= MAX_TASK or
            _SAFE_TEXT.search(task) or _SECRET.search(task) or
            not is_execution_request(task) or
            type(issued_at) is not int or not 0 < issued_at < 2**63):
        raise OrderRefused("Unsafe or ambiguous Telegram Coordinator order")
    claim = {"v": VERSION, "update_id": update_id, "target": target,
             "task": task, "issued_at": issued_at}
    return json.dumps(claim, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def sign_claim(token: str, update_id: int, target: str, task: str,
               issued_at: int | None = None) -> tuple[str, str]:
    if type(token) is not str or len(token) < 20:
        raise OrderRefused("Telegram authorization not configured")
    raw = _claim_bytes(update_id, target, task,
                       int(time.time()) if issued_at is None else issued_at)
    if len(raw) > 6000:
        raise OrderRefused("Oversized Telegram order")
    encoded = base64.b64encode(raw).decode("ascii")
    signature = hmac.new(token.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return encoded, signature


def verify_claim(token: str, encoded: str, signature: str,
                 now: int | None = None) -> dict:
    if (type(token) is not str or len(token) < 20 or
            type(encoded) is not str or len(encoded) > 8000 or
            type(signature) is not str or
            re.fullmatch(r"[a-f0-9]{64}", signature) is None):
        raise OrderRefused("Telegram authentication invalid")
    try:
        raw = base64.b64decode(encoded, validate=True)
        claim = json.loads(raw.decode("ascii", "strict"))
    except (ValueError, UnicodeError, binascii.Error):
        raise OrderRefused("Malformed signed Telegram order") from None
    if type(claim) is not dict or set(claim) != {
            "v", "update_id", "target", "task", "issued_at"} or claim.get("v") != VERSION:
        raise OrderRefused("Unexpected Telegram order identity")
    reconstructed = _claim_bytes(claim["update_id"], claim["target"],
                                 claim["task"], claim["issued_at"])
    if reconstructed != raw or not hmac.compare_digest(
            hmac.new(token.encode("utf-8"), raw, hashlib.sha256).hexdigest(),
            signature):
        raise OrderRefused("Telegram signature mismatch")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or not -300 <= observed - claim["issued_at"] <= MAX_AGE_SECONDS:
        raise OrderRefused("Expired Telegram authorization")
    return claim
