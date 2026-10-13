#!/usr/bin/env python3
"""Private usage ledger, replay protection and bounded Codex reasoning.

Only the Codex provider can enforce the signed-in account's actual limits.
The previous artificial 300,000-token / 24h VPS admission cap contradicted
the Owner's available ChatGPT account quota and has been removed explicitly.

This ledger still atomically rejects duplicate job identities and tracks
observed input/output usage (cached input is already included in input),
conservatively estimating unknown/failed turns. It is NOT a provider quota
API, billing limit, source of authorization, or admission threshold.
The trusted executor separately requires ChatGPT login, two process slots
and a finite per-turn timeout before any provider call.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

LEVELS = frozenset({"low", "medium", "high"})
CHOICES = LEVELS | {"auto"}
RESERVATIONS = {"low": 12000, "medium": 35000, "high": 75000}
WINDOW_SECONDS = 24 * 3600
JOB_PATTERN = re.compile(r"[0-9]+-[0-9]+(?:-[12]|-p[2-8]-[12])?\Z")

# A task's topic is an imperfect estimate; no model difficulty is asserted
# without actual evidence. The Owner may override with low/medium/high.
HARD_SIGNALS = (
    "race condition", "corrida de dados", "concorrencia", "concorrência",
    "deadlock", "criptografia", "seguranca critica", "segurança crítica",
    "data migration", "migração da base", "migracao da base",
    "irreversible", "irreversível", "root cause", "causa raiz",
    "flaky integration", "falha intermitente", "complex regression",
    "regressão complexa", "bug dificil", "bug difícil",
)
LOW_SIGNALS = (
    "corrige um typo", "corrigir typo", "ortografia", "documentação",
    "documentacao", "readme", "renomear", "formatar", "formatting",
    "small typo", "fix typo", "update docs",
)
PROTECTED_SIGNALS = ("produção", "production", "credential", "secrets", "permiss", "governance")


class BudgetError(ValueError):
    pass


def choose_effort(task: dict) -> str:
    """Choose once *per bounded Codex turn*; next tasks may use a new level."""
    requested = task.get("reasoning_effort", "auto")
    if requested not in CHOICES:
        raise BudgetError("Unsupported Codex reasoning choice")
    if requested != "auto":
        return requested
    prompt = task["task"].casefold()
    if any(signal in prompt for signal in HARD_SIGNALS):
        return "high"
    if any(signal in prompt for signal in PROTECTED_SIGNALS):
        return "medium"  # don't equate a keyword with a proven hard task
    if len(prompt) <= 240 and any(signal in prompt for signal in LOW_SIGNALS):
        return "low"
    return "medium"


def _validate_key(key: str) -> None:
    if not isinstance(key, str) or not JOB_PATTERN.fullmatch(key):
        raise BudgetError("Invalid bounded Codex execution identifier")


def _validate_root(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise BudgetError("Unsafe Codex budget directory")
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise BudgetError("Codex budget directory must be private (0700)")


def _edit(root: Path, operation):
    """Atomic, locked read-modify-write; JSON never contains task text or keys."""
    _validate_root(root)
    lock_path = root / ".usage-budget.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise BudgetError("Unsafe Codex budget lock permissions")
        fcntl.flock(fd, fcntl.LOCK_EX)
        path = root / "usage-budget.json"
        if path.is_symlink():
            raise BudgetError("Unsafe token-ledger symlink")
        if path.exists():
            if path.stat().st_size > 128000 or stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise BudgetError("Invalid private token-ledger size or mode")
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = {"version": 1, "records": []}
        if data.get("version") != 1 or not isinstance(data.get("records"), list):
            raise BudgetError("Invalid token-ledger format")
        now = time.time()
        records = [
            r for r in data["records"]
            if isinstance(r, dict) and isinstance(r.get("started_at"), (float, int))
            and now - WINDOW_SECONDS < r["started_at"] <= now + 60
        ]
        if len(records) > 5000:
            raise BudgetError("Unbounded token-ledger records")
        data["records"] = records
        value = operation(data, now)
        tmp = root / ("usage-budget.tmp-" + str(os.getpid()))
        if tmp.exists() or tmp.is_symlink():
            raise BudgetError("Refusing ambiguous temporary ledger overwrite")
        try:
            create_fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(create_fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()
        return value
    finally:
        os.close(fd)


def reserve(root: Path, key: str, effort: str) -> dict:
    """Record a unique turn atomically, never infer account quota from tokens."""
    _validate_key(key)
    if effort not in LEVELS:
        raise BudgetError("Unsupported Codex effort; no model started")
    estimate = RESERVATIONS[effort]  # Accounting fallback, never a token cap.

    def operation(data, now):
        records = data["records"]
        if any(r.get("job") == key for r in records):
            raise BudgetError("Already reserved: do not replay an ambiguous Codex call")
        used = sum(int(r["actual"] if r.get("actual") is not None else r["reservation"])
                   for r in records)
        records.append({
            "job": key, "started_at": now, "effort": effort,
            "reservation": estimate, "actual": None, "observed": False,
        })
        return {"reserved": True, "effort": effort, "reserved_tokens": estimate,
                "tracked_24h_tokens_estimate": used + estimate,
                "quota_source": "provider_not_available_in_cli"}
    return _edit(Path(root), operation)


def settle(root: Path, key: str, usage: dict) -> dict:
    _validate_key(key)
    observed = usage.get("observed") is True
    if observed:
        fields = ("input_tokens", "output_tokens", "cached_input_tokens")
        if any(type(usage.get(f)) is not int or usage[f] < 0 for f in fields):
            raise BudgetError("Malformed observed token usage")
        if usage["cached_input_tokens"] > usage["input_tokens"]:
            raise BudgetError("Cached input cannot exceed total input")
        # Do NOT add cached input again: it is part of input_tokens.
        total = usage["input_tokens"] + usage["output_tokens"]
    else:
        total = None

    def operation(data, now):
        records = [r for r in data["records"] if r.get("job") == key]
        if len(records) != 1:
            raise BudgetError("No unique reservation to settle")
        record = records[0]
        if record.get("actual") is not None:
            return {"settled": True, "already_settled": True, "observed": record["observed"]}
        record["actual"] = total if observed else record["reservation"]
        record["observed"] = observed
        record["finished_at"] = now
        return {"settled": True, "observed": observed,
                "accounted_tokens": record["actual"]}
    return _edit(Path(root), operation)


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        raise BudgetError("Expected reserve ROOT JOB EFFORT or settle ROOT JOB USAGE_JSON")
    operation, root, key, argument = argv[1:5]
    if operation == "reserve":
        if len(argv) != 5:
            raise BudgetError("Unsupported reserve arguments")
        result = reserve(Path(root), key, argument)
    elif operation == "settle":
        if len(argv) != 5:
            raise BudgetError("Unsupported settle arguments")
        usage_path = Path(argument)
        if not usage_path.is_file() or usage_path.stat().st_size > 4096:
            usage = {"observed": False}
        else:
            usage = json.loads(usage_path.read_text(encoding="utf-8"))
        result = settle(Path(root), key, usage)
    else:
        raise BudgetError("Unknown Codex budget action")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (BudgetError, OSError, ValueError) as exc:
        print("CODEX_RESOURCE_POLICY_BLOCKED: " + str(exc), file=sys.stderr)
        raise SystemExit(4) from None
