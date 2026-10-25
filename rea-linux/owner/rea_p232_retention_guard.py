#!/usr/bin/env python3
"""P232: REA operator-side fail-closed guard for binary session lifecycle.

This is a LOCAL pre-sealing safety check, NOT a new MCP, server, policy
verifier, owner authorization, or replacement for the original REA bridge.
It never contacts the VPS or reads owner keys. It prevents accidental use of
open_binary/close_binary while original REA investigation retention P225/P230
is unresolved. There is intentionally no bypass command-line option.

Invoke BEFORE sealing a private inner batch:
    python3 rea_p232_retention_guard.py --request private-inner-batch.json

Result PASS means only "no binary-lifecycle step in this plan"; it does NOT
grant permission for workspace/sensitive actions or validate owner signatures.
"""
import argparse
import json
from pathlib import Path
import sys

PROTECTED_TOOLS = frozenset(("open_binary", "close_binary"))
MAX_STEPS = 12
HOLD_REASON = (
    "P225/P230: original REA close_binary clears global Evidence/Unknown "
    "records; six authentic P214 records were restored in P229. No safe "
    "provider lifecycle with durable retention has been certified."
)


class RetentionGuardError(ValueError):
    """Fail-closed validation or retention hold."""


def verify_private_inner_batch(request):
    """Check a *plaintext* batch before sealing; never accept sealed envelopes.

    Only a structural screen for dangerous provider lifecycle transitions.
    The original server's policy and Ed25519 verifier remain mandatory.
    """
    if not isinstance(request, dict) or set(request) != {
        "protocol", "nonce", "expires_at", "steps"
    } or request["protocol"] != 1:
        raise RetentionGuardError("invalid inner REA protocol or missing fields")
    steps = request["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise RetentionGuardError("invalid REA step count")
    names = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) not in (
            {"tool", "arguments"}, {"tool", "arguments", "authorization"}
        ):
            raise RetentionGuardError("invalid step structure at index " + str(index))
        name = step.get("tool")
        args = step.get("arguments")
        if not isinstance(name, str) or not name or not isinstance(args, dict):
            raise RetentionGuardError("invalid tool or argument object at step " + str(index))
        names.append(name)
    blocked = sorted(set(names).intersection(PROTECTED_TOOLS))
    if blocked:
        raise RetentionGuardError(
            "P232_RETENTION_HOLD: blocked binary lifecycle operation(s) "
            + ",".join(blocked) + "; " + HOLD_REASON
        )
    return {
        "status": "PASS_PRESEAL_BINARY_LIFECYCLE_HOLD",
        "steps_checked": len(steps),
        "session_lifecycle_steps": 0,
        "caveat": "Other REA policies and per-step authorizations still apply",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True,
                        help="Private local inner batch JSON, not an encrypted envelope")
    args = parser.parse_args(argv)
    try:
        if args.request.is_symlink() or not args.request.is_file():
            raise RetentionGuardError("request must be an ordinary local file")
        if args.request.stat().st_size > 512000:
            raise RetentionGuardError("request exceeds 512000-byte bound")
        body = json.loads(args.request.read_text(encoding="utf-8"))
        result = verify_private_inner_batch(body)
    except (OSError, UnicodeError, json.JSONDecodeError, RetentionGuardError) as exc:
        print("REA_P232_RETENTION_GUARD=BLOCK " + str(exc), file=sys.stderr)
        return 3
    print("REA_P232_RETENTION_GUARD=PASS " + json.dumps(
        result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
