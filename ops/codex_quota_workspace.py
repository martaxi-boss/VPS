#!/usr/bin/env python3
"""Privately attest a Codex worktree when actual provider quota interrupts work.

Never publishes private patches, model logs, file names or GitHub credentials.
The intact isolated worktree stays in the Owner VPS until a new Owner order.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

JOB = re.compile(r"^[1-9][0-9]{0,15}-[1-9][0-9]{0,3}(?:-(?:[12]|p[2-8]-[12]))?$")
PROOF = "quota-workspace-proof.json"


class CheckpointError(RuntimeError):
    pass


def attest(base: Path, job: str) -> dict:
    if not JOB.fullmatch(job) or not base.is_absolute() or base.name != job:
        raise CheckpointError("QUOTA_WORKSPACE_ID_INVALID")
    if base.is_symlink() or not base.is_dir():
        raise CheckpointError("QUOTA_PRIVATE_DIRECTORY_MISSING")
    stat_info = base.stat()
    if stat_info.st_uid != os.getuid() or stat.S_IMODE(stat_info.st_mode) & 0o077:
        raise CheckpointError("QUOTA_WORKSPACE_NOT_PRIVATE")
    source = base / "codex-preflight-signal.txt"
    if (not source.is_file() or source.is_symlink() or
            source.stat().st_size > 64 or source.read_bytes() != b"CODEX_QUOTA_BLOCKED\n"):
        raise CheckpointError("PROVIDER_QUOTA_SIGNAL_UNVERIFIED")
    checkout = base / "repository"
    if (not checkout.is_dir() or checkout.is_symlink() or
            not (checkout / ".git").is_dir() or (checkout / ".git").is_symlink()):
        raise CheckpointError("QUOTA_WORKTREE_UNAVAILABLE")
    try:
        rev = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                             text=True, capture_output=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise CheckpointError("QUOTA_GIT_REVISION_UNVERIFIED") from None
    sha = rev.stdout.strip()
    if rev.returncode != 0 or not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise CheckpointError("QUOTA_GIT_REVISION_UNVERIFIED")
    # A stored worktree includes tracked AND untracked changes. A diff alone
    # would discard new files, so no patch or automatic publication occurs.
    result = {"version": 1, "job": job, "private_worktree": True,
              "base_sha": sha, "source": "authenticated_codex_provider_error",
              "owner_resumption": "NEW_OWNER_ORDER_REQUIRED"}
    proof = base / PROOF
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(proof), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    except (OSError, ValueError):
        raise CheckpointError("QUOTA_PROOF_NOT_WRITTEN") from None
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] != "secure":
        return 2
    try:
        result = attest(Path(argv[2]), argv[3])
        print("QUOTA_PRIVATE_WORKTREE=RETAINED_" + result["job"])
        return 0
    except CheckpointError as exc:
        # The caller must still KEEP the original worktree on the VPS, even
        # when proof failed; a later Owner-authorized repair may recover it.
        print("QUOTA_PRIVATE_WORKTREE=NOT_ATTESTED_" + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
