#!/usr/bin/env python3
"""Validate a Codex-generated change set before handing it back to GitHub.

Only called on disposable clones. This is a second guard, not a substitute
for sandboxing or reviewing the resulting PR.
"""
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_FILES = 40
MAX_PATCH_BYTES = 750_000
MAX_FILE_BYTES = 500_000
PROTECTED_PARTS = {".git", ".github", ".codex", ".ssh", ".project-leader", "__pycache__"}
PROTECTED_NAMES = {
    ".env", ".npmrc", ".pypirc", "auth.json", "config.toml",
    "codex-vps-remote.sh", "codex_patch_guard.py", "codex_sandbox_repair_ubuntu.sh",
    "codex-autonomous-remote.sh", "codex-autonomous-publish.py",
    "test_codex_autonomous.py", "telegram_gateway.py", "codex-project-leader-remote.sh",
}
PROTECTED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], stderr=subprocess.PIPE)


def guard_path(name: str) -> None:
    if not name or "\x00" in name or "\n" in name or "\r" in name:
        raise ValueError("Unsafe or empty filename")
    p = PurePosixPath(name)
    if (p.is_absolute() or any(part in {".", ".."} for part in p.parts)
            or any(part in PROTECTED_PARTS for part in p.parts)
            or p.name.lower() in PROTECTED_NAMES
            or p.suffix.lower() in PROTECTED_SUFFIXES):
        raise ValueError("Protected filename: " + name)
    if any(re.search(r"(token|credential|secret|private.key|passwd)", part, re.I)
           for part in p.parts):
        raise ValueError("Potential credential path: " + name)
    # Resolve existing path portions without following symlinks.
    cur = Path.cwd()
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("Symlink modification refused: " + name)
    if cur.is_file() and cur.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("File exceeds safe size: " + name)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: codex_patch_guard.py OUTPUT_PATCH")
    target = Path(sys.argv[1]).resolve()
    root = Path.cwd().resolve()
    if root in target.parents:
        raise SystemExit("Patch output must be outside the source checkout")
    if not (root / ".git").exists():
        raise SystemExit("Expected a fresh Git repository checkout")

    # Intent-to-add includes new, untracked files in the diff.
    subprocess.run(["git", "add", "-N", "--", "."], check=True)
    paths = [x.decode("utf-8", "strict") for x in
             git("diff", "--no-ext-diff", "--name-only", "-z").split(b"\0") if x]
    if len(paths) > MAX_FILES:
        raise ValueError("Too many modified files")
    for name in paths:
        guard_path(name)

    subprocess.run(["git", "diff", "--no-ext-diff", "--check"], check=True)
    patch = git("diff", "--no-ext-diff", "--binary")
    if len(patch) > MAX_PATCH_BYTES:
        raise ValueError("Patch exceeds safe size")
    target.write_bytes(patch)
    os.chmod(target, 0o600)
    print("CODEX_CHANGED_FILES=" + str(len(paths)))
    print("CODEX_PATCH_BYTES=" + str(len(patch)))
    print("CODEX_PATCH_STATE=" + ("CHANGED" if patch else "EMPTY"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as exc:
        print("PATCH_REJECTED: " + str(exc), file=sys.stderr)
        sys.exit(15)
