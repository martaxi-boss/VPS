#!/usr/bin/env python3
"""Owner-authorized VPS hygiene: audit and tightly scoped cache-only deletion.

The existing tested, trusted ops/vps_hygiene_050.py provides all path-based
inventory and file-descriptor-relative, symlink-safe removal operations.
This wrapper neither kills processes nor mutates app, Codex, DB or user data.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import time
import vps_hygiene_050 as h


PROTECTED = ("ssh", "nginx", "postgresql",
             "lowcost-europa.service", "pink-iptv-backend.service")
LOCKFILE = "/run/lock/codex-vps-safe-housekeeping.lock"



def _restore_no_replace(private_fd: int, stage: str,
                        original_fd: int, name: str) -> bool:
    """Never overwrite a new shared cache entry during a failed restore.

    renameat2(RENAME_NOREPLACE) is mandatory. Do not silently downgrade
    to os.rename, which would overwrite another producer's current file.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "atomic no-replace rename unavailable")
    renameat2.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    outcome = renameat2(private_fd, os.fsencode(stage),
                        original_fd, os.fsencode(name), 1)
    if outcome == 0:
        return True
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        return False
    raise OSError(error, "atomic recovery rename failed")


def _quarantined_verified_removal(root: str, entries: list) -> dict:
    """Move only a prescanned cache candidate into a private same-FS area.

    Validate the exact MOVED inode, then unlink only the private path.
    An atomic swap of the shared final name can never cause the replacement
    file to be unlinked. If the moved object does not match, restore it
    with RENAME_NOREPLACE; otherwise preserve it privately for recovery.
    """
    if root not in h.CACHE_ROOTS or str(Path(root).resolve()) != root:
        raise ValueError("Untrusted cache root")
    total_removed, allocated_removed, skipped, stranded = 0, 0, 0, 0
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    quarantine = ".vps-hygiene-" + secrets.token_hex(12)
    quarantine_fd = None
    try:
        os.mkdir(quarantine, mode=0o700, dir_fd=root_fd)
        quarantine_fd = os.open(
            quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd)
        for index, (relative, expected) in enumerate(entries):
            parts = Path(relative).parts
            if (not parts or Path(relative).is_absolute()
                    or any(p in (".", "..") for p in parts)):
                raise ValueError("Unsafe relative cache path")
            parent_fd = os.dup(root_fd)
            try:
                for part in parts[:-1]:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                      os.O_NOFOLLOW, dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = next_fd
                name = parts[-1]
                try:
                    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except (FileNotFoundError, NotADirectoryError):
                    skipped += 1
                    continue
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or h.metadata(before) != expected):
                    skipped += 1
                    continue
                stage = "candidate-" + str(index) + "-" + secrets.token_hex(6)
                try:
                    os.rename(name, stage, src_dir_fd=parent_fd,
                              dst_dir_fd=quarantine_fd)
                except (FileNotFoundError, NotADirectoryError):
                    skipped += 1
                    continue
                moved = os.stat(stage, dir_fd=quarantine_fd,
                                follow_symlinks=False)
                # Rename can update ctime; compare stable identity and content
                # metadata instead, after the atomic removal from shared path.
                matches = (
                    stat.S_ISREG(moved.st_mode) and moved.st_nlink == 1
                    and moved.st_dev == before.st_dev
                    and moved.st_ino == expected[1]
                    and moved.st_size == expected[2]
                    and moved.st_mtime_ns == expected[3]
                    and moved.st_blocks == expected[5]
                    and moved.st_mtime_ns < (
                        time.time_ns() - h.MIN_AGE_SECONDS * 1_000_000_000)
                )
                if not matches:
                    skipped += 1
                    if not _restore_no_replace(quarantine_fd, stage,
                                               parent_fd, name):
                        stranded += 1
                    continue
                # Final deletion acts on a path in the private, root-owned
                # quarantine directory, never on the shared cache final name.
                os.unlink(stage, dir_fd=quarantine_fd)
                total_removed += moved.st_size
                allocated_removed += moved.st_blocks * 512
            finally:
                os.close(parent_fd)
    finally:
        if quarantine_fd is not None:
            os.close(quarantine_fd)
        try:
            os.rmdir(quarantine, dir_fd=root_fd)
        except OSError:
            # A mismatched active object stays in private quarantine to
            # prevent deletion; the outer post-check fails closed.
            stranded += 1
        os.close(root_fd)
    return {
        "bytes_removed": total_removed,
        "allocated_bytes_removed": allocated_removed,
        "changed_or_unsafe_files_preserved": skipped,
        "quarantined_for_recovery": stranded,
    }


def _mem_available_bytes() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            value = line.split()
            return int(value[1]) * 1024
    return 0


def _services() -> dict[str, str]:
    return {name: h.command(["systemctl", "is-active", name], timeout=8)[1]
            for name in PROTECTED}


def _readiness(services: dict[str, str]) -> bool:
    # Never alter caches when the critical VPS access/proxy services are failing.
    return (services.get("ssh") == "active"
            and services.get("nginx") == "active"
            and h.command(["nginx", "-t"], timeout=10)[0] == 0)


def run(mode: str) -> dict:
    if mode not in {"audit", "clean"}:
        raise ValueError("Owner mode must be audit or clean")
    if os.geteuid() != 0:
        raise ValueError("Sudo required; never attempt unprivileged deletion")
    lock_fd = os.open(LOCKFILE, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cutoff = time.time_ns() - h.MIN_AGE_SECONDS * 1_000_000_000
        before_disk = shutil.disk_usage("/")
        before_mem = _mem_available_bytes()
        before_services = _services()
        ready = _readiness(before_services)
        busy = h.package_busy()
        refs = h.cache_open_references()
        summaries, candidates = [], []
        # Build a complete bounded snapshot before the first possible unlink.
        for root in h.CACHE_ROOTS:
            stats, items = h.cache_inventory(root, cutoff)
            summaries.append({"root": root, "files": stats["files"],
                              "eligible_files": stats["eligible_files"],
                              "eligible_allocated_bytes": stats["eligible_allocated_bytes"]})
            candidates.append((root, stats["signature"], items))
        eligible_files = sum(x["eligible_files"] for x in summaries)
        eligible_allocated = sum(x["eligible_allocated_bytes"] for x in summaries)

        # Failed/no-op preconditions remain explicit, never pretend "cleaned".
        if not ready:
            status = "BLOCKED_CRITICAL_HEALTH"
        elif busy:
            status = "BLOCKED_PACKAGE_MANAGER"
        elif any(refs.values()):
            status = "BLOCKED_OPEN_CACHE_REFERENCES"
        elif mode == "audit":
            status = "AUDIT_ONLY"
        elif not eligible_files:
            status = "NO_ELIGIBLE_CACHE"
        else:
            status = "CLEANED"
        removed_files = 0
        removed_allocated = 0
        changed_preserved = 0

        if status == "CLEANED":
            # Re-read every candidate signature before deleting a single entry.
            for root, expected_sig, _ in candidates:
                observed, _ = h.cache_inventory(root, cutoff)
                if observed["signature"] != expected_sig:
                    status = "BLOCKED_CACHE_CHANGED"
                    break
            if status == "CLEANED":
                for root, _, items in candidates:
                    if not items:
                        continue
                    effect = _quarantined_verified_removal(root, items)
                    if effect["quarantined_for_recovery"]:
                        status = "BLOCKED_QUARANTINE_RECOVERY"
                    removed_files += effect["bytes_removed"]
                    removed_allocated += effect["allocated_bytes_removed"]
                    changed_preserved += effect["changed_or_unsafe_files_preserved"]

        after_disk = shutil.disk_usage("/")
        after_mem = _mem_available_bytes()
        after_services = _services()
        protected_unchanged = before_services == after_services
        health_after = _readiness(after_services)
        if not protected_unchanged or (ready and not health_after):
            status = "POSTCHECK_HEALTH_CHANGED"

        return {
            "status": status, "mode": mode,
            "disk_total": before_disk.total,
            "disk_free_before": before_disk.free,
            "disk_free_after": after_disk.free,
            "disk_free_delta": after_disk.free - before_disk.free,
            "memory_available_before": before_mem,
            "memory_available_after": after_mem,
            "cache_roots_checked": len(summaries),
            "eligible_files": eligible_files,
            "eligible_allocated_bytes": eligible_allocated,
            "removed_file_bytes": removed_files,
            "removed_allocated_bytes": removed_allocated,
            "changed_or_unsafe_preserved": changed_preserved,
            "root_candidates": summaries,
            "protected_services_before": before_services,
            "protected_services_after": after_services,
            "protected_services_unchanged": protected_unchanged,
            "health_after": health_after,
            "package_manager_busy": busy,
            "cache_open_reference_count": sum(refs.values()),
            "runtime_sessions_deleted": 0,
            "app_or_database_data_deleted": 0,
        }
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        result = run(sys.argv[1] if len(sys.argv) > 1 else "audit")
        # No paths other than known, fixed cache roots; never emit file names.
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        if result["status"].startswith("BLOCKED_") or result["status"] == "POSTCHECK_HEALTH_CHANGED":
            sys.exit(3)
    except Exception:
        # Exception messages may contain private filenames; do not print them.
        print(json.dumps({"status": "SAFE_HYGIENE_FAILED", "mode": "unknown"}))
        sys.exit(3)
