#!/usr/bin/env python3
"""Owner-authorized VPS hygiene: audit and tightly scoped cache-only deletion.

The existing tested, trusted ops/vps_hygiene_050.py provides all path-based
inventory and file-descriptor-relative, symlink-safe removal operations.
This wrapper neither kills processes nor mutates app, Codex, DB or user data.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import time
import vps_hygiene_050 as h


PROTECTED = ("ssh", "nginx", "postgresql",
             "lowcost-europa.service", "pink-iptv-backend.service")
LOCKFILE = "/run/lock/codex-vps-safe-housekeeping.lock"


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
                    effect = h.remove_candidates(root, items)
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
