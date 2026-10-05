"""Bounded OVH maintenance: inspect first; remove only audited stale cache files."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

TASK_ID = "VPS-SAFE-HYGIENE-050"
CACHE_ROOTS = (
    "/var/cache/apt/archives", "/root/.cache/pip", "/home/ubuntu/.cache/pip",
    "/root/.npm/_cacache", "/home/ubuntu/.npm/_cacache",
)
CRITICAL = ("ssh", "nginx", "postgresql", "lowcost-europa.service", "pink-iptv-backend.service")
MAX_ENTRIES = 100000
MIN_AGE_SECONDS = 86400


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""


def metadata(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_blocks]


def cache_inventory(root, cutoff_ns):
    if root not in CACHE_ROOTS:
        raise ValueError("Root is outside the fixed cache allowlist")
    path = Path(root)
    if not path.exists():
        return {"root": root, "present": False, "files": 0, "bytes": 0, "eligible_bytes": 0,
                "eligible_allocated_bytes": 0, "eligible_files": 0, "signature": canonical_hash([])}, []
    if path.is_symlink() or str(path.resolve()) != root or not path.is_dir():
        raise ValueError("Cache root has a symlink or unsupported type")
    device = path.stat().st_dev
    eligible, count, total = [], 0, 0
    def fail(error):
        raise error
    for current, dirs, files in os.walk(path, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink()
                         and (Path(current) / d).stat().st_dev == device
                         and not (root == CACHE_ROOTS[0] and d == "partial"))
        for name in sorted(files):
            p = Path(current) / name
            s = p.lstat()
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("Cache inventory limit exceeded; no broad deletion authorized")
            if not stat.S_ISREG(s.st_mode) or s.st_dev != device or s.st_nlink != 1:
                continue
            total += s.st_size
            if root == CACHE_ROOTS[0] and not name.endswith(".deb"):
                continue
            if s.st_mtime_ns >= cutoff_ns:
                continue
            eligible.append([str(p.relative_to(path)), metadata(s)])
    eligible.sort()
    return {"root": root, "present": True, "files": count, "bytes": total,
            "eligible_bytes": sum(x[1][2] for x in eligible),
            "eligible_allocated_bytes": sum(x[1][5] * 512 for x in eligible),
            "eligible_files": len(eligible), "signature": canonical_hash(eligible)}, eligible


def remove_candidates(root, entries):
    if root not in CACHE_ROOTS or str(Path(root).resolve()) != root:
        raise ValueError("Unsafe root")
    removed, allocated, skipped = 0, 0, 0
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for relative, expected in entries:
            parts = Path(relative).parts
            if not parts or Path(relative).is_absolute() or any(p in (".", "..") for p in parts):
                raise ValueError("Unsafe relative cache path")
            fd = os.dup(root_fd)
            try:
                for part in parts[:-1]:
                    new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = new_fd
                s = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or metadata(s) != expected:
                    skipped += 1
                    continue
                os.unlink(parts[-1], dir_fd=fd)
                removed += s.st_size
                allocated += s.st_blocks * 512
            except (FileNotFoundError, NotADirectoryError, OSError):
                skipped += 1
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)
    return {"bytes_removed": removed, "allocated_bytes_removed": allocated, "changed_or_unsafe_files_preserved": skipped}


def package_busy():
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal():
            continue
        try:
            comm = (p / "comm").read_text().strip()
        except OSError:
            continue
        if comm in ("apt", "apt-get", "dpkg", "unattended-upgr") or comm.startswith(("pip", "npm")):
            return True
    locks = ["/var/lib/dpkg/lock", "/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock"]
    return any(command(["fuser", p], timeout=3)[0] == 0 for p in locks if Path(p).exists())


def snapshot(cutoff_ns):
    critical = {s: command(["systemctl", "is-active", s])[1] for s in CRITICAL}
    rc, units = command(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"])
    running = [line.split()[0] for line in units.splitlines() if line.split()]
    lowcost = "lowcost-europa.146-59-145-3.sslip.io"
    checks = {
        "nginx_config_ok": command(["nginx", "-t"])[0] == 0,
        "postgres_ready": command(["pg_isready", "-q"])[0] == 0,
        "lowcost_https": command(["curl", "--noproxy", "*", "--resolve", lowcost + ":443:127.0.0.1",
                                  "--max-time", "10", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://" + lowcost + "/"])[1],
        "pink_openapi": command(["curl", "--noproxy", "*", "--max-time", "10", "-sS", "-o", "/dev/null",
                                 "-w", "%{http_code}", "http://127.0.0.1:8010/openapi.json"])[1],
    }
    ufw_rc, ufw = command(["ufw", "status"])
    directories = {}
    for p in ("/var/log", "/var/cache", "/tmp", "/home", "/opt", "/srv", "/var/backups"):
        code, output = command(["du", "-sx", "-B1", p], timeout=20)
        directories[p] = int(output.split()[0]) if code == 0 and output.split() and output.split()[0].isdigit() else None
    cache = [cache_inventory(p, cutoff_ns)[0] for p in CACHE_ROOTS]
    residue_paths = (
        "/opt/martaxi-commander", "/etc/martaxi-commander", "/usr/local/bin/martaxi-commander-mcp",
        "/usr/local/bin/tunnel-client", "/etc/nginx/openai-mtls",
        "/usr/lib/node_modules/@wonderwhy-er/desktop-commander",
        "/usr/local/lib/node_modules/@wonderwhy-er/desktop-commander",
    )
    _, runner_units = command(["systemctl", "list-unit-files", "actions.runner.*.service", "--no-legend"])
    _, dc_units = command(["systemctl", "list-unit-files", "desktop-commander-remote.service", "--no-legend"])
    _, commander_units = command(["systemctl", "list-unit-files", "martaxi-commander*.service", "--no-legend"])
    d = shutil.disk_usage("/")
    return {"observed_at_epoch": time.time(), "hostname": os.uname().nodename, "cutoff_ns": cutoff_ns,
            "disk": {"total": d.total, "used": d.used, "free": d.free}, "critical_services": critical,
            "running_services": sorted(running), "checks": checks, "package_manager_busy": package_busy(),
            "firewall": {"readable": ufw_rc == 0, "active": ufw.startswith("Status: active"), "sha256": hashlib.sha256(ufw.encode()).hexdigest()},
            "directory_bytes": directories, "caches": cache,
            "legacy_tooling": {"existing_paths": [p for p in residue_paths if os.path.lexists(p)],
                               "runner_unit_names": [x.split()[0] for x in runner_units.splitlines() if x.split()],
                               "desktop_commander_unit_names": [x.split()[0] for x in dc_units.splitlines() if x.split()],
                               "commander_unit_names": [x.split()[0] for x in commander_units.splitlines() if x.split()]},
            "health": "PASS" if all(v == "active" for v in critical.values()) and checks["nginx_config_ok"]
                      and checks["postgres_ready"] and checks["lowcost_https"] == "200" and checks["pink_openapi"] == "200" else "REVIEW"}


def validate_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("Missing exact cleanup authorization")
    auth, manifest = payload["authorization"], payload["manifest"]
    if auth["task_id"] != TASK_ID or auth["repository"] != "martaxi-boss/VPS" or auth["action"] != "destructive_data_change":
        raise ValueError("Wrong cleanup authority")
    if auth["authority"]["source"] != "CURRENT_OWNER_INSTRUCTION" or auth["authority"]["binding_mode"] != "EXACT_REVISION_BOUND":
        raise ValueError("Unbound cleanup authority")
    if auth["target"]["kind"] != "vps_cache_manifest" or auth["target"]["identifier"] != "146.59.145.3":
        raise ValueError("Wrong VPS target")
    if auth["target"]["revision"] != manifest["audited_implementation_sha"]:
        raise ValueError("Wrong implementation binding")
    if "manifest_sha256=" + canonical_hash(manifest) not in auth["authority"]["summary"]:
        raise ValueError("Manifest digest mismatch")
    if manifest["host"] != "146.59.145.3" or manifest["cache_roots"] != list(CACHE_ROOTS):
        raise ValueError("Cache allowlist mismatch")
    if manifest["audit"]["cutoff_ns"] > time.time_ns() - MIN_AGE_SECONDS * 1000000000:
        raise ValueError("Unsafe cache age threshold")
    return manifest


def cleanup(payload):
    manifest = validate_payload(payload)
    audit = manifest["audit"]
    lock = os.open("/run/lock/project-leader-vps-hygiene-050.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(audit["cutoff_ns"])
        if before["hostname"] != audit["hostname"] or before["health"] != "PASS":
            raise ValueError("VPS identity or health changed; no cleanup performed")
        if before["package_manager_busy"]:
            raise ValueError("Package operation active; no cleanup performed")
        if before["critical_services"] != audit["critical_services"] or before["firewall"] != audit["firewall"]:
            raise ValueError("Protected baseline changed; no cleanup performed")
        # Validate every root before deleting the first file.
        candidates = []
        for root, expected in zip(CACHE_ROOTS, audit["caches"]):
            observed, entries = cache_inventory(root, audit["cutoff_ns"])
            if observed["root"] != expected["root"] or observed["signature"] != expected["signature"]:
                raise ValueError("Audited cache candidates changed; no cleanup performed")
            candidates.append((root, entries))
        effects = [{"root": root, **remove_candidates(root, entries)} for root, entries in candidates if entries]
        after = snapshot(audit["cutoff_ns"])
        healthy = after["health"] == "PASS" and after["critical_services"] == before["critical_services"] and after["firewall"] == before["firewall"]
        report = {"task_id": TASK_ID, "mode": "cleanup", "before": before, "after": after, "effects": effects,
                  "allocated_bytes_removed": sum(x["allocated_bytes_removed"] for x in effects),
                  "file_bytes_removed": sum(x["bytes_removed"] for x in effects),
                  "disk_free_delta": after["disk"]["free"] - before["disk"]["free"], "protected_health": "PASS" if healthy else "FAIL"}
        print("CLEANUP_JSON=" + json.dumps(report, sort_keys=True), flush=True)
        if not healthy:
            raise ValueError("Post-cleanup health needs bounded diagnosis; do not repeat deletion")
    finally:
        os.close(lock)


def main():
    if os.geteuid() != 0:
        raise ValueError("Audited sudo access required")
    mode = sys.argv[1] if len(sys.argv) > 1 else "audit"
    if mode == "audit":
        cutoff = time.time_ns() - MIN_AGE_SECONDS * 1000000000
        print("AUDIT_JSON=" + json.dumps(snapshot(cutoff), sort_keys=True), flush=True)
    elif mode == "cleanup":
        cleanup(globals().get("CONTROL_PAYLOAD"))
    else:
        raise ValueError("Unsupported operation")


if __name__ == "__main__":
    main()
