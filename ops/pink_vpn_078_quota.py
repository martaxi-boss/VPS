"""Bounded reversible quota-only runtime transition. Never touches peers or DB."""

from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys

ENV = Path("/etc/pink-iptv/vpn.env")
ROOT = Path("/srv/pink-iptv/backend")
BACKUP = Path("/var/backups/pink-iptv/task078")
UNIT = "pink-iptv-backend"
TIMER = "pink-vpn-quota-078-rollback"
EXPECTED_BACKEND_VPN_SHA256 = "d2e73d88a65602fbbb51a5460dc4d3edab3b8f8da0d3e271e07fad12c775065a"  # pragma: allowlist secret - public code fingerprint
KEY = b"VPN_MAX_INSTALLATIONS_PER_ACCOUNT="


def run(*args: str) -> str:
    return subprocess.run(
        args, check=True, text=True, capture_output=True, timeout=35
    ).stdout.strip()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def desired(original: bytes) -> bytes:
    assert b"\x00" not in original and len(original) < 100_000
    assert not any(line.strip().startswith(KEY) for line in original.splitlines())
    suffix = b"" if not original or original.endswith(b"\n") else b"\n"
    return original + suffix + KEY + b"10\n"


def guarded_environment() -> tuple[bytes, os.stat_result]:
    assert os.geteuid() == 0
    assert run("hostname") == "vps-32bea5b6"
    assert run("systemctl", "is-active", UNIT) == "active"
    assert run("systemctl", "is-active", "pink-vpn") == "active"
    assert str(ENV) in run(
        "systemctl", "show", UNIT, "-p", "EnvironmentFiles", "--value"
    )
    assert ENV.is_file() and not ENV.is_symlink()
    source = ROOT / "app/vpn.py"
    assert source.is_file() and digest(source.read_bytes()) == EXPECTED_BACKEND_VPN_SHA256
    old = ENV.read_bytes()
    status = ENV.stat()
    assert stat.S_ISREG(status.st_mode)
    assert stat.S_IMODE(status.st_mode) & 0o077 == 0
    return old, status


def write_atomic(data: bytes, uid: int, gid: int, mode: int) -> None:
    temp = ENV.with_name("vpn.env.task078.next")
    assert not temp.exists()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        os.replace(temp, ENV)
    finally:
        if temp.exists():
            temp.unlink()


def process_has_expected_quota() -> bool:
    pid = int(run("systemctl", "show", UNIT, "-p", "MainPID", "--value"))
    assert pid > 0
    payload = Path(f"/proc/{pid}/environ").read_bytes()
    # Only boolean equality is evaluated; never emit process environments.
    return KEY + b"10" in payload.split(b"\x00")


def healthy() -> None:
    assert run("systemctl", "is-active", UNIT) == "active"
    assert run("systemctl", "is-active", "pink-vpn") == "active"
    assert run("curl", "--silent", "--show-error", "--output", "/dev/null",
               "--write-out", "%{http_code}", "--max-time", "8",
               "http://127.0.0.1:8010/openapi.json") == "200"


def inspect() -> None:
    old, _status = guarded_environment()
    assert KEY + b"10" not in old.splitlines()
    assert not any(line.startswith(KEY) for line in old.splitlines())
    assert not BACKUP.exists()
    assert re.search(r"vpn_max_installations_per_account\s*:\s*int\s*=\s*Field\(default=5",
                     (ROOT / "app/config.py").read_text())
    healthy()
    print("PINK078_READINESS_QUOTA_CHANGE_ONLY=PASS")


def apply() -> None:
    # No remote action begins without a precisely inspected baseline.
    inspect()
    old, status = guarded_environment()
    new = desired(old)
    assert BACKUP.parent.is_dir() and not BACKUP.parent.is_symlink()
    BACKUP.mkdir(mode=0o700)
    os.chmod(BACKUP, 0o700)
    (BACKUP / "baseline").write_bytes(old)
    os.chmod(BACKUP / "baseline", 0o600)
    metadata = {
        "original_sha256": digest(old), "new_sha256": digest(new),
        "uid": status.st_uid, "gid": status.st_gid,
        "mode": stat.S_IMODE(status.st_mode),
    }
    (BACKUP / "state.json").write_text(json.dumps(metadata))
    os.chmod(BACKUP / "state.json", 0o600)
    shutil.copy2(__file__, BACKUP / "quota.py")
    os.chmod(BACKUP / "quota.py", 0o600)
    # The rollback timer is armed BEFORE the change; it acts even if Actions dies.
    run("systemd-run", "--unit=" + TIMER, "--on-active=8m",
        "/usr/bin/python3", str(BACKUP / "quota.py"), "rollback")
    assert run("systemctl", "is-active", TIMER + ".timer") == "active"
    write_atomic(new, status.st_uid, status.st_gid, metadata["mode"])
    run("systemctl", "restart", UNIT)
    healthy()
    assert process_has_expected_quota()
    print("PINK078_TEMP_QUOTA10_AND_AUTO_ROLLBACK_ARMED=PASS")


def verify() -> None:
    assert BACKUP.is_dir() and not (BACKUP / "accepted").exists()
    state = json.loads((BACKUP / "state.json").read_text())
    assert digest(ENV.read_bytes()) == state["new_sha256"]
    healthy()
    assert process_has_expected_quota()
    assert run("systemctl", "is-active", TIMER + ".timer") == "active"
    print("PINK078_INDEPENDENT_QUOTA10_RUNTIME_VERIFIED=PASS")


def rollback() -> None:
    if not BACKUP.is_dir() or (BACKUP / "accepted").exists():
        return
    state = json.loads((BACKUP / "state.json").read_text())
    current = ENV.read_bytes()
    if digest(current) == state["original_sha256"]:
        print("PINK078_ROLLBACK_ALREADY_APPLIED=PASS")
        return
    assert digest(current) == state["new_sha256"]
    original = (BACKUP / "baseline").read_bytes()
    assert digest(original) == state["original_sha256"]
    write_atomic(original, state["uid"], state["gid"], state["mode"])
    run("systemctl", "restart", UNIT)
    healthy()
    assert not process_has_expected_quota()
    (BACKUP / "rolled-back").write_text("verified rollback\n")
    print("PINK078_EXACT_INVERSE_NO_DB_OR_PEER_CHANGES=PASS")


def accept() -> None:
    verify()
    (BACKUP / "accepted").write_text("accepted exact verified configuration\n")
    run("systemctl", "stop", TIMER + ".timer")
    print("PINK078_QUOTA10_ACCEPTED=PASS")


if __name__ == "__main__":
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ""
        operations = {
            "check": inspect, "apply": apply, "verify": verify,
            "rollback": rollback, "accept": accept,
        }
        assert action in operations
        operations[action]()
    except Exception:
        print("PINK078_TRANSITION_FAILED_REDACTED", flush=True)
        raise SystemExit(1)
