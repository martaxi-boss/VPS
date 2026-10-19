#!/usr/bin/env python3
"""Strictly scoped, idempotent staging of Telegram Robot Leads; never starts Telegram."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = "https://github.com/martaxi-boss/telegram-robot-leads.git"
PINNED = "8232551543a4dc8a703ddea3fe06f15a192e2948"
PREVIOUS_PINNED = "1f3e538301d01dbde7ef49ac7e0f41a761e85049"
PREVIOUS_CHECKOUT_BACKUP = Path("/opt/.telegram-leads-previous-1f3e538301d0")
DEST = Path("/opt/telegram-robot-leads")
VAULT = Path("/root/project-secrets/telegram-robot-leads")
STATE_DIR = Path("/var/lib/telegram-robot-leads")
BACKUP = VAULT / ".env.backup.pre-leads-hygiene-20261019"
LEGACY_PREFIXES = ("SCRAPE_", "MIN_ADDS_", "MAX_ADDS_")
OLD_KEYS = {"TELEGRAM_INVITES_ENABLED", "TELEGRAM_ACTIVE_MODE"}

class StageBlocked(RuntimeError):
    pass

def owned_private_directory(path):
    try:
        s = path.lstat()
    except OSError:
        raise StageBlocked("protected_directory_missing")
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
        raise StageBlocked("protected_directory_unsafe")

def private_file(path):
    try:
        s = path.lstat()
    except OSError:
        raise StageBlocked("protected_file_missing")
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
        raise StageBlocked("protected_file_unsafe")

def stale_key(line):
    if "=" not in line or line.lstrip().startswith("#"):
        return False
    key = line.split("=", 1)[0].strip().removeprefix("export ").strip()
    return key.startswith(LEGACY_PREFIXES) or key in OLD_KEYS

def validate_prerequisites():
    owned_private_directory(VAULT)
    env = VAULT / ".env"
    private_file(env)
    private_file(VAULT / "accounts.json")
    sessions = list(VAULT.glob("*.session"))
    if len(sessions) != 2:
        raise StageBlocked("existing_two_sessions_not_found")
    for path in sessions:
        private_file(path)
    if Path("/root/project-secrets/TELEGRAM-IPTVPN").exists() or Path("/root/TELEGRAM-IPTVPN").exists():
        raise StageBlocked("legacy_runtime_collision")
    if DEST.is_symlink() or STATE_DIR.is_symlink():
        raise StageBlocked("runtime_symlink_invalid")
    try:
        ps = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=12)
        if ps.returncode != 0:
            raise StageBlocked("pm2_unavailable")
        items = json.loads(ps.stdout)
        if not isinstance(items, list):
            raise StageBlocked("pm2_invalid")
        for entry in items:
            if isinstance(entry, dict) and entry.get("name") in {
                "TELEGRAM-IPTVPN", "telegram-robot-leads", "TELEGRAM-LEADS-METRICS"
            }:
                raise StageBlocked("leads_worker_already_exists")
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        raise StageBlocked("pm2_unavailable") from e
    return env

def run(cmd, *, cwd=None, timeout=120):
    subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=timeout, check=True)

def finalize_source_checkout(path):
    """Record exact source provenance and discard all git history from live checkout."""
    marker = path / ".verified-source-commit"
    gitdir = path / ".git"
    if marker.is_symlink() or gitdir.is_symlink():
        raise StageBlocked("provenance_symlink_invalid")
    if gitdir.exists():
        if not gitdir.is_dir():
            raise StageBlocked("source_git_metadata_invalid")
        try:
            actual = subprocess.check_output(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                text=True, timeout=8, stderr=subprocess.DEVNULL).strip()
        except (subprocess.SubprocessError, OSError) as exc:
            raise StageBlocked("source_commit_unverifiable") from exc
        if actual != PINNED:
            raise StageBlocked("source_commit_mismatch")
        if not marker.exists():
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as file:
                file.write(PINNED + "\n")
                file.flush()
                os.fsync(file.fileno())
        if marker.read_text(encoding="ascii").strip() != PINNED:
            raise StageBlocked("provenance_marker_mismatch")
        shutil.rmtree(gitdir)
        return True
    if not marker.is_file() or marker.read_text(encoding="ascii").strip() != PINNED:
        raise StageBlocked("source_provenance_missing")
    if marker.stat().st_uid != os.geteuid() or stat.S_IMODE(marker.stat().st_mode) & 0o077:
        raise StageBlocked("source_provenance_permissions_invalid")
    return False

def existing_checkout_revision():
    """Accept only a known previous staging or the exact current target.

    Never overwrite an unexpected installation or recover from a mismatched
    provenance marker by guessing. The vault is never part of the replacement.
    """
    if not DEST.exists():
        return None
    if not DEST.is_dir() or DEST.is_symlink():
        raise StageBlocked("runtime_path_collision")
    if not (DEST / ".venv/bin/python").is_file():
        raise StageBlocked("existing_runtime_unverified")
    marker = DEST / ".verified-source-commit"
    private_file(marker)
    if (DEST / ".git").exists() or (DEST / ".git").is_symlink():
        raise StageBlocked("live_checkout_history_present")
    revision = marker.read_text(encoding="ascii").strip()
    if revision not in (PINNED, PREVIOUS_PINNED):
        raise StageBlocked("unexpected_existing_source_commit")
    return revision


def stage_source():
    revision = existing_checkout_revision()
    if revision == PINNED:
        finalize_source_checkout(DEST)
        return False
    temp = Path(tempfile.mkdtemp(prefix=".telegram-leads-install-", dir="/opt"))
    try:
        run(["git", "clone", "--quiet", "--depth", "1", "--branch", "main", "--no-checkout", REPO, str(temp)], timeout=120)
        run(["git", "-C", str(temp), "checkout", "--quiet", "--detach", PINNED])
        head = subprocess.check_output(["git", "-C", str(temp), "rev-parse", "HEAD"],
                                       text=True, timeout=8).strip()
        if head != PINNED:
            raise StageBlocked("source_commit_mismatch")
        run(["python3", "-m", "venv", str(temp / ".venv")], timeout=60)
        python = temp / ".venv/bin/python"
        run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
             "--no-input", "-r", str(temp / "requirements.txt")], timeout=180)
        run([str(python), "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_*.py"], cwd=temp, timeout=120)
        finalize_source_checkout(temp)
        if revision is None:
            os.rename(temp, DEST)
        else:
            # Preserve the one verified previous version for recovery.
            # Never overwrite an existing backup or move protected vault files.
            if PREVIOUS_CHECKOUT_BACKUP.exists() or PREVIOUS_CHECKOUT_BACKUP.is_symlink():
                raise StageBlocked("previous_checkout_backup_already_exists")
            os.rename(DEST, PREVIOUS_CHECKOUT_BACKUP)
            try:
                os.rename(temp, DEST)
            except Exception:
                os.rename(PREVIOUS_CHECKOUT_BACKUP, DEST)
                raise
        return True
    finally:
        if temp.exists():
            shutil.rmtree(temp)

def clean_old_env(env):
    private_file(env)
    if BACKUP.exists() or BACKUP.is_symlink():
        private_file(BACKUP)
    data = env.read_bytes()
    if len(data) > 65536:
        raise StageBlocked("env_too_large")
    try:
        original = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StageBlocked("env_encoding_invalid") from exc
    lines = original.splitlines(keepends=True)
    removed = sum(stale_key(line) for line in lines)
    if removed == 0:
        return 0
    if not BACKUP.exists():
        fd = os.open(BACKUP, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    elif BACKUP.read_bytes() != data:
        # Fail rather than overwrite a prior backup or ambiguous user changes.
        raise StageBlocked("backup_exists_and_env_changed")
    content = "".join(line for line in lines if not stale_key(line))
    fd, name = tempfile.mkstemp(prefix=".env.hygiene-", dir=str(VAULT))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, env)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    private_file(env)
    return removed

def offline_session_source():
    """No Telegram network connection or exposure of API values."""
    try:
        report = subprocess.run(
            [str(DEST / ".venv/bin/python"), str(DEST / "scripts/telethon_sessions.py"),
             "--vault", str(VAULT)],
            cwd=DEST, capture_output=True, text=True, timeout=25, check=False)
        if report.returncode != 0:
            return "NOT_VERIFIED"
        value = json.loads(report.stdout).get("api_source")
        if value in ("private_app_credentials", "published_android_fallback"):
            return value
        return "NOT_VERIFIED"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "NOT_VERIFIED"

def main():
    if os.geteuid() != 0:
        raise StageBlocked("root_required")
    env = validate_prerequisites()
    created = stage_source()
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_private_directory(STATE_DIR)
    removed = clean_old_env(env)
    print(json.dumps({
        "status": "STAGED_NOT_STARTED",
        "pinned_source": PINNED,
        "installed_new_checkout": created,
        "previous_checkout_backup_preserved": PREVIOUS_CHECKOUT_BACKUP.is_dir(),
        "deprecated_config_lines_removed": removed,
        "backup_private": BACKUP.exists(),
        "state_directory_private": True,
        "source_provenance_recorded": (DEST / ".verified-source-commit").is_file(),
        "git_history_present_in_live_checkout": (DEST / ".git").exists(),
        "api_source": offline_session_source(),
        "telegram_actions": 0,
        "other_projects_touched": False
    }, sort_keys=True))
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": type(exc).__name__}, sort_keys=True))
        sys.exit(2)
