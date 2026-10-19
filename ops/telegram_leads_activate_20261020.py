#!/usr/bin/env python3
"""One-shot guarded activation of Telegram Robot Leads for 2026-10-20 08:00 Europe/Lisbon."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

EXPECTED_SOURCE = "08ffc99ae8b14696bbfb84c5952173f28ea035d4"
DEST = Path("/opt/telegram-robot-leads")
VAULT = Path("/root/project-secrets/telegram-robot-leads")
STATE = Path("/var/lib/telegram-robot-leads")
TZ = ZoneInfo("Europe/Lisbon")
NOT_BEFORE = datetime(2026, 10, 20, 8, 0, tzinfo=TZ)
NOT_AFTER = datetime(2026, 10, 20, 22, 0, tzinfo=TZ)

class ActivationBlocked(RuntimeError):
    pass

def private(path: Path, directory=False):
    if path.is_symlink():
        raise ActivationBlocked("symlink_invalid")
    try:
        s = path.lstat()
    except OSError as exc:
        raise ActivationBlocked("required_path_missing") from exc
    if directory:
        ok = stat.S_ISDIR(s.st_mode)
    else:
        ok = stat.S_ISREG(s.st_mode)
    if not ok or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
        raise ActivationBlocked("protected_path_unsafe")

def verify_source():
    private(DEST, directory=True)
    marker = DEST / ".verified-source-commit"
    private(marker)
    if marker.read_text(encoding="ascii").strip() != EXPECTED_SOURCE:
        raise ActivationBlocked("source_revision_mismatch")
    if (DEST / ".git").exists() or (DEST / ".git").is_symlink():
        raise ActivationBlocked("live_git_history_present")
    if not (DEST / ".venv/bin/python").is_file():
        raise ActivationBlocked("runtime_python_missing")

def verify_vault():
    private(VAULT, directory=True)
    private(VAULT / ".env")
    private(VAULT / "accounts.json")
    sessions = list(VAULT.glob("*.session"))
    if len(sessions) != 2:
        raise ActivationBlocked("exactly_two_sessions_required")
    for path in sessions:
        private(path)

def verify_offline_sessions():
    proc = subprocess.run(
        [str(DEST / ".venv/bin/python"), str(DEST / "scripts/telethon_sessions.py"),
         "--vault", str(VAULT)],
        cwd=DEST, capture_output=True, text=True, timeout=30, check=False
    )
    if proc.returncode != 0:
        raise ActivationBlocked("session_offline_validation_failed")
    try:
        data = json.loads(proc.stdout)
    except ValueError as exc:
        raise ActivationBlocked("session_validation_output_invalid") from exc
    if data.get("status") != "SESSION_FILES_READABLE_NOT_ONLINE_VERIFIED":
        raise ActivationBlocked("session_validation_status_invalid")
    if data.get("accounts") != 2 or data.get("session_keys_present") != 2:
        raise ActivationBlocked("session_count_invalid")
    if data.get("api_source") not in {"private_app_credentials", "published_android_fallback"}:
        raise ActivationBlocked("api_source_invalid")
    return data.get("api_source")

def ensure_state():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(STATE, directory=True)

def current_pm2():
    proc = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=15)
    if proc.returncode != 0:
        raise ActivationBlocked("pm2_unavailable")
    try:
        rows = json.loads(proc.stdout)
    except ValueError as exc:
        raise ActivationBlocked("pm2_output_invalid") from exc
    if not isinstance(rows, list):
        raise ActivationBlocked("pm2_output_invalid")
    return rows

def activate():
    rows = current_pm2()
    for row in rows:
        if isinstance(row, dict) and row.get("name") == "telegram-robot-leads":
            status = row.get("pm2_env", {}).get("status")
            if status == "online":
                return "ALREADY_ONLINE"
            subprocess.run(["pm2", "delete", "telegram-robot-leads"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            break
    subprocess.run(
        ["pm2", "start", "ecosystem.config.js", "--only", "telegram-robot-leads", "--update-env"],
        cwd=DEST, timeout=30, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.run(["pm2", "save"], timeout=20, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = current_pm2()
    online = [
        row for row in rows
        if isinstance(row, dict) and row.get("name") == "telegram-robot-leads"
        and row.get("pm2_env", {}).get("status") == "online"
    ]
    if len(online) != 1:
        raise ActivationBlocked("pm2_worker_not_online")
    return "STARTED"

def main():
    if os.geteuid() != 0:
        raise ActivationBlocked("root_required")
    now = datetime.now(TZ)
    if now < NOT_BEFORE:
        raise ActivationBlocked("activation_too_early")
    if now >= NOT_AFTER:
        raise ActivationBlocked("activation_window_closed")
    verify_source()
    verify_vault()
    api_source = verify_offline_sessions()
    ensure_state()
    result = activate()
    print(json.dumps({
        "status": result,
        "source": EXPECTED_SOURCE,
        "api_source": api_source,
        "accounts": 2,
        "window": "2026-10-20T08:00/22:00 Europe/Lisbon",
        "other_projects_touched": False,
    }, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc) or type(exc).__name__},
                         sort_keys=True))
        sys.exit(2)
