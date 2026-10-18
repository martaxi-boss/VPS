#!/usr/bin/env python3
"""Bounded read-only VPS inventory of Telegram Robot Leads (no Telegram calls)."""
import json
import os
import re
from pathlib import Path
import stat
import subprocess

VAULT = Path("/root/project-secrets/telegram-robot-leads")
LEGACY_VAULT = Path("/root/project-secrets/TELEGRAM-IPTVPN")
NEW_CHECKOUT = Path("/opt/telegram-robot-leads")
LEGACY_CHECKOUT = Path("/root/TELEGRAM-IPTVPN")
METRICS = Path("/opt/telegram-leads-optin")
STATE = Path("/var/lib/telegram-robot-leads/operation-state.json")

def descriptor(path):
    try:
        obj = path.lstat()
    except FileNotFoundError:
        return {"present": False}
    except OSError:
        return {"present": False, "unreadable": True}
    if stat.S_ISLNK(obj.st_mode):
        return {"present": True, "symlink": True}
    return {
        "present": True, "symlink": False,
        "directory": stat.S_ISDIR(obj.st_mode),
        "file": stat.S_ISREG(obj.st_mode),
        "private": (stat.S_IMODE(obj.st_mode) & 0o077) == 0,
        "root_owned": obj.st_uid == 0,
    }

def safe_keys(path):
    """Read protected configuration, returning booleans only; never expose values."""
    info = descriptor(path)
    if not (info.get("file") and info.get("private") and info.get("root_owned")):
        return {"present": info.get("present", False), "private": False}
    try:
        with open(path, encoding="utf-8") as file:
            data = file.read(65537)
        if len(data) > 65536:
            return {"present": True, "private": True, "readable": False}
        keys = set()
        selected = {}
        allowed = {"TELEGRAM_API_ID", "API_ID", "TELEGRAM_API_HASH", "API_HASH",
                   "TELEGRAM_USE_PUBLISHED_ANDROID_API"}
        for line in data.splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            k, value = line.split("=", 1)
            k = k.strip().removeprefix("export ").strip()
            if not k.isidentifier():
                continue
            keys.add(k)
            if k in allowed:
                value = value.strip()
                if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                    value = value[1:-1]
                selected[k] = value
        raw_id = selected.get("TELEGRAM_API_ID") or selected.get("API_ID") or ""
        raw_hash = selected.get("TELEGRAM_API_HASH") or selected.get("API_HASH") or ""
        try:
            app_id = int(raw_id)
        except (ValueError, TypeError):
            app_id = 0
        app_hash_valid = bool(re.fullmatch(r"[a-fA-F0-9]{32}", raw_hash))
        is_public_android = app_id == 4 and raw_hash.lower() == "014b35b6184100b085b0d0572f9b5103"
        candidate_private = app_id > 0 and app_hash_valid and not is_public_android
        force_public = selected.get("TELEGRAM_USE_PUBLISHED_ANDROID_API", "").lower() in {
            "1", "true", "on", "yes"
        }
        return {
            "present": True, "private": True, "readable": True,
            "api_id_key_present": bool(keys.intersection({"API_ID", "TELEGRAM_API_ID"})),
            "api_hash_key_present": bool(keys.intersection({"API_HASH", "TELEGRAM_API_HASH"})),
            "group_key_present": bool(keys.intersection({"TARGET_GROUP", "TELEGRAM_GROUP"})),
            "old_scraping_config_key_count": sum(k.startswith(("SCRAPE_", "MIN_ADDS_", "MAX_ADDS_")) for k in keys),
            "published_android_override_active": force_public,
            "api_pair_valid_and_not_known_android_public": candidate_private,
            "api_pair_is_known_public_android": is_public_android,
        }
    except (OSError, UnicodeError):
        return {"present": True, "private": True, "readable": False}

def pm2_snapshot():
    try:
        p = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=10, check=False)
        if p.returncode != 0:
            return {"available": False}
        items = json.loads(p.stdout)
        if not isinstance(items, list):
            return {"available": False}
        result = {}
        for key in ("telegram-robot-leads", "TELEGRAM-IPTVPN", "TELEGRAM-LEADS-METRICS"):
            matches = [v for v in items if isinstance(v, dict) and v.get("name") == key]
            result[key] = {
                "count": len(matches),
                "online": sum(v.get("pm2_env", {}).get("status") == "online" for v in matches
                              if isinstance(v.get("pm2_env"), dict)),
            }
        return {"available": True, "processes": result}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"available": False}

def main():
    vault = descriptor(VAULT)
    sessions = 0
    sessions_private = True
    if vault.get("directory") and vault.get("private") and vault.get("root_owned"):
        try:
            for path in VAULT.iterdir():
                if path.name.endswith(".session"):
                    sessions += 1
                    p = descriptor(path)
                    sessions_private = sessions_private and bool(p.get("file") and p.get("private") and p.get("root_owned"))
        except OSError:
            sessions_private = False
    report = {
        "probe": "LEADS_VPS_READ_ONLY_20261019",
        "side_effects": False,
        "vault": vault,
        "account_config": descriptor(VAULT / "accounts.json"),
        "credentials": safe_keys(VAULT / ".env"),
        "session_count": sessions,
        "sessions_private": sessions_private,
        "legacy_vault": descriptor(LEGACY_VAULT),
        "new_runtime": descriptor(NEW_CHECKOUT),
        "new_main_py": descriptor(NEW_CHECKOUT / "main.py"),
        "new_safe_runtime": descriptor(NEW_CHECKOUT / "scripts/safe_runtime.py"),
        "new_venv_python": descriptor(NEW_CHECKOUT / ".venv/bin/python"),
        "legacy_runtime": descriptor(LEGACY_CHECKOUT),
        "optin_metrics_staging": descriptor(METRICS),
        "operation_state": descriptor(STATE),
        "pm2": pm2_snapshot(),
    }
    print(json.dumps(report, sort_keys=True))
if __name__ == "__main__":
    main()
