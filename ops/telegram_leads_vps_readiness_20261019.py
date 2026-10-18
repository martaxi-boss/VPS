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


def account_and_credential_file_inventory():
    """Inspect existing protected files in memory; output only counts/booleans."""
    accounts_path = VAULT / "accounts.json"
    accounts_meta = descriptor(accounts_path)
    accounts = {"file_present": accounts_meta.get("present", False),
                "readable_privately": False}
    if (accounts_meta.get("file") and accounts_meta.get("private")
            and accounts_meta.get("root_owned")):
        try:
            if accounts_path.stat().st_size > 65536:
                raise ValueError("oversize")
            with accounts_path.open("r", encoding="utf-8") as stream:
                config = json.load(stream)
            if not isinstance(config, list):
                raise ValueError("invalid")
            accounts["readable_privately"] = True
            accounts["record_count"] = len(config)
            accounts["phone_fields_populated"] = sum(
                bool(re.fullmatch(r"\\+?[0-9\\s()\\-]{7,25}", str(entry.get("phone") or "")))
                for entry in config if isinstance(entry, dict)
            )
            accounts["session_files_paired"] = sum(
                bool(
                    isinstance(entry.get("session"), str)
                    and re.fullmatch(r"[A-Za-z0-9_-]{1,60}", entry["session"])
                    and descriptor(VAULT / (entry["session"] + ".session")).get("file")
                    and descriptor(VAULT / (entry["session"] + ".session")).get("private")
                ) for entry in config if isinstance(entry, dict)
            )
        except (OSError, UnicodeError, ValueError, TypeError):
            accounts["readable_privately"] = False

    # This module checks only the Leads vault, not unrelated applications' secrets.
    env_path = VAULT / ".env"
    env_meta = descriptor(env_path)
    credential_filename = "telegram_api.json"
    env_account_override = False
    if (env_meta.get("file") and env_meta.get("private") and env_meta.get("root_owned")):
        try:
            if env_path.stat().st_size > 65536:
                raise ValueError("env_oversize")
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                k, value = line.split("=", 1)
                key = k.strip().removeprefix("export ").strip()
                raw = value.strip()
                if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
                    raw = raw[1:-1]
                if key == "TELEGRAM_CREDENTIALS_FILE" and raw:
                    credential_filename = raw
                elif key == "TELEGRAM_ACCOUNTS_JSON" and raw:
                    env_account_override = True
        except (OSError, UnicodeError, ValueError):
            pass
    accounts["inline_accounts_override_present"] = env_account_override
    file_is_safe = bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", credential_filename))
    app_file = VAULT / credential_filename if file_is_safe else VAULT / "invalid"
    app_meta = descriptor(app_file) if file_is_safe else {"present": False}
    api_file = {
        "selected_filename_safe": file_is_safe,
        "file_present": app_meta.get("present", False),
        "file_private_root_owned": bool(app_meta.get("file") and
                                        app_meta.get("private") and
                                        app_meta.get("root_owned")),
        "private_api_pair_present": False,
        "known_public_android_pair": False,
    }
    if api_file["file_private_root_owned"]:
        try:
            if app_file.stat().st_size > 65536:
                raise ValueError("api_file_oversize")
            with app_file.open("r", encoding="utf-8") as stream:
                fields = json.load(stream)
            if isinstance(fields, dict):
                app_id = fields.get("api_id") or fields.get("TELEGRAM_API_ID")
                app_hash = fields.get("api_hash") or fields.get("TELEGRAM_API_HASH")
                try:
                    app_id = int(app_id)
                except (ValueError, TypeError):
                    app_id = 0
                hash_valid = isinstance(app_hash, str) and bool(
                    re.fullmatch(r"[0-9a-fA-F]{32}", app_hash))
                public_android = bool(
                    app_id == 4 and hash_valid and
                    app_hash.lower() == "014b35b6184100b085b0d0572f9b5103")
                api_file["known_public_android_pair"] = public_android
                api_file["private_api_pair_present"] = bool(
                    app_id > 0 and hash_valid and not public_android)
        except (OSError, UnicodeError, ValueError, TypeError):
            pass
    return {"accounts": accounts, "selected_application_file": api_file}


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
        "protected_existing_account_details": account_and_credential_file_inventory(),
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
