#!/usr/bin/env python3
"""Classify the Antigravity terminal screen without publishing its contents.

The screen may contain a one-time Google OAuth URL or account information:
NEVER print excerpts, hashes, URLs, environment or profile data.
"""
import re
import sys
from urllib.parse import urlsplit

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
URLS = re.compile(r"https://[^\s<>\"'\x1b]+")
MAX_BYTES = 120000


def screen_state(value: str) -> str:
    value = ANSI.sub("", value)
    low = value.lower()
    for raw in URLS.findall(value):
        try:
            link = urlsplit(raw.rstrip(".,;)]}"))
        except ValueError:
            continue
        if link.scheme == "https" and link.hostname in ("accounts.google.com", "antigravity.google", "antigravity.google.com"):
            if "oauth" in link.path.lower() or "authorize" in raw.lower() or "client_id=" in link.query:
                return "GOOGLE_AUTH_URL_PRESENT"
    if any(k in low for k in ("enter authorization code", "paste the authorization code", "authorization code:")):
        return "CODE_ENTRY_PROMPT"
    if any(k in low for k in ("could not connect to keyring", "keyring unavailable", "secret service not found", "dbus error", "no secret service")):
        return "KEYRING_ERROR"
    if ("google" in low and any(k in low for k in ("sign in", "log in", "login", "sign-in", "authenticate", "personal account"))) or "sign in to antigravity" in low:
        return "GOOGLE_SIGNIN_MENU"
    if "theme" in low and any(k in low for k in ("choose", "select", "color")):
        return "THEME_MENU"
    if any(k in low for k in ("workspace trust", "trust this", "trust folder")):
        return "TRUST_MENU"
    if any(k in low for k in ("permission denied", "terminal cannot", "fatal error", "connection refused")):
        return "STARTUP_ERROR"
    if len(value.strip()) < 5:
        return "EMPTY_SCREEN"
    if any(k in low for k in ("antigravity", "welcome", "press enter", "continue", "select")):
        return "OTHER_ONBOARDING_SCREEN"
    return "UNCLASSIFIED_TERMINAL"


if __name__ == "__main__":
    try:
        raw = sys.stdin.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            print("AGY_SCREEN=TOO_LARGE")
            raise SystemExit(2)
        print("AGY_SCREEN=" + screen_state(raw))
    except Exception:
        print("AGY_SCREEN=DIAGNOSIS_FAILED")
        raise SystemExit(2)
