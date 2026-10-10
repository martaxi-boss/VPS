#!/usr/bin/env python3
"""Extract an official Google sign-in URL from private tmux pane text.

Never logs the source text or URL itself on errors. Caller must hand the result
only to the authenticated private recipient; never print it in Actions logs.
"""
import re
import sys
from urllib.parse import urlsplit, parse_qs

CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
URLS = re.compile(r"https://[^\s<>\"'\x1b]+")
MAX_CAPTURE = 40000


def login_url(screen: str) -> str:
    screen = CSI.sub("", screen[-MAX_CAPTURE:]).replace("\r", "")
    urls = []
    for item in URLS.findall(screen):
        value = item.rstrip(".,;)]}")
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme != "https" or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if host not in ("accounts.google.com", "antigravity.google", "antigravity.google.com") and not host.endswith(".accounts.google.com"):
            continue
        if host == "accounts.google.com" and ("oauth" in parsed.path or "client_id" in parse_qs(parsed.query)):
            urls.append((2, value))
        elif ("oauth" in value.lower() or "authorize" in value.lower()) and host in ("antigravity.google", "antigravity.google.com"):
            urls.append((1, value))
    if not urls:
        raise ValueError("No verified Google sign-in URL was detected")
    return sorted(urls, key=lambda item: item[0], reverse=True)[0][1]


if __name__ == "__main__":
    try:
        print(login_url(sys.stdin.read(MAX_CAPTURE + 1)))
    except ValueError:
        print("AGY_OAUTH_URL_NOT_READY", file=sys.stderr)
        raise SystemExit(2)
