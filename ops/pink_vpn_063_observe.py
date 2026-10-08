"""Privacy-preserving, strictly read-only observation of live PINK enrollment.

This code runs over the existing approved SSH channel and MUST NOT print
journal lines, service configuration, account data, device identities or IPs.
Only fixed service booleans and endpoint/status aggregate counts are emitted.
"""
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
import base64
import json
import os
import re
import socket
import stat
import subprocess
import urllib.error
import urllib.request


EXPECTED_HOST = "vps-32bea5b6"
ENDPOINTS = {
    "/v1/session/resolve": "SESSION",
    "/v1/vpn/enroll": "ENROLL",
    "/v1/vpn/refresh": "REFRESH",
}
WINDOWS = {
    # Portugal daylight saving in October: 18:04 and 19:05 local = 17:04/18:05 UTC.
    "FIRST_DEVICE_1804": ("2026-10-08 16:59:00 UTC", "2026-10-08 17:14:00 UTC"),
    "SECOND_DEVICE_1905": ("2026-10-08 17:59:00 UTC", "2026-10-08 18:16:00 UTC"),
}
HTTP_PATTERN = re.compile(
    r'"POST (/v1/session/resolve|/v1/vpn/enroll|/v1/vpn/refresh) HTTP/1\.[01]" ([1-5][0-9]{2})(?:\s|$)'
)


def aggregated_statuses(lines):
    counts = Counter()
    for line in lines:
        match = HTTP_PATTERN.search(line)
        if match:
            counts[ENDPOINTS[match[1]] + "_" + match[2]] += 1
    return dict(sorted(counts.items()))


def cmd(*argv, timeout=15):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, timeout=timeout).stdout.strip()


def service_ok(name):
    return subprocess.run(["systemctl", "is-active", "--quiet", name],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0


def observe():
    assert os.geteuid() == 0 and cmd("hostname") == EXPECTED_HOST
    print("PINK063_REMOTE_READ_ONLY=PASS", flush=True)
    for service in ("nginx", "postgresql", "pink-iptv-backend", "pink-vpn"):
        status = "ACTIVE" if service_ok(service) else "INACTIVE"
        print(f"PINK063_SERVICE_{service.upper().replace('-', '_')}={status}", flush=True)

    path = Path("/run/pink-vpn/control.sock")
    present = path.exists() and stat.S_ISSOCK(path.stat().st_mode)
    print("PINK063_GATEWAY_SOCKET=" + ("PRESENT" if present else "ABSENT"), flush=True)
    backend_dir = cmd("systemctl", "show", "pink-iptv-backend", "-p", "WorkingDirectory", "--value")
    print("PINK063_BACKEND_DIRECTORY=" + ("EXPECTED" if backend_dir == "/srv/pink-iptv/backend" else "MISMATCH"), flush=True)

    # A journal may contain account/network details. Parse it in memory and never
    # print either its text or the exception messages from subprocess failures.
    for label, (start, end) in WINDOWS.items():
        raw = cmd("journalctl", "-u", "pink-iptv-backend", "--since", start,
                  "--until", end, "--no-pager", "-o", "cat", "-n", "15000", timeout=30)
        counts = aggregated_statuses(raw.splitlines())
        print("PINK063_AGGREGATE=" + label + ";" +
              (";".join(f"{key}={val}" for key, val in counts.items()) if counts else "NO_MATCHING_ACCESS_LOGS"),
              flush=True)

    # An unauthenticated, syntactically valid public-key request cannot create
    # an installation: this is an endpoint availability/authentication probe.
    public = base64.b64encode(os.urandom(32)).decode("ascii")
    request = urllib.request.Request("https://pink-iptv.duckdns.org/v1/vpn/enroll",
             method="POST", data=json.dumps({"public_key":public}).encode(),
             headers={"Content-Type":"application/json", "Accept":"application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            code = response.status
    except urllib.error.HTTPError as error:
        code = error.code
    except (urllib.error.URLError, TimeoutError, OSError):
        code = 0
    assert isinstance(code, int) and 0 <= code < 600
    print(f"PINK063_UNAUTH_ENROLL_HTTP_STATUS={code}", flush=True)
    # This probe proves only availability/status, never authenticated enrollment.
    assert code == 401, "Unauthenticated enrollment must be denied (HTTP 401)"


if __name__ == "__main__":
    observe()
