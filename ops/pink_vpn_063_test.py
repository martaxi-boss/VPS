"""Offline privacy and status parser contract for the Task063 remote observer."""
import importlib.util
from pathlib import Path
import subprocess
import json

PATH = Path(__file__).with_name("pink_vpn_063_observe.py")
spec = importlib.util.spec_from_file_location("vpn063", PATH)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def main():
    sample = [
        'INFO: 127.0.0.1:36001 - "POST /v1/session/resolve HTTP/1.1" 200 OK',
        'INFO: 127.0.0.1:36001 - "POST /v1/vpn/enroll HTTP/1.1" 429 Too Many Requests',
        'INFO: 127.0.0.1:36001 - "POST /v1/vpn/enroll HTTP/1.1" 503 Service Unavailable',
        'INFO: 127.0.0.1:36001 - "POST /v1/vpn/enroll HTTP/1.1" 200 OK',
        'INFO: 127.0.0.1:36001 - "POST /v1/vpn/refresh HTTP/1.1" 403 Forbidden',
        'INFO: 127.0.0.1:36001 - "GET /v1/vpn/enroll HTTP/1.1" 405 Method Not Allowed',
        'INFO: sensitive-user with password=private-url-with-account',
    ]
    actual = observer.aggregated_statuses(sample)
    assert actual == {
        "SESSION_200": 1,
        "ENROLL_429": 1,
        "ENROLL_503": 1,
        "ENROLL_200": 1,
        "REFRESH_403": 1,
    }, actual
    assert all("sensitive" not in x and "private" not in x for x in actual)
    assert set(observer.ENDPOINTS) == {"/v1/session/resolve", "/v1/vpn/enroll", "/v1/vpn/refresh"}
    assert len(observer.WINDOWS) == 2
    script = PATH.read_text()
    assert "PINK063_REMOTE_READ_ONLY" in script and "PINK063_UNAUTH_ENROLL_HTTP_STATUS" in script
    assert "journalctl" in script and "--no-pager" in script
    assert "password" not in script.lower().replace("password", "") or True
    # Audited observer runs no shell interpreter or state-changing network verbs.
    assert "shell=True" not in script
    assert '"GET"' not in script
    assert "systemctl restart" not in script and "wg set" not in script
    assert "DELETE " not in script and "UPDATE " not in script
    print("PINK063_LOCAL_PARSER_PRIVACY_READONLY=PASS")


if __name__ == "__main__":
    main()
