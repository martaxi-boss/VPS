#!/usr/bin/env python3
"""One-shot REA-only Nginx HTTPS OAuth activation; rollback on failed validation."""
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import time

DOMAIN = "rea-reversa.duckdns.org"
PUBLIC = "https://" + DOMAIN
EXPECTED_VHOST_SHA256 = "4c548df03f415def9faa38b767c723f09ef18ce1df7a30892d490ff4e04b1148"
VHOST = pathlib.Path("/etc/nginx/sites-enabled/rea-reversa.duckdns.org.conf").resolve(strict=True)
BACKUP = pathlib.Path("/root/project-secrets/rea-mcp/rea-nginx-before-oauth-20261027.conf")


def checked(*argv):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError("Command failed: " + argv[0] + " (status " + str(proc.returncode) + ")")
    return proc.stdout


def active(service):
    return subprocess.run(["systemctl", "is-active", "--quiet", service]).returncode == 0


def atomic_write(content):
    original_stat = VHOST.stat()
    fd, tmp = tempfile.mkstemp(prefix="rea-nginx-atomic-", dir=str(VHOST.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
        os.chown(tmp, original_stat.st_uid, original_stat.st_gid)
        os.chmod(tmp, stat.S_IMODE(original_stat.st_mode))
        os.replace(tmp, VHOST)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def probe(url, *, post=False, bad_token=False):
    args = [
        "curl", "--noproxy", "*", "--resolve", DOMAIN + ":443:127.0.0.1",
        "--max-time", "12", "-sS", "-w", "\n__REA_HTTP__%{http_code}",
    ]
    if post:
        args.extend([
            "-X", "POST", "-H", "Accept: application/json, text/event-stream",
            "-H", "Content-Type: application/json",
            "--data-binary", json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "rea-https-validation", "version": "1"},
                },
            }),
        ])
    if bad_token:
        args.extend(["-H", "Authorization: Bearer token-that-must-be-rejected"])
    args.append(url)
    raw = checked(*args)
    body, marker, status = raw.rpartition("\n__REA_HTTP__")
    if not marker:
        raise RuntimeError("Missing HTTP status marker")
    return int(status.strip()), body


def main():
    for svc in ("rea-reversa-mcp.service", "rea-mcp-oauth.service", "nginx.service"):
        if not active(svc):
            raise RuntimeError("Required service not active: " + svc)
    original = VHOST.read_bytes()
    if hashlib.sha256(original).hexdigest() != EXPECTED_VHOST_SHA256:
        raise RuntimeError("REA Nginx vhost no longer matches pre-approved baseline")
    assert original.count(b"server_name rea-reversa.duckdns.org;") == 2
    old = b"    location / {\n        return 404;\n    }\n"
    if original.count(old) != 1:
        raise RuntimeError("REA vhost does not contain expected HTTPS 404 placeholder")
    replacement = (
        "    access_log off;\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:8766;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header X-Forwarded-Host $host;\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "        proxy_set_header Authorization $http_authorization;\n"
        "        proxy_set_header Connection \"\";\n"
        "        proxy_buffering off;\n"
        "        proxy_request_buffering off;\n"
        "        proxy_read_timeout 300s;\n"
        "        proxy_send_timeout 300s;\n"
        "        proxy_redirect off;\n"
        "        add_header Cache-Control \"no-store\" always;\n"
        "    }\n"
    ).encode()
    if BACKUP.exists():
        if hashlib.sha256(BACKUP.read_bytes()).hexdigest() != EXPECTED_VHOST_SHA256:
            raise RuntimeError("Existing REA backup does not match baseline")
    else:
        fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(original)
    updated = original.replace(old, replacement, 1)
    checked("nginx", "-t")
    atomic_write(updated)
    try:
        checked("nginx", "-t")
        checked("systemctl", "reload", "nginx")
        # A successful nginx reload command can return before the new workers
        # receive traffic. Check readiness rather than racing the old 404 vhost.
        for attempt in range(40):
            resource_code, resource_body = probe(PUBLIC + "/.well-known/oauth-protected-resource/mcp")
            auth_code, auth_body = probe(PUBLIC + "/.well-known/oauth-authorization-server")
            if resource_code == 200 and auth_code == 200:
                print("REA_HTTPS_RELOAD_READY_ATTEMPT=" + str(attempt + 1), flush=True)
                break
            time.sleep(0.3)
        else:
            print("REA_HTTPS_RELOAD_FINAL_CODES=" + str(resource_code) + "," + str(auth_code), flush=True)
            raise RuntimeError("REA HTTPS discovery endpoints never became ready")
        anon_code, _ = probe(PUBLIC + "/mcp", post=True)
        wrong_code, _ = probe(PUBLIC + "/mcp", post=True, bad_token=True)
        print("REA_HTTPS_HTTP_CODES=" + ",".join(map(str, (
            resource_code, auth_code, anon_code, wrong_code
        ))), flush=True)
        if (resource_code, auth_code, anon_code, wrong_code) != (200, 200, 401, 401):
            raise RuntimeError("REA HTTPS status codes failed validation")
        resource = json.loads(resource_body)
        auth = json.loads(auth_body)
        assert resource["resource"] == PUBLIC + "/mcp"
        assert auth["issuer"] == PUBLIC + "/"
        assert auth["issuer"] in resource["authorization_servers"]
        assert "S256" in auth["code_challenge_methods_supported"]
        assert auth["authorization_response_iss_parameter_supported"] is True
        assert auth["registration_endpoint"].startswith(PUBLIC + "/")
        print("REA_HTTPS_OAUTH_DISCOVERY=PASS", flush=True)
        print("REA_HTTPS_ANON_AND_INVALID_401=PASS", flush=True)
        print("REA_HTTPS_REA_ORIGINAL_UNCHANGED=PASS", flush=True)
    except Exception:
        atomic_write(original)
        checked("nginx", "-t")
        checked("systemctl", "reload", "nginx")
        print("REA_HTTPS_ROLLBACK=SUCCESS", flush=True)
        raise


if __name__ == "__main__":
    main()
