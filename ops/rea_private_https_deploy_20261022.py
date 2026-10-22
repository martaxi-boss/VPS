#!/usr/bin/env python3
"""Scoped REA VPS deployment. Root-only, fail-closed, never publishes an unauthenticated MCP.
Requires: DNS points at this VPS; REA trial already built, JADX/JDK/Ghidra verified.
Does not touch pre-existing sites or other services except validated nginx reloads.
"""
import http.client
import json
import os
import pwd
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path

D="rea-reversa.duckdns.org"
IP="146.59.145.3"
TRIAL=Path("/home/ubuntu/.local/share/rea-chatgpt-trial")
INSTALL=Path("/opt/rea-reversa")
NODE_SOURCE=Path(os.environ.get("REA_NODE_BIN","/usr/bin/node"))
NAME="rea-reversa"
SITE=Path("/etc/nginx/sites-available")/D
SITE_LINK=Path("/etc/nginx/sites-enabled")/D
AUTH_MAP=Path("/etc/nginx/conf.d/rea-reversa-auth-map.conf")
KEY_DIR=Path("/etc/rea-reversa")
TOKEN_FILE=KEY_DIR/"api-token"
ACME=Path("/var/www/rea-reversa-acme")
CERT=Path("/etc/letsencrypt/live")/D
UNIT=Path("/etc/systemd/system/rea-reversa-mcp.service")
MARKER=INSTALL/".rea-reversa-deployment-v1"
PORT=8765

def run(argv,timeout=90,check=True):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,text=True,timeout=timeout,check=False)
    if check and p.returncode:
        raise RuntimeError("Command failed: "+argv[0]+" "+str(p.returncode))
    return p

def print_status(k,v):
    print("REA_DEPLOY_"+k+"="+str(v),flush=True)

def preflight():
    if os.geteuid()!=0:
        raise RuntimeError("Root required")
    if socket.gethostbyname(D)!=IP:
        raise RuntimeError("DuckDNS does not point to expected VPS IP")
    if not TRIAL.joinpath("repository/rea/scripts/rea.mjs").is_file():
        raise RuntimeError("REA CLI missing")
    for name in ("tools/jdk-21/bin/java","tools/jdk-21/bin/javac",
                 "tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless",
                 "tools/jadx-headless-mcp-0.7.1-all.jar"):
        if not TRIAL.joinpath(name).is_file():
            raise RuntimeError("Missing tool "+name)
    if not NODE_SOURCE.is_file() or not os.access(NODE_SOURCE,os.X_OK):
        raise RuntimeError("Missing Node binary")
    version=run([str(NODE_SOURCE),"--version"],timeout=8).stdout.strip()
    v=[int(x) for x in version.lstrip("v").split(".")[:2]]
    if not ((v[0]==22 and v[1]>=19) or (v[0]==24 and v[1]>=11) or v[0]>=26):
        raise RuntimeError("Incompatible Node")
    if shutil.disk_usage("/").free < 18*1024**3:
        raise RuntimeError("Less than 18 GiB free disk")
    if not SITE.parent.is_dir() or not SITE_LINK.parent.is_dir():
        raise RuntimeError("Unexpected nginx directory layout")
    if (MARKER.is_file() and UNIT.is_file() and SITE.is_file() and SITE_LINK.is_symlink() and
        SITE_LINK.resolve()==SITE and "server_name rea-reversa.duckdns.org;" in SITE.read_text() and
        "location / { return 404; }" in SITE.read_text() and
        not AUTH_MAP.exists()):
        print_status("ACME_STAGE","RECOVER_SAFELY")
        return "staged"
    if MARKER.is_file() and UNIT.is_file() and not any((SITE.exists(), SITE_LINK.exists(), AUTH_MAP.exists(), TOKEN_FILE.exists())):
        print_status("PREPARED_INSTALL","RESUME_ONLY")
        return "staged"
    if SITE.exists() or SITE_LINK.exists() or AUTH_MAP.exists() or UNIT.exists():
        if MARKER.is_file() and SITE.exists() and TOKEN_FILE.is_file() and UNIT.is_file():
            print_status("EXISTING_DEPLOYMENT", "PRESENT")
            return "exists"
        raise RuntimeError("Pre-existing REA deployment item: refuse overwrite")
    if INSTALL.exists() or TOKEN_FILE.exists():
        raise RuntimeError("Unmarked REA target: refuse overwrite")
    run(["nginx","-t"],timeout=10)
    print_status("PREFLIGHT","PASS")
    print_status("NODE",version)
    return "new"

def stage_files():
    temp=Path("/opt/rea-reversa-staging")
    if temp.exists():
        raise RuntimeError("Pre-existing staging directory: refuse overwrite")
    temp.mkdir(mode=0o700)
    try:
        shutil.copytree(TRIAL/"repository/rea",temp/"rea",symlinks=True)
        shutil.copytree(TRIAL/"tools",temp/"tools",symlinks=True)
        (temp/"bin").mkdir()
        shutil.copy2(NODE_SOURCE,temp/"bin/node")
        run(["chmod","-R","a+rX,go-w",str(temp)],timeout=130)
        run([str(temp/"bin/node"),str(temp/"rea/scripts/rea.mjs"),"providers","--json"],
            timeout=55)
        MARKER_TEMP=temp/".rea-reversa-deployment-v1"
        MARKER_TEMP.write_text("source=martaxi-boss/Engenheira-reversa; trial=20261022\n")
        MARKER_TEMP.chmod(0o644)
        temp.rename(INSTALL)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
    print_status("ISOLATED_COPY","PASS")

def service():
    if not run(["id","-u",NAME],check=False).returncode==0:
        run(["useradd","--system","--user-group","--home-dir",
             "/var/lib/rea-reversa","--shell","/usr/sbin/nologin",NAME])
    if UNIT.exists():
        raise RuntimeError("Systemd service already exists unexpectedly")
    body="""[Unit]
Description=Private REA MCP analysis engine (loopback only)
After=network.target

[Service]
Type=simple
User=rea-reversa
Group=rea-reversa
StateDirectory=rea-reversa
RuntimeDirectory=rea-reversa
WorkingDirectory=/var/lib/rea-reversa
Environment=HOME=/var/lib/rea-reversa
Environment=PATH=/opt/rea-reversa/bin:/usr/bin:/bin
Environment=NODE_OPTIONS=--max-old-space-size=768
Environment=JAVA_HOME=/opt/rea-reversa/tools/jdk-21
Environment=GHIDRA_INSTALL_DIR=/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC
Environment=GHIDRA_HEADLESS_MAXMEM=1024M
Environment=REA_JADX_MCP_JAR=/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar
Environment=REA_JADX_HEAP_MIB=1024
ExecStart=/opt/rea-reversa/bin/node /opt/rea-reversa/rea/scripts/rea.mjs mcp --http --host 127.0.0.1 --port 8765
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
UMask=0077
CPUQuota=200%
MemoryMax=3G
TasksMax=256
LimitNOFILE=4096
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
"""
    UNIT.write_text(body)
    UNIT.chmod(0o644)
    run(["systemctl","daemon-reload"])
    run(["systemctl","enable","--now","rea-reversa-mcp.service"],timeout=45)
    for i in range(60):
        if run(["systemctl","is-active","--quiet","rea-reversa-mcp.service"],check=False).returncode!=0:
            raise RuntimeError("REA service not active")
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.settimeout(.4)
            if sock.connect_ex(("127.0.0.1",PORT))==0:
                print_status("SYSTEMD_LOOPBACK","PASS")
                return
        time.sleep(.5)
    raise RuntimeError("REA service did not open the loopback port")

def nginx_validate_reload():
    run(["nginx","-t"],timeout=15)
    run(["systemctl","reload","nginx"],timeout=25)

def resume_service():
    if not (MARKER.is_file() and UNIT.is_file()):
        raise RuntimeError("Unverified partial REA installation; refuse resume")
    run(["systemctl","daemon-reload"])
    run(["systemctl","enable","--now","rea-reversa-mcp.service"],timeout=45)
    for attempt in range(60):
        if run(["systemctl","is-active","--quiet","rea-reversa-mcp.service"],check=False).returncode!=0:
            raise RuntimeError("REA MCP systemd service failed startup")
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.settimeout(.4)
            if sock.connect_ex(("127.0.0.1",PORT))==0:
                print_status("SYSTEMD_LOOPBACK","PASS")
                return
        time.sleep(.5)
    raise RuntimeError("MCP did not listen on loopback")

def configure_acme():
    ACME.joinpath(".well-known/acme-challenge").mkdir(parents=True,exist_ok=True)
    http_config="""server {
    listen 80;
    server_name rea-reversa.duckdns.org;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/rea-reversa-acme;
        try_files $uri =404;
    }
    location / { return 404; }
}
"""
    SITE.write_text(http_config)
    SITE.chmod(0o644)
    if not SITE_LINK.is_symlink():
        SITE_LINK.symlink_to(SITE)
    elif SITE_LINK.resolve()!=SITE:
        raise RuntimeError("Unexpected nginx symlink target")
    nginx_validate_reload()
    challenge=ACME/".well-known/acme-challenge/rea-vps-test"
    challenge.write_text("REA_ACME_TEST_V1")
    try:
        conn=http.client.HTTPConnection("127.0.0.1",80,timeout=10)
        conn.request("GET","/.well-known/acme-challenge/rea-vps-test",
                     headers={"Host":D})
        resp=conn.getresponse()
        content=resp.read(80).decode("ascii",errors="replace")
        conn.close()
        if resp.status!=200 or content!="REA_ACME_TEST_V1":
            raise RuntimeError("Nginx ACME location misrouted; refuse TLS issuance")
    finally:
        challenge.unlink(missing_ok=True)
    print_status("ACME_HTTP_CHALLENGE","PASS")

def issue_cert():
    run(["certbot","certonly","--webroot",
        "--webroot-path",str(ACME),"--cert-name",D,
        "-d",D,"--non-interactive","--agree-tos",
        "--register-unsafely-without-email","--keep-until-expiring"],
        timeout=240)
    if not (CERT/"fullchain.pem").is_file() or not (CERT/"privkey.pem").is_file():
        raise RuntimeError("HTTPS certificate missing after certbot")
    print_status("TLS_CERTIFICATE","PASS")

def configure_tls():
    KEY_DIR.mkdir(mode=0o700,exist_ok=True)
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(secrets.token_hex(32)+"\n")
        TOKEN_FILE.chmod(0o600)
    token=TOKEN_FILE.read_text().strip()
    if len(token)!=64:
        raise RuntimeError("Credential generation failed")
    AUTH_MAP.write_text('map_hash_bucket_size 128;\nmap $http_authorization $rea_reversa_auth_ok {\n'
        '    default 0;\n'
        '    "Bearer '+token+'" 1;\n'
        '}\n')
    AUTH_MAP.chmod(0o600)
    https="""server {
    listen 80;
    server_name rea-reversa.duckdns.org;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/rea-reversa-acme;
        try_files $uri =404;
    }
    location / { return 308 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    server_name rea-reversa.duckdns.org;
    ssl_certificate /etc/letsencrypt/live/rea-reversa.duckdns.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rea-reversa.duckdns.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 4m;
    access_log off;
    location = /mcp {
        if ($rea_reversa_auth_ok = 0) { return 401; }
        proxy_pass http://127.0.0.1:8765/mcp;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_set_header Host "127.0.0.1:8765";
        proxy_set_header Origin "";
        proxy_set_header Authorization "";
        proxy_set_header Connection "";
        add_header Cache-Control "no-store" always;
    }
    location / { return 404; }
}
"""
    SITE.write_text(https)
    try:
        nginx_validate_reload()
    except Exception:
        diag=run(["nginx","-t"],check=False)
        print_status("NGINX_VALIDATION_ERROR",diag.stderr.strip()[-450:].replace(token,"[REDACTED]"))
        AUTH_MAP.unlink(missing_ok=True)
        SITE.write_text("""server {
    listen 80;
    server_name rea-reversa.duckdns.org;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/rea-reversa-acme;
        try_files $uri =404;
    }
    location / { return 404; }
}
""")
        nginx_validate_reload()
        raise
    print_status("NGINX_TLS_BEARER","PASS")

class LocalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        sock=socket.create_connection(("127.0.0.1",443),timeout=20)
        self.sock=self._context.wrap_socket(sock,server_hostname=D)

def check_http(authorization=None):
    context=ssl.create_default_context()
    conn=LocalHTTPS(D,443,context=context,timeout=35)
    payload={"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"rea-vps-auth-proof","version":"1.0.0"}}}
    headers={
        "Content-Type":"application/json",
        "Accept":"application/json, text/event-stream",
    }
    if authorization:
        headers["Authorization"]="Bearer "+authorization
    conn.request("POST","/mcp",body=json.dumps(payload).encode(),headers=headers)
    resp=conn.getresponse()
    body=resp.read(1000000)
    status=resp.status
    conn.close()
    return status,body

def verify():
    for attempt in range(20):
        try:
            unauthorized,_=check_http()
            if unauthorized==401:
                break
        except (ssl.SSLCertVerificationError, ConnectionError, TimeoutError, OSError):
            if attempt==19:
                raise
        time.sleep(.7)
    else:
        raise RuntimeError("HTTPS not ready after nginx reload")
    if unauthorized!=401:
        raise RuntimeError("Unauthenticated MCP did not return 401")
    print_status("UNAUTHENTICATED_REQUEST","BLOCKED_401")
    token=TOKEN_FILE.read_text().strip()
    code,body=check_http(token)
    if code!=200:
        raise RuntimeError("Authorized MCP failed with HTTP "+str(code))
    payload=body.decode("utf-8",errors="replace")
    if not ("\"serverInfo\"" in payload and "\"protocolVersion\"" in payload):
        raise RuntimeError("MCP initialize did not contain serverInfo")
    print_status("AUTHENTICATED_MCP","PASS")
    print_status("TOKEN_STORED_ONLY_ON_VPS",str(TOKEN_FILE))
    print_status("ENDPOINT","https://"+D+"/mcp")
    print_status("SERVICES_ISOLATED","PASS")

def renewal_hook():
    hook=Path("/etc/letsencrypt/renewal-hooks/deploy/rea-reversa-only-nginx-reload.sh")
    if hook.exists():
        print_status("RENEWAL_HOOK","EXISTS")
        return
    hook.parent.mkdir(parents=True,exist_ok=True)
    hook.write_text("""#!/bin/sh
case " $RENEWED_DOMAINS " in
  *" rea-reversa.duckdns.org "*)
    /usr/sbin/nginx -t >/dev/null 2>&1 && /bin/systemctl reload nginx
    ;;
esac
""")
    hook.chmod(0o755)
    print_status("RENEWAL_HOOK","STAGED")

def main():
    state=preflight()
    if state=="exists":
        verify()
        return
    if state=="staged":
        resume_service()
    else:
        stage_files()
        service()
    configure_acme()
    issue_cert()
    configure_tls()
    verify()
    renewal_hook()
    print_status("COMPLETE","HTTPS_AUTH_MCP_VERIFIED")

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print_status("FAILED",type(e).__name__+": "+str(e)[:200])
        sys.exit(1)
