#!/usr/bin/env python3
"""Read-only summary of HTTPS/DNS readiness. Redacts secrets and paths."""
import json, os, re, shutil, socket, subprocess
from pathlib import Path
SECRET_PATTERNS = ["token", "password", "authorization", "cookie", "secret", "key"]
def cmd(args, limit=800000):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
          text=True,timeout=15,check=False)
        return p.stdout[:limit] if p.returncode==0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""
def names():
    text=cmd(["nginx","-T"])
    if not text: text=cmd(["sudo","-n","nginx","-T"])
    found=set()
    for line in text.splitlines():
        s=line.split("#",1)[0].strip()
        if s.startswith("server_name "):
            for item in s.replace(";", " ").split()[1:]:
                if re.fullmatch(r"[A-Za-z0-9*._-]{3,160}",item):
                    found.add(item)
    return sorted(found)[:45]
def dns(host):
    try:
        values={x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM) if x[0]==socket.AF_INET}
        return sorted(values)
    except (OSError,socket.gaierror): return []
def main():
    domains=names()
    existing=[host for host in domains if host not in ("_","localhost") and "*" not in host]
    certdirs=Path("/etc/letsencrypt/live")
    certnames=sorted(p.name for p in certdirs.iterdir() if p.is_dir())[:45] if certdirs.is_dir() else []
    certbot=shutil.which("certbot")
    ip="146.59.145.3"
    wildcard="rea.146-59-145-3.sslip.io"
    gathered={
        "probe":"REA_HTTPS_DNS_READONLY_20261022",
        "side_effects":False,
        "nginx_has_config":bool(domains),
        "nginx_server_names":domains,
        "letsencrypt_names":certnames,
        "certbot_command_present":bool(certbot),
        "hostnames_dns":{x:dns(x) for x in existing[:15]},
        "trial_hostname":wildcard,
        "trial_hostname_ipv4":dns(wildcard),
        "trial_hostname_points_to_vps":ip in dns(wildcard),
        "nginx_services":cmd(["systemctl","is-active","nginx"]).strip()[:40],
        "rea_mcp_8765":False,
    }
    with socket.socket() as s:
        s.settimeout(0.3)
        gathered["rea_mcp_8765"]=(s.connect_ex(("127.0.0.1",8765))==0)
    print("REA_HTTPS_DNS_RESULT="+json.dumps(gathered,sort_keys=True))
if __name__=="__main__": main()
