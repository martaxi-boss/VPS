#!/usr/bin/env python3
"""Non-mutating, redacted readiness check for a dedicated REA DuckDNS vhost."""
import json, socket, subprocess
from pathlib import Path
DOMAIN="rea-reversa.duckdns.org"
EXPECTED_IP="146.59.145.3"
def cmd(args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=12,check=False)
        return p.stdout if p.returncode==0 else ""
    except (OSError,subprocess.TimeoutExpired): return ""
def addresses(name):
    try: return sorted(set(x[4][0] for x in socket.getaddrinfo(name,443,type=socket.SOCK_STREAM) if x[0]==socket.AF_INET))
    except (OSError,socket.gaierror): return []
def nginx_directives():
    raw=cmd(["nginx","-T"])
    if not raw: raw=cmd(["sudo","-n","nginx","-T"])
    directives={"server_names":[],"includes":[],"certbot_comments":0}
    for line in raw.splitlines():
        line=line.partition("#")[0].strip()
        if line.startswith("server_name "):
            directives["server_names"] += line.strip(";").split()[1:]
        if line.startswith("include ") and ("sites-enabled" in line or "conf.d" in line):
            directives["includes"].append(line.strip(";"))
    return {k:sorted(set(v)) if isinstance(v,list) else v for k,v in directives.items()}
def main():
    v=nginx_directives()
    result={
       "probe":"REA_DUCKDNS_DOMAIN_READONLY_V1",
       "changes":False,"hostname":DOMAIN,"expected_vps_ipv4":EXPECTED_IP,
       "resolved_ipv4":addresses(DOMAIN),
       "dns_points_to_vps":EXPECTED_IP in addresses(DOMAIN),
       "nginx_host_already_configured":DOMAIN in v["server_names"],
       "nginx_directives":v,
       "cert_exists":(Path("/etc/letsencrypt/live")/DOMAIN/"fullchain.pem").exists(),
       "certbot_installed":bool(cmd(["sh","-c","command -v certbot"])),
       "nginx_sites_available":Path("/etc/nginx/sites-available").is_dir(),
       "nginx_sites_enabled":Path("/etc/nginx/sites-enabled").is_dir(),
       "nginx_conf_d":Path("/etc/nginx/conf.d").is_dir(),
       "nginx_check_ok": bool(cmd(["nginx","-t"]) or cmd(["sudo","-n","nginx","-t"])),
    }
    print("REA_DUCKDNS_READINESS="+json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
