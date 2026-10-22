#!/usr/bin/env python3
"""Read-only scoped service diagnostic, no credentials or other services."""
import json,os,subprocess,stat
from pathlib import Path
def cmd(args):
    try:
        p=subprocess.run(args,timeout=15,capture_output=True,text=True,check=False)
        return {"exit":p.returncode,"out":p.stdout.strip()[:3500],"err":p.stderr.strip()[:650]}
    except Exception as exc:return {"exception":type(exc).__name__}
def mode(path):
    p=Path(path)
    try:
        s=p.stat()
        return {"exists":True,"mode":oct(stat.S_IMODE(s.st_mode)),"uid":s.st_uid,"gid":s.st_gid,"size":s.st_size}
    except OSError:return {"exists":False}
def main():
    result={
      "probe":"REA_SYSTEMD_SCOPED_DIAG_V1","side_effects":False,
      "paths":{x:mode(x) for x in (
        "/opt/rea-reversa","/opt/rea-reversa/bin/node",
        "/opt/rea-reversa/rea/scripts/rea.mjs",
        "/opt/rea-reversa/rea/dist",
        "/etc/systemd/system/rea-reversa-mcp.service",
        "/var/lib/rea-reversa")},
      "unit_status":cmd(["systemctl","status","--no-pager","--full","rea-reversa.service"]),
      "unit_mcp_status":cmd(["systemctl","status","--no-pager","--full","rea-reversa-mcp.service"]),
      "journal":cmd(["journalctl","-u","rea-reversa.service","-n","22","--no-pager","-o","cat"]),
      "journal_mcp":cmd(["journalctl","-u","rea-reversa-mcp.service","-n","22","--no-pager","-o","cat"]),
      "user":cmd(["id","rea-reversa"]),
      "systemd_enabled":cmd(["systemctl","is-enabled","rea-reversa.service"]),
      "systemd_mcp_enabled":cmd(["systemctl","is-enabled","rea-reversa-mcp.service"]),
      "unit_verified":cmd(["systemd-analyze","verify","/etc/systemd/system/rea-reversa-mcp.service"]),
    }
    print("REA_SYSTEMD_DIAG="+json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
