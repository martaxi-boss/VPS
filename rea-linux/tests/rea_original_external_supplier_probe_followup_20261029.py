#!/usr/bin/env python3
"""Additional read-only Binwalk/pwntools provider verification; never install.

Binwalk is present but its selected --version exited 3 in the previous audit.
Check the stderr, available compatible candidates and official CLI acceptance.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
BASE=Path("/opt/rea-reversa/providers")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/external-supplier-gaps-20261029")
COMMIT="160d821ac9a0310afcb8d1fc427862dd6508add5"
os.umask(0o077)

def call(args,env=None,timeout=25):
    try:
        return subprocess.run(args,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf8",
            errors="replace",timeout=timeout,check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args,124,"","DEADLINE_EXPIRED")
    except OSError as e:
        return subprocess.CompletedProcess(args,126,"",type(e).__name__+":"+str(e)[:140])

def trim(s):
    return s.replace("\x1b","").strip()[:270]

def main():
    if pwd.getpwuid(os.geteuid()).pw_name!="ubuntu":raise RuntimeError("UBUNTU_ONLY")
    x=call(["git","-C",str(ROOT),"rev-parse","HEAD"])
    if x.returncode or x.stdout.strip()!=COMMIT:raise RuntimeError("SOURCE_COMMIT_CHANGED")
    if not EVID.is_dir():raise RuntimeError("PREVIOUS_AUDIT_REQUIRED")
    env=dict(os.environ)
    for name in list(env):
        if name.startswith("REA_") or name in ("JAVA_HOME","GHIDRA_INSTALL_DIR","PLAYWRIGHT_BROWSERS_PATH"):
            env.pop(name,None)
    env["PATH"]="/opt/rea-reversa/tools/jdk-21/bin:"+str(NODE.parent)+":"+env.get("PATH","")
    env["HOME"]=str(EVID/"isolated-home")
    env["CI"]="1"
    found=[]
    selected=shutil.which("binwalk",path=env["PATH"])
    if selected:found.append(Path(selected))
    matches=[]
    for pat in ["binwalk*","*/binwalk","*/bin/binwalk","*/.venv/bin/binwalk","*/venv/bin/binwalk"]:
        matches.extend(list(BASE.glob(pat))[:70])
    for entry in matches:
        try:
            if entry.is_file() and os.access(entry,os.X_OK) and entry not in found:
                found.append(entry)
        except (OSError,PermissionError):pass
    unique=[]
    for p in found:
        if str(p) not in [str(q) for q in unique]:unique.append(p)
    records=[]
    test=EVID/"safe-binwalk-firmware-probe-20261029.bin"
    raw=b"\x00"*32+gzip.compress(b"REA_ORIGINAL_BINWALK_READ_ONLY_PROBE",mtime=0)+b"\x00"*32
    test.write_bytes(raw)
    for path in unique[:15]:
        item={"path":str(path)}
        for flag in ["--version","-V"]:
            result=call([str(path),flag],env=env,timeout=12)
            item[flag]={"exit":result.returncode,
                         "stdout":trim(result.stdout),
                         "stderr":trim(result.stderr)}
        # Verify actual REA 6.8.0 caller contract in addition to a standalone
        # tool version, not merely the existence of a binary.
        individual=env.copy()
        individual["REA_BINWALK_COMMAND"]=str(path)
        cli=call([str(NODE),"scripts/rea.mjs","inspect-firmware-regions",
                  str(test),"--json"],env=individual,timeout=65)
        save=EVID/("binwalk-rea-probe-"+str(len(records))+".json")
        save.write_text(cli.stdout,encoding="utf8",errors="replace")
        try:
            j=json.loads(cli.stdout)
            if isinstance(j,dict) and isinstance(j.get("result"),dict):j=j["result"]
        except (ValueError,TypeError):j={}
        norm=j.get("normalized_result",{}) if isinstance(j,dict) else {}
        item["original_rea"]={
            "exit":cli.returncode,
            "error_code":j.get("error",{}).get("code") if isinstance(j.get("error"),dict) else None,
            "normalized_type":type(norm).__name__,
            "region_count":len(norm.get("regions",[])) if isinstance(norm,dict) and isinstance(norm.get("regions"),list) else 0,
            "cleanup_incomplete":"cleanup_incomplete" in (cli.stdout+cli.stderr).lower(),
            "stderr_excerpt":trim(cli.stderr)
        }
        records.append(item)
        print("REA_GAP_BINWALK_CANDIDATE="+str(path),flush=True)
        print("REA_GAP_BINWALK_VERSION_EXIT="+str(item["--version"]["exit"])+
              ";stdout="+item["--version"]["stdout"][:95]+
              ";stderr="+item["--version"]["stderr"][:140],flush=True)
        print("REA_GAP_BINWALK_REA_TEST="+("PASS" if cli.returncode==0 and item["original_rea"]["region_count"]>0 else "NOT_READY")+
              ";rc="+str(cli.returncode)+
              ";regions="+str(item["original_rea"]["region_count"])+
              ";err="+str(item["original_rea"]["error_code"]),flush=True)
    # Distinguish missing Python venv wiring from an absent supplier package.
    venvs=[]
    patterns=["pwntools*/bin/python3","pwntools*/.venv/bin/python",
              "pwntools*/.venv/bin/python3","pwntools*/venv/bin/python3",
              "pwntools*/bin/python","pwntools*/venv/bin/python",
              "*/pwntools*/bin/python3","*/pwntools*/.venv/bin/python3"]
    for pat in patterns:
        for p in list(BASE.glob(pat))[:30]:
            try:
                if p.is_file() and os.access(p,os.X_OK) and str(p) not in venvs:venvs.append(str(p))
            except (OSError,PermissionError):continue
    versions=[]
    for binary in venvs[:12]:
        r=call([binary,"-c","import importlib.util;print('PWN_FOUND' if importlib.util.find_spec('pwn') else 'PWN_MISSING')"],
             env=env,timeout=15)
        versions.append({"python":binary,"exit":r.returncode,"pwn_found":"PWN_FOUND" in r.stdout})
        print("REA_GAP_PWNTOOLS_VENV="+binary+";result="+("FOUND" if "PWN_FOUND" in r.stdout else "UNAVAILABLE"),flush=True)
    summary={"source":COMMIT,"unchanged_vps_program_installations":True,
             "binwalk_candidates":records,"pwntools_venv_candidates":versions}
    (EVID/"binwalk-pwntools-followup.json").write_text(json.dumps(summary,indent=2,sort_keys=True),encoding="utf8")
    print("REA_GAP_BINWALK_CANDIDATES="+str(len(records)),flush=True)
    print("REA_GAP_PWNTOOLS_VENV_CANDIDATES="+str(len(versions)),flush=True)
    print("REA_GAP_FOLLOWUP=READ_ONLY_COMPLETE",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("REA_GAP_FOLLOWUP_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
