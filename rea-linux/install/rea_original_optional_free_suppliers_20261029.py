#!/usr/bin/env python3
"""REA official 6.8.0: preflight, then optional isolated supplier installation.

Entry point is GitHub Actions -> pinned SSH -> ubuntu. No new MCP or service.
Phase=preflight is strictly read only. Install phase is intentionally not yet
enabled: records precise aptitude, storage, versions and rights before writes.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
DIST={
"dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
"dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655"}
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/optional-free-suppliers-20261029")
os.umask(0o077)

def run(a,timeout=28):
    try:
        return subprocess.run(a,stdin=subprocess.DEVNULL,cwd=ROOT,
            timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            encoding="utf-8",errors="replace",text=True,check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(a,124,"","TIMEOUT")
    except OSError as e:
        return subprocess.CompletedProcess(a,126,"",type(e).__name__+":"+str(e)[:110])

def check(x,s):
    if not x:raise RuntimeError(s)

def verify_original():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","EXPECTED_SSH_UBUNTU")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"PINNED_ORIGINAL_ROOT_MISSING")
    check(NODE.is_file(),"PINNED_NODE_MISSING")
    check((ROOT/"node_modules").is_symlink(),"EXISTING_DEP_LINK_CHANGED")
    check((ROOT/"node_modules").resolve()==(OLD/"node_modules").resolve(),"EXISTING_DEPS_ORIGIN_CHANGED")
    check((ROOT/"package-lock.json").read_bytes()==(OLD/"package-lock.json").read_bytes(),"PACKAGE_LOCK_CHANGED")
    rev=run(["git","-C",str(ROOT),"rev-parse","HEAD"],12)
    check(rev.returncode==0 and rev.stdout.strip()==REV,"ORIGINAL_SOURCE_COMMIT_CHANGED")
    for path,want in DIST.items():
        f=ROOT/path
        check(f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==want,"ORIGINAL_COMPILED_DIGEST_CHANGED")
    check(EVID.parent.is_dir(),"EVIDENCE_PARENT_UNAVAILABLE")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_OPT_SOURCE_PIN=PASS",flush=True)
    print("REA_OPT_TRANSPORT=GITHUB_ACTIONS_PINNED_SSH_UBUNTU_CLI",flush=True)
    print("REA_OPT_MCP_USED=NO",flush=True)

def simple(a,limit=500,timeout=15):
    p=run(a,timeout)
    return {"rc":p.returncode,"out":p.stdout.strip()[:limit],"err":p.stderr.strip()[:250]}

def preflight():
    verify_original()
    pre={}
    pre["system"]={
        "os":simple(["lsb_release","-ds"]),
        "arch":simple(["dpkg","--print-architecture"]),
        "disk_home":simple(["df","-Pk","/home/ubuntu"]),
        "disk_opt":simple(["df","-Pk","/opt/rea-reversa"]),
        "mem":simple(["free","-m"]),
        "sudo_n":simple(["sudo","-n","/usr/bin/id","-u"],timeout=9)
    }
    pre["runtime"]={
        "python3":simple(["python3","--version"]),
        "gdb":simple(["/usr/bin/gdb","--version"]),
        "gdb_python":simple(["/usr/bin/gdb","-nx","--batch","-ex",
                "python import sysconfig;print(sysconfig.get_config_var('VERSION'))"],timeout=15),
        "dotnet":simple(["dotnet","--list-sdks"]) if shutil.which("dotnet") else None,
        "uv":simple(["uv","--version"]) if shutil.which("uv") else None,
        "pipx":simple(["pipx","--version"]) if shutil.which("pipx") else None,
        "python_venv":simple(["python3","-c","import venv;print('VENV_MODULE_PRESENT')"]),
        "python_ensurepip":simple(["python3","-c","import ensurepip;print(ensurepip.version())"])
    }
    pre["apt"]={
        "dotnet_sdk_10":simple(["apt-cache","policy","dotnet-sdk-10.0"],limit=1100),
        "dotnet_runtime_10":simple(["apt-cache","policy","dotnet-runtime-10.0"],limit=1100),
        "uv_package":simple(["apt-cache","policy","uv"],limit=1100),
        "python3_venv":simple(["apt-cache","policy","python3-venv"],limit=1100),
        "dotnet_sdk_10_simulation":simple(["apt-get","-s","-o","Debug::NoLocking=1",
         "install","--no-install-recommends","--no-remove","--no-upgrade","dotnet-sdk-10.0"],limit=2400,timeout=40),
    }
    paths={
      "ilspycmd_existing_user":Path("/home/ubuntu/.dotnet/tools/ilspycmd"),
      "ilspycmd_existing_scoped":Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd"),
      "pwndbg_gdbinit_source":Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/gdbinit.py"),
      "pwndbg_gdbinit_uv":Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/share/pwndbg/gdbinit.py"),
      "pwn_debug_old_source":Path("/opt/pwndbg/gdbinit.py"),
    }
    pre["preexisting"]={k:{"file":v.is_file(),"accessible":os.access(v,os.R_OK)} for k,v in paths.items()}
    for k,path in (("ssh_user","/home/ubuntu"),("evidence","/home/ubuntu/rea-original-upstream-680-evidence")):
        pre["preexisting"][k]={"writable":os.access(path,os.W_OK)}
    (EVID/"preflight.json").write_text(json.dumps(pre,sort_keys=True,indent=2),encoding="utf8")
    for k,v in pre["system"].items():
        if k in ("disk_home","disk_opt","mem"):continue
        print("REA_OPT_SYSTEM_"+k.upper()+"="+str(v["rc"])+";"+v["out"].replace("\n"," ")[:180],flush=True)
    for k,v in pre["runtime"].items():
        if v is None:
            print("REA_OPT_RUNTIME_"+k.upper()+"=NOT_FOUND",flush=True)
        else:
            print("REA_OPT_RUNTIME_"+k.upper()+"="+str(v["rc"])+";"+
                  v["out"].replace("\n"," ")[:220],flush=True)
    for k,v in pre["apt"].items():
        print("REA_OPT_APT_"+k.upper()+"="+str(v["rc"])+";"+
              v["out"].replace("\n"," | ")[:530]+
              ";stderr="+v["err"].replace("\n"," ")[:110],flush=True)
    for k,v in pre["preexisting"].items():
        print("REA_OPT_EXISTING_"+k.upper()+"="+json.dumps(v,separators=(",",":")),flush=True)
    for k in ("disk_home","disk_opt"):
        print("REA_OPT_"+k.upper()+"="+pre["system"][k]["out"].replace("\n"," | ")[:210],flush=True)
    print("REA_OPT_PREFLIGHT=PASS",flush=True)

if __name__=="__main__":
    try:
        if len(sys.argv)>1:raise RuntimeError("ONLY_PREFLIGHT_CURRENTLY_SUPPORTED")
        preflight()
    except Exception as exc:
        print("REA_OPT_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
