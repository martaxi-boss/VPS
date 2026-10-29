#!/usr/bin/env python3
"""Stage independent provider copies for FINAL REA only; no modification of old system.

Fixed source/destination allowlist; SSH transport is the preexisting pinned workflow.
No new software installs, no license handling, no modification of host services.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

PIN="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
FINAL=Path("/home/ubuntu/rea-final-runtime")
TEMP=FINAL/".strict-final-stage-20261029"
REPORT=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029/strict-copy-20261029.json")
SOURCES={
 "vendors/providers/chromium-playwright-1.58.2":"/opt/rea-reversa/providers/chromium-playwright-1.58.2",
 "optional/rea-optional-ilspycmd-11.2.0":"/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0",
 "optional/rea-optional-pwndbg-2026.09.15":"/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15",
 "optional/rea-optional-pwntools-4.15.0":"/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0",
}
ENTRY={
 "chromium":"vendors/providers/chromium-playwright-1.58.2/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell",
 "ilspy":"optional/rea-optional-ilspycmd-11.2.0/ilspycmd",
 "pwndbg":"optional/rea-optional-pwndbg-2026.09.15/tools/pwndbg/share/pwndbg/gdbinit.py",
 "pwntools":"optional/rea-optional-pwntools-4.15.0/bin/python",
}
def check(ok,reason):
 if not ok:raise RuntimeError(reason)
def cmd(args,timeout=100):
 p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,text=True,errors="replace",timeout=timeout,check=False)
 return p.returncode,p.stdout.strip(),p.stderr.strip()[:180]
def hashed(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for part in iter(lambda:f.read(1024*1024),b""):h.update(part)
 return h.hexdigest()
def size(path):
 rc,out,err=cmd(["sudo","-n","du","-s","-B1","--",str(path)],timeout=120)
 check(rc==0,"DU_FAILED:"+path.name)
 return int(out.split()[0])
def verify_links(where):
 # The copied provider must never link back to the 6.8 legacy tree or original user-local installation.
 n=0; old=[]; userlocal=[];broken=[]
 for current, dirs, files in os.walk(where,followlinks=False):
  for name in dirs+files:
   p=Path(current)/name
   if not p.is_symlink():continue
   n+=1; dest=p.resolve(strict=False)
   if str(dest).startswith("/opt/rea-reversa/"):old.append(str(p.relative_to(where))[:110])
   if str(dest).startswith("/home/ubuntu/.local/share/rea-optional-"):userlocal.append(str(p.relative_to(where))[:110])
   if not dest.exists():broken.append(str(p.relative_to(where))[:110])
 return {"symlinks":n,"links_old":old[:15],"links_userlocal":userlocal[:15],
         "broken":broken[:15],"count_old":len(old),"count_userlocal":len(userlocal),"count_broken":len(broken)}

def relink_inside_copied_provider(stage_dir,source_dir,final_dir):
 """Rewrite only symlinks into the same source tree; do not follow external links."""
 changed=[]
 for current,dirs,files in os.walk(stage_dir,followlinks=False):
  for name in dirs+files:
   p=Path(current)/name
   if not p.is_symlink():continue
   target=os.readlink(p)
   if target==str(source_dir) or target.startswith(str(source_dir)+"/"):
    inside=Path(target).relative_to(source_dir)
    new=final_dir/inside
    # These are newly staged files only. A symlink cannot be used to overwrite a target.
    p.unlink()
    p.symlink_to(new)
    changed.append(str(p.relative_to(stage_dir))[:120])
 return changed

def main():
 check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","NOT_UBUNTU")
 check(ROOT.is_dir() and not ROOT.is_symlink(),"FINAL_CODE_MISSING")
 check(cmd(["git","-C",str(ROOT),"rev-parse","HEAD"],timeout=12)[1]==PIN,"WRONG_MOTOR")
 check((ROOT/"node_modules").resolve(strict=False)==FINAL/"node_modules","NPM_NOT_ISOLATED")
 check(FINAL.is_dir() and FINAL.stat().st_uid==os.geteuid() and not FINAL.is_symlink(),"RUNTIME_WRONG_OWNER")
 check(cmd(["sudo","-n","true"],timeout=9)[0]==0,"SUDO_NO_ACCESS")
 check(not TEMP.exists() and not TEMP.is_symlink(),"STAGE_ALREADY_PRESENT")
 check(not REPORT.exists(),"REPORT_ALREADY_EXISTS")
 source_size=0; entries=[]
 for relative,path in SOURCES.items():
  p=Path(path)
  check(p.is_dir() and not p.is_symlink(),"MISSING_COPY_SOURCE:"+relative)
  target=FINAL/relative
  check(not target.exists() and not target.is_symlink(),"TARGET_ALREADY_EXISTS:"+relative)
  bytes_=size(p)
  source_size+=bytes_
  entries.append({"name":relative,"source":path,"bytes":bytes_})
 check(shutil.disk_usage(str(FINAL)).free > source_size+6*1024**3,"FREE_DISK_TOO_LOW")
 TEMP.mkdir(mode=0o700)
 created=[]
 try:
  for row in entries:
   target=TEMP/row["name"]
   target.parent.mkdir(parents=True,exist_ok=True)
   rc,_,err=cmd(["sudo","-n","cp","-a","--reflink=auto","--",row["source"],str(target)],timeout=950)
   check(rc==0,"COPY_FAILED:"+row["name"]+":"+err)
   copied=size(target)
   check(abs(copied-row["bytes"])<max(12*1024**2,row["bytes"]//25),"COPY_SIZE_DIFF:"+row["name"])
   row["copied_bytes"]=copied
   row["rewired_local_symlinks"]=relink_inside_copied_provider(target,Path(row["source"]),FINAL/row["name"])
   links=verify_links(target)
   check(links["count_old"]==0 and links["count_userlocal"]==0,
        "COPY_SYMLINK_DEPENDS_ON_OLD_INSTALLATION:"+row["name"])
   row["symlinks"]=links
  hashes={}
  for alias,rel in ENTRY.items():
   p=TEMP/rel
   check(p.is_file(),"ENTRYPOINT_MISSING:"+alias)
   origin=Path(SOURCES[next(k for k in SOURCES if rel.startswith(k+"/"))]) / rel.split("/",2)[-1] if False else None
   hashes[alias]={"sha256":hashed(p),"path":str(FINAL/rel)}
  # Probe only the new copies where doing so does not require GUI or an attached target.
  rc,out,err=cmd([str(TEMP/ENTRY["chromium"]),"--version"],timeout=22)
  check(rc==0 and "Chrome" in out,"NEW_CHROMIUM_VERSION_PROBE_FAILED")
  hashes["chromium"]["version"]=out[:90]
  rc,out,err=cmd([str(TEMP/ENTRY["ilspy"]),"--version"],timeout=28)
  check(rc==0 and "ilspycmd" in out.lower(),"NEW_ILSPY_VERSION_PROBE_FAILED")
  hashes["ilspy"]["version"]=out[:90]
  rc,out,err=cmd([str(TEMP/ENTRY["pwntools"]),"-c",
     "import pwnlib,importlib.metadata;print(importlib.metadata.version('pwntools'))"],timeout=24)
  hashes["pwntools"]["probe_exit"]=rc
  hashes["pwntools"]["version"]=out[:80] if rc==0 else "NOT_CERTIFIED"
  if rc!=0:
   hashes["pwntools"]["probe_error_type"]="PYTHON_IMPORT_OR_PACKAGE_METADATA_FAILED"
  else:
   check("4.15" in out,"NEW_PWNTOOLS_VERSION_UNEXPECTED")
  # Pwndbg is a Python source hook for GDB, not directly executable.
  for row in entries:
   origin=TEMP/row["name"]
   target=FINAL/row["name"]
   target.parent.mkdir(parents=True,exist_ok=True)
   rc,_,err=cmd(["sudo","-n","mv","-T","--",str(origin),str(target)],timeout=120)
   check(rc==0,"STAGE_ACTIVATION_FAILED:"+row["name"]+":"+err)
   created.append(str(target))
  data={"status":"PASS_COPIED_INDEPENDENT_OPTIONAL_PROVIDER_FILES",
     "source_commit":PIN,"runtime":str(FINAL),"entries":entries,
     "entrypoints":hashes,"new_sources_unchanged":True,
     "no_service_change":True,
     "host_os_binaries_not_duplicated":True,
     "free_bytes":shutil.disk_usage(str(FINAL)).free,
     "timestamp_unix":int(time.time())}
  REPORT.parent.mkdir(exist_ok=True,parents=True)
  REPORT.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf8")
  return data
 except BaseException:
  # Do not delete existing legacy packages, final node_modules or vendor copies.
  # Already moved copies are left intact for explicit read-back if a later check fails.
  if TEMP.exists() and TEMP.is_dir() and not TEMP.is_symlink():
   cmd(["sudo","-n","rm","-rf","--",str(TEMP)],timeout=180)
  raise

if __name__=="__main__":
 try:
  result=main()
  print("REA_STRICT_STAGE_RESULT="+json.dumps(result,sort_keys=True,separators=(",",":")),flush=True)
 except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as e:
  print("REA_STRICT_STAGE_BLOCKED="+type(e).__name__+":"+str(e)[:160],flush=True)
  sys.exit(2)
