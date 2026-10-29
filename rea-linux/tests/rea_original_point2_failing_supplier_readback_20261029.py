#!/usr/bin/env python3
"""Read-only evidence readback for point 2's headless Chromium and GUI suppliers.

No new processes other than bounded read-only diagnostic commands. Never
disable browser sandbox or start GUI services.
"""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029")
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"

def proc(a,seconds=12):
    try:
        p=subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
              encoding="utf8",errors="replace",text=True,timeout=seconds,
              cwd=ROOT,stdin=subprocess.DEVNULL,check=False)
        return p.returncode,p.stdout,p.stderr
    except Exception as e:return 126,"",type(e).__name__

def original():
    if pwd.getpwuid(os.geteuid()).pw_name!="ubuntu":raise RuntimeError("NOT_UBUNTU")
    rc,x,err=proc(["git","-C",str(ROOT),"rev-parse","HEAD"])
    if rc or x.strip()!=REV:raise RuntimeError("SOURCE_CHANGED")
    if not EVID.is_dir() or not (EVID/"chromium-ephemeral-acceptance.json").is_file():
        raise RuntimeError("PREVIOUS_TEST_MISSING")

def text_env(path):
    p=Path(path)
    try:return p.read_text(encoding="utf8",errors="replace").strip()[:70]
    except (OSError,PermissionError):return "UNAVAILABLE"

def main():
    original()
    previous=json.loads((EVID/"summary.json").read_text())
    browser=json.loads((EVID/"chromium-ephemeral-acceptance.json").read_text())
    for k in ("browser_launch","original_rea_cdp","cleanup","sandbox_disabled"):
        print("REA_P2_FINAL_CHROMIUM_"+k.upper()+"="+str(browser.get(k)),flush=True)
    stderr=EVID/"browser-launch.stderr"
    if stderr.exists():
        data=stderr.read_text(encoding="utf8",errors="replace")
        rules=re.compile(r"fatal|error|crash|sandbox|trap|namespace|zygote|apparmor|unable|failed|not found|denied|abort|missing|seccomp",re.I)
        lines=[line[:260] for line in data.splitlines() if rules.search(line)]
        # Never emit paths outside our test and machine-level system diagnostics.
        excerpts=lines[:15]
        print("REA_P2_FINAL_CHROMIUM_STDERR="+json.dumps(excerpts,ensure_ascii=False)[:4400],flush=True)
        print("REA_P2_FINAL_CHROMIUM_STDERR_LENGTH="+str(len(data)),flush=True)
    binary=Path(browser.get("browser","/missing"))
    if binary.is_file():
        rc,out,err=proc(["/usr/bin/ldd",str(binary)],seconds=14)
        missing=[x.strip()[:200] for x in out.splitlines() if "not found" in x.lower()]
        print("REA_P2_FINAL_CHROMIUM_LDD_MISSING="+json.dumps(missing[:22]),flush=True)
    print("REA_P2_FINAL_KERNEL_APPARMOR_USERNS="+
        text_env("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),flush=True)
    print("REA_P2_FINAL_KERNEL_USERNS_ENABLED="+
        text_env("/proc/sys/kernel/unprivileged_userns_clone"),flush=True)
    from shutil import which
    print("REA_P2_FINAL_XVFB_AVAILABLE="+str(which("Xvfb") is not None).lower(),flush=True)
    print("REA_P2_FINAL_DISPLAY_ACTIVE="+str(bool(os.getenv("DISPLAY"))).lower(),flush=True)
    cutter=EVID/"cutter-original-sessions.stdout.txt"
    if cutter.is_file():
        try:
            cut=json.loads(cutter.read_text(encoding="utf8",errors="replace"))
            if isinstance(cut,dict) and isinstance(cut.get("result"),dict):cut=cut["result"]
            norm=cut.get("normalized_result",{}) if isinstance(cut,dict) else {}
            if isinstance(norm,dict):
                st=norm.get("discovery_status")
                sr=norm.get("bridge_directory_security")
                sessions=norm.get("sessions")
                print("REA_P2_FINAL_CUTTER_DISCOVERY_STATUS="+
                    str(st)[:150],flush=True)
                print("REA_P2_FINAL_CUTTER_SESSIONS_TYPE="+
                    type(sessions).__name__,flush=True)
                if isinstance(sessions,list):
                    print("REA_P2_FINAL_CUTTER_ACTIVE_SESSIONS="+str(len(sessions)),flush=True)
                print("REA_P2_FINAL_CUTTER_SECURITY_KEYS="+
                    str(list(sr)[:15] if isinstance(sr,dict) else type(sr).__name__),flush=True)
        except ValueError:print("REA_P2_FINAL_CUTTER_PARSE=UNKNOWN",flush=True)
    hopper=previous.get("results",{}).get("hopper",{})
    print("REA_P2_FINAL_HOPPER_STATUS="+str(hopper.get("status")),flush=True)
    print("REA_P2_FINAL_BINWALK_SELECTION="+
          str(previous.get("results",{}).get("binwalk",{}).get("selected_for_original_cli")),flush=True)
    print("REA_P2_FINAL_STATUS=READ_ONLY_FACTS",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print("REA_P2_FINAL_FATAL="+type(e).__name__+":"+str(e)[:140],flush=True)
        sys.exit(44)
