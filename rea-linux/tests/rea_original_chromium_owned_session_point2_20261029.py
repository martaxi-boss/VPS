#!/usr/bin/env python3
"""Confirm Chromium + REA original CDP support with an owned ephemeral local browser.

No persistent server, port registration, new MCP, new software, changing
user profiles, or real websites. Never disable Chromium sandbox.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import time

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
os.umask(0o077)

def run(a,env=None,timeout=30):
    try:
        p=subprocess.run(a,cwd=ROOT,env=env,
          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
          encoding="utf8",errors="replace",timeout=timeout)
        return p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as exc:
        def cv(s):return s.decode("utf8",errors="replace") if isinstance(s,bytes) else (s or "")
        return 124,cv(exc.stdout),cv(exc.stderr)+"\nTIMEOUT"
    except OSError as exc:return 126,"",type(exc).__name__+":"+str(exc)[:130]

def pparse(text):
    try:
        obj=json.loads(text)
        if isinstance(obj,dict) and isinstance(obj.get("result"),dict):obj=obj["result"]
        return obj if isinstance(obj,dict) else {}
    except (ValueError,TypeError):return {}

def find_browser():
    vendor=Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2")
    if not vendor.is_dir():return None
    for base,dirs,files in os.walk(vendor,followlinks=False):
        dirs[:]=[x for x in dirs if x not in ("locales","resources","node_modules",".git","swiftshader")]
        for name in ("chrome","chromium","headless_shell","chrome-headless-shell"):
            if name in files:
                path=Path(base)/name
                if path.is_file() and os.access(path,os.X_OK):return path
    return None

def main():
    if pwd.getpwuid(os.geteuid()).pw_name!="ubuntu":raise RuntimeError("UBUNTU_REQUIRED")
    code,out,err=run(["git","-C",str(ROOT),"rev-parse","HEAD"],timeout=12)
    if code!=0 or out.strip()!=REV:raise RuntimeError("OFFICIAL_REV_CHANGED")
    audit=EVID/"summary.json"
    if not audit.is_file() or json.loads(audit.read_text()).get("capture_regression")!="PASS":
        raise RuntimeError("PRIOR_SUPPLIER_TEST_MISSING")
    browser=find_browser()
    if browser is None:raise RuntimeError("EXISTING_BROWSER_NOT_FOUND")
    profile=EVID/"browser-owned-ephemeral-profile"
    if profile.exists():raise RuntimeError("EXISTING_BROWSER_PROFILE_MUST_NOT_BE_TOUCHED")
    profile.mkdir(mode=0o700)
    env=dict(os.environ)
    for name in list(env):
        if name.startswith("REA_") or name in ("PLAYWRIGHT_BROWSERS_PATH","PYTHONPATH","PYTHONHOME","JAVA_HOME"):
            env.pop(name,None)
    env["PATH"]=str(NODE.parent)+":"+env.get("PATH","")
    env["HOME"]=str(profile)
    env["XDG_CACHE_HOME"]=str(profile/"cache")
    env["XDG_CONFIG_HOME"]=str(profile/"config")
    env["XDG_DATA_HOME"]=str(profile/"data")
    env["CI"]="1"
    outcome={"browser":str(browser),"browser_launch":"NOT_ATTEMPTED",
             "original_rea_cdp":"NOT_ATTEMPTED",
             "cleanup":"NOT_ATTEMPTED","old_mcp_used":False,
             "services_installed":0,"sandbox_disabled":False}
    pid=None
    stderr_path=EVID/"browser-launch.stderr"
    stdout_path=EVID/"browser-launch.stdout"
    stdout_file=stdout_path.open("w",encoding="utf8")
    stderr_file=stderr_path.open("w",encoding="utf8")
    try:
        args=[str(browser),"--headless=new","--disable-gpu",
          "--no-first-run","--no-default-browser-check",
          "--remote-debugging-address=127.0.0.1","--remote-debugging-port=0",
          "--user-data-dir="+str(profile),
          "data:text/html,%3Ctitle%3EREA%20local%20test%3C%2Ftitle%3E%3Cp%3EREA%20read-only%20Chromium%20smoke%3C%2Fp%3E"]
        # Isolated process group only; no sudo, no change to existing profiles.
        proc=subprocess.Popen(args,env=env,cwd=str(EVID),
              stdin=subprocess.DEVNULL,stdout=stdout_file,stderr=stderr_file,
              start_new_session=True)
        pid=proc.pid
        print("REA_P2_CHROMIUM_OWNED_SESSION_STARTED=YES",flush=True)
        active=profile/"DevToolsActivePort"
        port=None
        for _ in range(90):
            if active.is_file():
                text=active.read_text(encoding="utf8",errors="replace")
                first=text.splitlines()[0] if text.splitlines() else ""
                if first.isdigit() and 0<int(first)<65536:
                    port=int(first);break
            if proc.poll() is not None:break
            time.sleep(0.12)
        if port is None:
            outcome["browser_launch"]="NO_CDP_PORT"
            print("REA_P2_CHROMIUM_PRIVATE_CDP=BLOCKED;exit="+str(proc.poll()),flush=True)
        else:
            outcome["browser_launch"]="PASS_CDP_LOOPBACK"
            outcome["private_port_selected"]=True
            print("REA_P2_CHROMIUM_PRIVATE_CDP=PASS",flush=True)
            r,out,err=run([str(NODE),"scripts/rea.mjs","list-browser-targets",
                  "http://127.0.0.1:"+str(port),"--json"],env,timeout=48)
            (EVID/"chromium-original-rea-cdp.json").write_text(out[:3*1024*1024],encoding="utf8")
            (EVID/"chromium-original-rea-cdp.stderr").write_text(err[:50000],encoding="utf8")
            obj=pparse(out)
            norm=obj.get("normalized_result",{})
            data=norm if isinstance(norm,dict) else {}
            target=data.get("targets",[])
            count=len(target) if isinstance(target,list) else None
            success=r==0 and bool(obj) and "cleanup_incomplete" not in (out+err).lower()
            outcome["original_rea_cdp"]="PASS" if success else "FAIL"
            outcome["target_count"]=count
            outcome["cli_exit"]=r
            outcome["normalized_keys"]=list(data)[:24]
            if not success:
                outcome["cli_error_code"]=obj.get("code")
                outcome["cli_message"]=str(obj.get("message",""))[:220]
            print("REA_P2_CHROMIUM_REA_CDP="+("PASS" if success else "FAIL")+
                  ";targets="+str(count)+";exit="+str(r),flush=True)
    finally:
        stdout_file.close()
        stderr_file.close()
        if pid is not None:
            try:os.killpg(pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait(timeout=5)
        outcome["cleanup"]="PASS" if (pid is None or proc.poll() is not None) else "FAIL"
        # A private browser profile is not needed after the evidence is written.
        try:shutil.rmtree(profile)
        except (OSError,PermissionError):
            outcome["cleanup"]="PARTIAL_PROFILE_REMAINING"
        (EVID/"chromium-ephemeral-acceptance.json").write_text(
            json.dumps(outcome,indent=2,sort_keys=True),encoding="utf8")
        print("REA_P2_CHROMIUM_OWNED_CLEANUP="+outcome["cleanup"],flush=True)
        print("REA_P2_CHROMIUM_OWNED_TEST="+outcome["original_rea_cdp"],flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("REA_P2_CHROMIUM_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
