#!/usr/bin/env python3
"""Targeted point-2 follow-up, using previous real observed evidence.

Recover actionable Hopper/Cutter/Chromium facts without downloading or
installing anything. Perform one real Frida spawn of a harmless owned local
program, never attach to unrelated processes and never use an MCP server.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029")
os.umask(0o077)

def stop_if(cond,reason):
    if not cond:raise RuntimeError(reason)

def read_json(name):
    p=EVID/name
    stop_if(p.is_file(),"PRIOR_EVIDENCE_MISSING_"+name)
    return json.loads(p.read_text(encoding="utf-8"))

def observe(args,env=None,timeout=90):
    try:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=timeout,text=True,
            encoding="utf-8",errors="replace",cwd=ROOT,env=env)
        return p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as exc:
        def cv(x):return x.decode("utf8",errors="replace") if isinstance(x,bytes) else (x or "")
        return 124,cv(exc.stdout),cv(exc.stderr)+"\nTIMEOUT"

def parsed(s):
    try:
        obj=json.loads(s)
        if isinstance(obj,dict) and isinstance(obj.get("result"),dict):
            obj=obj["result"]
        return obj
    except (ValueError,TypeError):
        return {}

def shortlist(obj,level=0):
    """Preserve only status keys, not freeform credential/trace/target data."""
    if level>4:return None
    fields=("name","id","status","healthy","passed","ok","code","category",
            "provider","provider_id","providerId","scope","reason","source",
            "availability","available","level","check_id","result","supported")
    if isinstance(obj,list):return [shortlist(x,level+1) for x in obj[:16]]
    if isinstance(obj,dict):
        result={}
        for k,v in obj.items():
            if k in fields and isinstance(v,(str,int,float,bool,type(None))):
                result[k]=v if not isinstance(v,str) else v[:130]
            elif k in ("checks","scope_checks","informational_checks","providerInspections",
                        "provider_inspections","diagnostics","scope","details","inspection","providers"):
                result[k]=shortlist(v,level+1)
        return result
    return str(obj)[:100]

def main():
    stop_if(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","SSH_PRINCIPAL_CHANGED")
    code,git,_=observe(["git","-C",str(ROOT),"rev-parse","HEAD"],timeout=15)
    stop_if(code==0 and git.strip()==REV,"OFFICIAL_SOURCE_CHANGED")
    audit=read_json("summary.json")
    stop_if(audit.get("source_revision")==REV and audit.get("capture_regression")=="PASS",
            "PRIOR_POINT2_NOT_CERTIFIED")
    print("REA_P2_FOLLOWUP_SOURCE_PIN=PASS",flush=True)
    print("REA_P2_FOLLOWUP_TRANSPORT=PINNED_SSH_ORIGINAL_CLI",flush=True)
    print("REA_P2_FOLLOWUP_NEW_INSTALLS=0",flush=True)
    for key in ("binwalk","cutter","chromium","frida","hopper"):
        info=audit["results"].get(key,{})
        print("REA_P2_FOLLOWUP_PREVIOUS_"+key.upper()+"="+info.get("status","UNKNOWN"),flush=True)
        if key=="chromium":
            print("REA_P2_FOLLOWUP_CHROMIUM_VERSION="+str(info.get("version_line",""))[:150],flush=True)
        if key=="cutter":
            print("REA_P2_FOLLOWUP_CUTTER_SESSIONS="+str(info.get("sessions_observed")),flush=True)
        if key=="frida":
            print("REA_P2_FOLLOWUP_FRIDA_DEVICES="+str(info.get("device_count")),flush=True)
    hopper_file=EVID/"hopper-doctor.stdout.txt"
    if hopper_file.is_file():
        doc=parsed(hopper_file.read_text(encoding="utf-8",errors="replace"))
        summarized=shortlist(doc)
        print("REA_P2_FOLLOWUP_HOPPER_DOCTOR="+json.dumps(summarized,ensure_ascii=False,separators=(",",":"))[:4800],flush=True)
        # Extract only well-defined check statuses, never dump raw output.
        checks=doc.get("scope_checks",doc.get("scopeChecks",[])) if isinstance(doc,dict) else []
        if isinstance(checks,list):
            for item in checks[:22]:
                if not isinstance(item,dict):continue
                print("REA_P2_FOLLOWUP_HOPPER_CHECK="+
                    json.dumps(shortlist(item),ensure_ascii=False,separators=(",",":"))[:320],flush=True)
    cutter_file=EVID/"cutter-original-sessions.stdout.txt"
    if cutter_file.is_file():
        cut=parsed(cutter_file.read_text(encoding="utf-8",errors="replace"))
        print("REA_P2_FOLLOWUP_CUTTER_KEYS="+
              str(list(cut)[:30] if isinstance(cut,dict) else type(cut).__name__),flush=True)
    # A real, short-lived, user-owned Frida spawn: no other process and no
    # persistent endpoint. Scripts are ORIGINAL, harmless literal send only.
    env=dict(os.environ)
    for k in tuple(env):
        if k.startswith("REA_") or k in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
            "HOPPER_LAUNCHER_PATH","PLAYWRIGHT_BROWSERS_PATH","PYTHONPATH","PYTHONHOME"):
            env.pop(k,None)
    env["PATH"]=str(NODE.parent)+":"+env.get("PATH","")
    env["CI"]="1"
    js="send('REA_P2_OWNED_FRIDA_SPAWN_PASS')"
    cmd=[str(NODE),"scripts/rea.mjs",
         "instrument-with-frida","spawn","/usr/bin/sleep",
         "--argument","1",
         "--script",js,"--duration-ms","300","--json"]
    rc,out,err=observe(cmd,env,timeout=75)
    (EVID/"frida-real-controlled-spawn.stdout.json").write_text(out[:3*1024*1024],encoding="utf8")
    (EVID/"frida-real-controlled-spawn.stderr.txt").write_text(err[:1024*1024],encoding="utf8")
    obj=parsed(out)
    norm=obj.get("normalized_result",{}) if isinstance(obj,dict) else {}
    if not isinstance(norm,dict):norm={}
    incomplete="cleanup_incomplete" in (out+err).lower()
    ok=rc==0 and bool(norm) and not incomplete
    print("REA_P2_FRIDA_REAL_OWNED_SPAWN="+("PASS" if ok else "BLOCKED")+
          ";exit="+str(rc)+";cleanup_incomplete="+str(incomplete).lower(),flush=True)
    if not ok:
        error=obj.get("error",obj) if isinstance(obj,dict) else {}
        if not isinstance(error,dict):error={}
        print("REA_P2_FRIDA_REAL_ERROR="+
              json.dumps({"code":error.get("code"),"message":str(error.get("message",""))[:270],
              "reason":str(error.get("details",{}).get("reason",""))[:150]
                if isinstance(error.get("details"),dict) else ""},
              ensure_ascii=False),flush=True)
    else:
        print("REA_P2_FRIDA_REAL_RESULT_KEYS="+str(list(norm)[:30]),flush=True)
    result={"real_frida_spawn":"PASS" if ok else "BLOCKED",
        "exit":rc,"normalized_keys":list(norm)[:25],
        "cleanup_incomplete":incomplete,
        "hopper_doctor":shortlist(doc) if hopper_file.is_file() else None}
    (EVID/"followup.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf8")
    print("REA_P2_FOLLOWUP=COMPLETE",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print("REA_P2_FOLLOWUP_FATAL="+type(e).__name__+":"+str(e)[:160],flush=True)
        sys.exit(45)
