#!/usr/bin/env python3
"""Point 2: run non-destructive, real REA 6.8.0 readiness tests for existing suppliers.

Uses only existing GitHub Actions -> pinned SSH -> ubuntu -> original REA CLI.
No service or listener is started, no provider install, no new MCP, no
external user targets or mobile/GUI interaction, no edits to REA source.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
PREVIOUS=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
ORIGINAL_DIGEST={
    "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
    "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)
observed={}
evidence_calls=[]

def assert_expected(cond,why):
    if not cond:raise RuntimeError(why)

def execute(args,environment=None,deadline=35):
    begin=time.monotonic()
    try:
        p=subprocess.run(args,cwd=ROOT,env=environment,
          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
          text=True,encoding="utf-8",errors="replace",timeout=deadline,check=False)
        return p.returncode,p.stdout,p.stderr,round(time.monotonic()-begin,3)
    except subprocess.TimeoutExpired as exc:
        def decode(x):return x.decode("utf-8",errors="replace") if isinstance(x,bytes) else (x or "")
        return 124,decode(exc.stdout),decode(exc.stderr)+"\nDEADLINE",round(time.monotonic()-begin,3)
    except (OSError,PermissionError) as exc:
        return 126,"",type(exc).__name__+":"+str(exc)[:200],round(time.monotonic()-begin,3)

def preflight():
    assert_expected(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","ONLY_SSH_UBUNTU")
    assert_expected(ROOT.is_dir() and not ROOT.is_symlink(),"OFFICIAL_REA_MISSING")
    assert_expected(NODE.is_file(),"EXISTING_NODE_MISSING")
    assert_expected((ROOT/"node_modules").is_symlink(),"DEPENDENCIES_REPLACED")
    assert_expected((ROOT/"node_modules").resolve()==(PREVIOUS/"node_modules").resolve(),"DEPENDENCIES_LINK_CHANGED")
    assert_expected((ROOT/"package-lock.json").read_bytes()==(PREVIOUS/"package-lock.json").read_bytes(),"LOCKFILE_DIVERGENCE")
    code,out,err,_=execute(["git","-C",str(ROOT),"rev-parse","HEAD"])
    assert_expected(code==0 and out.strip()==REV,"OFFICIAL_REA_COMMIT_CHANGED")
    for name,digest in ORIGINAL_DIGEST.items():
        f=ROOT/name
        assert_expected(f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==digest,
                        "OFFICIAL_REA_BINARY_HASH_CHANGED_"+name)
    assert_expected(EVID.parent.is_dir(),"EXPECTED_EVIDENCE_ROOT_MISSING")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_P2_OFFICIAL_680=PINNED_VERIFIED",flush=True)
    print("REA_P2_TRANSPORT=EXISTING_GITHUB_ACTIONS_SSH_ORIGINAL_CLI",flush=True)
    print("REA_P2_OLD_MCP=UNUSED",flush=True)
    print("REA_P2_NEW_INSTALLATIONS=ZERO",flush=True)

def environment():
    e=dict(os.environ)
    for k in list(e):
        if k.startswith("REA_") or k in ("JAVA_HOME","HOPPER_LAUNCHER_PATH",
             "PLAYWRIGHT_BROWSERS_PATH","GHIDRA_INSTALL_DIR","VIRTUAL_ENV",
             "PYTHONPATH","PYTHONHOME"):
            e.pop(k,None)
    h=EVID/"isolated-home"
    h.mkdir(parents=True,exist_ok=True,mode=0o700)
    e["HOME"]=str(h)
    e["XDG_CACHE_HOME"]=str(h/".cache")
    e["XDG_CONFIG_HOME"]=str(h/".config")
    e["XDG_DATA_HOME"]=str(h/".local/share")
    e["PATH"]=str(NODE.parent)+":"+e.get("PATH","")
    e["CI"]="1"
    return e

def trace(label,cmd,env,deadline=40):
    rc,stdout,stderr,seconds=execute(cmd,environment=env,deadline=deadline)
    (EVID/(label+".stdout.txt")).write_text(stdout[:6*1024*1024],encoding="utf-8",errors="replace")
    (EVID/(label+".stderr.txt")).write_text(stderr[:6*1024*1024],encoding="utf-8",errors="replace")
    rec={"exit":rc,"seconds":seconds,
         "cleanup_incomplete":"cleanup_incomplete" in (stdout+stderr).lower(),
         "stdout_sha256":hashlib.sha256(stdout.encode()).hexdigest(),
         "stdout_length":len(stdout),"stderr_length":len(stderr)}
    evidence_calls.append({"name":label,**rec})
    return rc,stdout,stderr,rec

def parse(raw):
    try:
        obj=json.loads(raw)
        if isinstance(obj,dict) and isinstance(obj.get("result"),dict):
            obj=obj["result"]
        if isinstance(obj,dict):
            return obj
    except (TypeError,ValueError):
        pass
    return {}

def report(label,state,facts):
    observed[label]={"status":state,**facts}
    print("REA_P2_"+label.upper()+"="+state,flush=True)

def possible_binwalk():
    paths=["/usr/bin/binwalk","/usr/local/bin/binwalk",
       "/home/ubuntu/.cargo/bin/binwalk","/root/.cargo/bin/binwalk"]
    roots=[Path("/opt/rea-reversa/providers"),Path("/opt/rea-reversa/tools"),
           Path("/home/ubuntu/.local/bin")]
    for base in roots:
        if not base.is_dir():continue
        for glob in ("binwalk*","binwalk*/bin/binwalk","binwalk*/target/release/binwalk",
                     "*/bin/binwalk","*/binwalk"):
            paths.extend(str(p) for p in sorted(base.glob(glob))[:25])
    found=[]
    for candidate in paths:
        if candidate in found:continue
        try:
            if Path(candidate).is_file() and os.access(candidate,os.X_OK):
                found.append(candidate)
        except (OSError,PermissionError):pass
    return found

def binwalk(e):
    found=possible_binwalk()
    versions=[]
    selected=None
    for i,path in enumerate(found[:20]):
        rc,out,err,info=trace("binwalk-version-"+str(i),[path,"--version"],e,deadline=22)
        line=(out+"\n"+err).strip().splitlines()
        banner=line[0][:190] if line else ""
        # The official REA 6.8.0 accepts an exact 3.1.x version banner.
        match=re.search(r"(?m)^binwalk\s+(3\.1\.\d+)(?:\s|$)",out)
        versions.append({"path":path,"version_rc":rc,"first_line":banner,
            "binwalk_3_1_compatible":rc==0 and match is not None})
        print("REA_P2_BINWALK_CANDIDATE="+path+";rc="+str(rc)+
              ";first_line="+banner[:160],flush=True)
        if selected is None and rc==0 and match:
            selected=path
        # Diagnostic-only help when version does not work; never guess.
        if rc!=0:
            helper,helpout,helperr,_=trace("binwalk-help-"+str(i),[path,"--help"],e,deadline=20)
            versions[-1]["help_rc"]=helper
            versions[-1]["help_first_line"]=(helpout+"\n"+helperr).strip()[:240]
    if not found:
        report("binwalk","MISSING",{"candidates":0})
        return
    fixture=EVID/"firmware-binwalk-probe.bin"
    fixture.write_bytes(b"\x00"*64+gzip.compress(b"REA_ORIGINAL_BINWALK_REAL_TEST\n"*250,mtime=0)+b"\x00"*80)
    original_hash=hashlib.sha256(fixture.read_bytes()).hexdigest()
    # Choose already available compatible binary only, never change default PATH.
    chosen=selected if selected is not None else found[0]
    ee=e.copy()
    ee["REA_BINWALK_COMMAND"]=chosen
    rc,out,err,info=trace("binwalk-original-cli",[
       str(NODE),"scripts/rea.mjs","inspect-firmware-regions",str(fixture),"--json"],ee,deadline=100)
    obj=parse(out)
    norm=obj.get("normalized_result",{})
    if not isinstance(norm,dict):norm={}
    code=obj.get("code",obj.get("error",{}).get("code")
          if isinstance(obj.get("error"),dict) else None)
    regions=norm.get("regions",[])
    if not isinstance(regions,list):regions=[]
    digest_preserved=hashlib.sha256(fixture.read_bytes()).hexdigest()==original_hash
    if selected is not None and rc==0 and bool(norm) and len(regions)>0 and digest_preserved and not info["cleanup_incomplete"]:
        status="PASS_REAL_INSPECTION"
    elif selected is None:
        status="INCOMPATIBLE_OR_INACCESSIBLE_VERSION"
    elif rc!=0:
        status="ORIGINAL_CLI_REJECTED"
    else:
        status="INSPECTION_NOT_PROVEN"
    report("binwalk",status,{"candidates":versions,
        "selected_for_original_cli":chosen,"original_cli_exit":rc,
        "original_cli_error_code":code,
        "original_cli_error_message":str(obj.get("message",""))[:270],
        "normalized_keys":list(norm)[:30],"regions":len(regions),
        "controlled_fixture_hash_preserved":digest_preserved,
        "cleanup_incomplete":info["cleanup_incomplete"]})
    print("REA_P2_BINWALK_REA_EXIT="+str(rc)+
          ";error_code="+str(code)+";regions="+str(len(regions)),flush=True)

def cutter(e):
    program=Path("/opt/rea-reversa/providers/cutter-2.5.0/bin/Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage")
    exists=program.is_file() and os.access(program,os.X_OK)
    # Only session discovery; does not start GUI, open documents or send commands.
    rc,out,err,info=trace("cutter-original-sessions",[
       str(NODE),"scripts/rea.mjs","list-cutter-sessions","--json"],e,deadline=35)
    obj=parse(out)
    norm=obj.get("normalized_result",{})
    count=None
    if isinstance(norm,dict):
        for key in ("sessions","instances"):
            value=norm.get(key)
            if isinstance(value,list):count=len(value);break
    if count is None and isinstance(norm,list):count=len(norm)
    if exists and rc==0:
        status="DISCOVERY_PASS_ACTIVE_SESSION" if count else "INSTALLED_NO_ACTIVE_GUI_BRIDGE"
    elif exists:
        status="INSTALLED_DISCOVERY_UNAVAILABLE"
    else:status="PROGRAM_NOT_FOUND"
    report("cutter",status,{"program_present":exists,"program_path":str(program),
       "cli_exit":rc,"sessions_observed":count,
       "cli_error_code":obj.get("code"),
       "cli_message":str(obj.get("message",""))[:220],
       "cleanup_incomplete":info["cleanup_incomplete"]})

def chromium(e):
    vendor=Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2")
    candidates=[]
    if vendor.is_dir():
        for base,dirs,files in os.walk(vendor,followlinks=False):
            dirs[:]=[d for d in dirs if d not in ("locales","resources","node_modules",".git","swiftshader")]
            if len(candidates)>=3:break
            for name in ("chrome","chromium","headless_shell","chrome-headless-shell"):
                if name in files:
                    path=Path(base)/name
                    if path.is_file() and os.access(path,os.X_OK):
                        candidates.append(str(path))
    if not candidates:
        report("chromium","BROWSER_EXECUTABLE_NOT_FOUND",{"vendor_root":vendor.is_dir()})
        return
    exe=candidates[0]
    # Version only: never open another project's CDP port or a user profile.
    rc,out,err,info=trace("chromium-existing-version",[exe,"--version"],e,deadline=18)
    version=(out+"\n"+err).strip().splitlines()
    status="INSTALLED_BINARY_PASS_SESSION_NOT_STARTED" if rc==0 else "INSTALLED_VERSION_PROBE_FAILED"
    report("chromium",status,{"path":exe,"version_line":version[0][:135] if version else "",
       "exit":rc,"live_cdp_session_proven":False})

def frida(e):
    # Real official REA Frida device discovery; does not attach to any
    # application, start frida-server or require an Android device.
    rc,out,err,info=trace("frida-original-device-discovery",[
       str(NODE),"scripts/rea.mjs","list-frida-devices","--json"],e,deadline=45)
    obj=parse(out)
    norm=obj.get("normalized_result",{})
    devices=None
    if isinstance(norm,dict):
        for key in ("devices","device_list"):
            if isinstance(norm.get(key),list):
                devices=len(norm[key]);break
    status="PASS_DISCOVERY_NO_TARGET_CLAIM" if rc==0 and bool(obj) and not info["cleanup_incomplete"] else "FRIDA_DISCOVERY_FAILED"
    report("frida",status,{"node_binding_present":(ROOT/"node_modules/frida").exists(),
       "cli_exit":rc,"device_count":devices,
       "normalized_keys":list(norm)[:25] if isinstance(norm,dict) else [],
       "cli_error_code":obj.get("code"),"cli_message":str(obj.get("message",""))[:250],
       "cleanup_incomplete":info["cleanup_incomplete"]})

def hopper(e):
    exe=Path("/opt/hopper/bin/Hopper")
    exists=exe.is_file() and os.access(exe,os.X_OK)
    if not exists:
        report("hopper","LAUNCHER_MISSING",{"path":str(exe)})
        return
    # Doctor's --provider scope performs read-only inspection only.
    ee=e.copy();ee["HOPPER_LAUNCHER_PATH"]=str(exe)
    rc,out,err,info=trace("hopper-doctor",[
      str(NODE),"scripts/rea.mjs","doctor","--provider","hopper","--json"],ee,deadline=75)
    obj=parse(out)
    status="DOCTOR_PROVIDER_PASS_GUI_NOT_TESTED" if rc==0 else "INSTALLED_DOCTOR_NOT_READY"
    info_obj=obj.get("providerInspections",obj.get("provider_inspections",{}))
    # Doctor schema may contain license metadata; do not print entire report.
    report("hopper",status,{"launcher_present":exists,
       "doctor_exit":rc,"doctor_keys":list(obj)[:22],
       "provider_inspection_type":type(info_obj).__name__,
       "gui_license_or_demo_session_proven":False,
       "cleanup_incomplete":info["cleanup_incomplete"]})

def regression(e):
    for n in (8,30):
        payload=("import subprocess; a=[subprocess.Popen(['/usr/bin/true']) "
            "for _ in range("+str(n)+")];codes=[p.wait() for p in a];"
            "print('OWNED_CHILDREN='+str(len(codes)))")
        file=EVID/("capture-"+str(n)+".scenario.json")
        file.write_text(json.dumps({"executable":"/usr/bin/python3",
            "arguments":["-c",payload],"timeout_ms":24000}),encoding="utf-8")
        rc,out,err,info=trace("capture-"+str(n),[
            str(NODE),"scripts/rea.mjs","capture-process",str(file),"--json"],
            e,deadline=70)
        result=parse(out).get("normalized_result",{})
        if not isinstance(result,dict):result={}
        cleanup=result.get("cleanup",{})
        exit_=result.get("exit",{})
        ok=rc==0 and not info["cleanup_incomplete"] and isinstance(cleanup,dict) and (
               cleanup.get("owned_process_group") in ("verified","cleaned")) and (
               cleanup.get("temporary_root") in ("removed","cleaned")) and (
               isinstance(exit_,dict) and exit_.get("code")==0)
        report("capture_"+str(n),"PASS" if ok else "FAIL",{
           "exit_code":rc,"cleanup":cleanup,
           "cleanup_incomplete":info["cleanup_incomplete"]})

def main():
    preflight()
    e=environment()
    binwalk(e)
    cutter(e)
    chromium(e)
    frida(e)
    hopper(e)
    regression(e)
    all_capture=all(observed.get("capture_"+str(i),{}).get("status")=="PASS" for i in (8,30))
    warnings=[k for k,v in observed.items() if not v["status"].startswith(("PASS","DOCTOR_PROVIDER_PASS","INSTALLED_BINARY_PASS","DISCOVERY_PASS"))]
    summary={"source_revision":REV,"transport":"GITHUB_ACTIONS_SSH_ORIGINAL_CLI",
         "old_mcp_used":False,"new_suppliers_installed":0,
         "rea_original_modified":False,"other_projects_modified":False,
         "results":observed,"commands":evidence_calls,
         "capture_regression":"PASS" if all_capture else "FAIL",
         "vendor_attention":warnings}
    (EVID/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True),encoding="utf-8")
    print("REA_P2_REPORT="+str(EVID/"summary.json"),flush=True)
    print("REA_P2_CLEANUP_REGRESSION="+summary["capture_regression"],flush=True)
    print("REA_P2_DIAGNOSTIC=COMPLETE",flush=True)
    return 0 if all_capture else 41

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print("REA_P2_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(42)
