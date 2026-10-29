#!/usr/bin/env python3
"""Check preinstalled Apktool 2.7+ through real, unmodified REA 6.8.0 CLI.

Use only established GitHub Actions -> pinned SSH -> ubuntu -> official REA CLI.
The known public Appium ApiDemos APK was SHA-pinned in the previous step-2
functional test. No new tools/MCP, no install, no APK from user projects.
"""
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

ORIG=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
JDK=Path("/opt/rea-reversa/tools/jdk-21")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/apktool-original-20261029")
APK=Path("/home/ubuntu/rea-original-upstream-680-evidence/functional-suppliers-step2-20261029/ApiDemos-debug.apk")
APK_SHA="a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686"
COMMIT="160d821ac9a0310afcb8d1fc427862dd6508add5"
BUILT={
 "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
 "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)
checks=[]
runs=[]

def require(value,name):
    if not value:raise RuntimeError(name)

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda:fp.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def cmd(parts,env=None,timeout=45):
    start=time.monotonic()
    try:
        p=subprocess.run(parts,cwd=ORIG,env=env,text=True,encoding="utf8",
           errors="replace",stdout=subprocess.PIPE,stderr=subprocess.PIPE,
           timeout=timeout,check=False)
        return p.returncode,p.stdout,p.stderr,round(time.monotonic()-start,3)
    except subprocess.TimeoutExpired as e:
        def dec(v):return v.decode("utf8",errors="replace") if isinstance(v,bytes) else (v or "")
        return 124,dec(e.stdout),dec(e.stderr)+"\nTIMEOUT",round(time.monotonic()-start,3)
    except (OSError,PermissionError) as e:
        return 126,"",type(e).__name__+":"+str(e)[:180],round(time.monotonic()-start,3)

def persist(label,text,suffix):
    (EVID/(label+"."+suffix)).write_text(text,encoding="utf8",errors="replace")

def preflight():
    require(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","UNPRIVILEGED_UBUNTU_REQUIRED")
    require(ORIG.is_dir() and not ORIG.is_symlink(),"ORIGINAL_CHECKOUT_NOT_FOUND")
    require(NODE.is_file(),"EXISTING_NODE_NOT_FOUND")
    require((ORIG/"node_modules").is_symlink(),"DEPENDENCIES_NOT_REUSED")
    require((ORIG/"node_modules").resolve()==(OLD/"node_modules").resolve(),
            "DEPENDENCY_TREE_CHANGED")
    require((ORIG/"package-lock.json").read_bytes()==(OLD/"package-lock.json").read_bytes(),
            "DEPENDENCY_LOCK_CHANGED")
    rc,out,err,_=cmd(["git","-C",str(ORIG),"rev-parse","HEAD"],timeout=10)
    require(rc==0 and out.strip()==COMMIT,"OFFICIAL_UPSTREAM_COMMIT_CHANGED")
    for item,digest in BUILT.items():
        target=ORIG/item
        require(target.is_file() and sha(target)==digest,"ORIGINAL_SOURCE_HASH_CHANGED:"+item)
    require(EVID.parent.is_dir(),"EVIDENCE_BASE_NOT_FOUND")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    require(JDK.is_dir() and (JDK/"bin/java").is_file(),"EXISTING_JDK_21_UNAVAILABLE")
    require(APK.is_file() and sha(APK)==APK_SHA,"PINNED_PUBLIC_TEST_APK_MISSING_OR_CHANGED")
    print("REA_APKTOOL_ORIGINAL_OFFICIAL=PASS",flush=True)
    print("REA_APKTOOL_PUBLIC_APK_SHA_VERIFIED=PASS",flush=True)
    print("REA_APKTOOL_CONNECTION=GITHUB_ACTIONS_SSH_ORIGINAL_CLI_NO_MCP",flush=True)
    print("REA_APKTOOL_PROVIDER_INSTALLS=ZERO",flush=True)

def env_and_bin():
    h=EVID/"isolated-home"
    h.mkdir(mode=0o700,parents=True,exist_ok=True)
    env=dict(os.environ)
    for k in tuple(env):
        if k.startswith("REA_") or k in (
            "JAVA_HOME","GHIDRA_INSTALL_DIR","HOPPER_LAUNCHER_PATH",
            "PLAYWRIGHT_BROWSERS_PATH"):
            env.pop(k,None)
    env["HOME"]=str(h)
    env["XDG_CACHE_HOME"]=str(h/".cache")
    env["XDG_CONFIG_HOME"]=str(h/".config")
    env["XDG_DATA_HOME"]=str(h/".local/share")
    env["JAVA_HOME"]=str(JDK)
    env["PATH"]=str(JDK/"bin")+":"+str(NODE.parent)+":"+env.get("PATH","")
    env["CI"]="1"
    chosen=shutil.which("apktool",path=env["PATH"])
    if not chosen:return env,None
    p=Path(chosen)
    if not p.is_absolute() or not p.is_file() or not os.access(p,os.X_OK):
        return env,None
    env["REA_APKTOOL_COMMAND"]=str(p)
    return env,p

def evidence(label,args,env,timeout=150):
    rc,out,err,secs=cmd([str(NODE),"scripts/rea.mjs",*args,"--json"],env,timeout)
    persist(label,out,"json")
    persist(label,err,"stderr")
    try:
        obj=json.loads(out)
        if isinstance(obj,dict) and isinstance(obj.get("result"),dict):
            obj=obj["result"]
        if not isinstance(obj,dict):obj={}
    except (ValueError,TypeError):obj={}
    norm=obj.get("normalized_result",{})
    if not isinstance(norm,dict):norm={}
    incomplete="cleanup_incomplete" in (out+err).lower()
    runs.append({"operation":label,"exit":rc,"seconds":secs,
                 "cleanup_incomplete":incomplete,
                 "normalized_keys":list(norm)[:30],
                 "stdout_sha256":hashlib.sha256(out.encode()).hexdigest()})
    print("REA_APKTOOL_RUN="+label+";exit="+str(rc)+
          ";secs="+str(secs)+";cleanup_incomplete="+str(incomplete).lower(),
          flush=True)
    return (rc==0 and bool(obj) and not incomplete),obj,norm

def check(name,cond,detail):
    checks.append({"name":name,"result":"PASS" if cond else "FAIL","details":detail})
    print("REA_APKTOOL_TEST="+name+";result="+("PASS" if cond else "FAIL"),flush=True)
    return cond

def capture(env,n):
    payload=("import subprocess; p=[subprocess.Popen(['/usr/bin/true']) "
             "for _ in range("+str(n)+")]; r=[x.wait() for x in p]; "
             "print('CHILDREN='+str(len(r)))")
    scenario=EVID/("capture-"+str(n)+".scenario.json")
    scenario.write_text(json.dumps({"executable":"/usr/bin/python3",
                      "arguments":["-c",payload],"timeout_ms":24000}),
                      encoding="utf8")
    ok,obj,norm=evidence("post-apktool-capture-"+str(n),[
       "capture-process",str(scenario)],env,timeout=65)
    exitobj=norm.get("exit",{})
    cleanup=norm.get("cleanup",{})
    passed=(ok and isinstance(exitobj,dict) and exitobj.get("code")==0
         and isinstance(cleanup,dict)
         and cleanup.get("owned_process_group") in ("verified","cleaned")
         and cleanup.get("temporary_root") in ("removed","cleaned"))
    return check("cleanup_after_apktool_"+str(n),passed,
                 {"cleanup":cleanup,"exit_code":exitobj.get("code") if isinstance(exitobj,dict) else None})

def main():
    preflight()
    env,launcher=env_and_bin()
    if launcher is None:
        check("preinstalled_apktool_launcher",False,{"reason":"NOT_FOUND_ON_PATH"})
        return
    version_rc,vers,v_err,secs=cmd([str(launcher),"--version"],env,timeout=30)
    persist("launcher-version",vers,"stdout")
    persist("launcher-version",v_err,"stderr")
    version=vers.strip()
    matched=re.match(r"^(\d+)\.(\d+)\.(\d+)",version)
    supported=(version_rc==0 and matched is not None and
               tuple(map(int,matched.groups())) >= (2,7,0))
    check("preinstalled_apktool_launcher",supported,
          {"launcher":str(launcher),"version":version[:100],"exit":version_rc})
    print("REA_APKTOOL_SELECTED_LAUNCHER="+str(launcher),flush=True)
    print("REA_APKTOOL_DETECTED_VERSION="+version[:50],flush=True)
    if not supported:return
    # Informative disclosure, not a fabricated audit of binary patches.
    nums=tuple(map(int,matched.groups()))
    potentially_affected=(nums<(2,9,2) or (3,0,0)<=nums<(3,0,2))
    print("REA_APKTOOL_VERSION_ADVISORY="+
          ("REVIEW_BEFORE_UNTRUSTED_APKS" if potentially_affected else "NO_LISTED_VERSION_WINDOW"),
          flush=True)
    ok,obj,norm=evidence("inspect-apktool-client",["inspect-apktool-client"],env)
    client=norm.get("client",{})
    inspected=(ok and isinstance(client,dict) and
         client.get("apktool_version")==version and
         client.get("command_source")=="environment" and
         Path(str(client.get("command",""))) == launcher)
    check("rea_inspect_apktool_client",inspected,
          {"version":client.get("apktool_version") if isinstance(client,dict) else None,
           "source":client.get("command_source") if isinstance(client,dict) else None})
    if not inspected:return
    # Read only: the known public source APK from the completed Step 2.
    original_digest=sha(APK)
    ok,obj,norm=evidence("decode-android-resources",[
         "decode-android-resources",str(APK)],env,timeout=360)
    target=norm.get("target",{})
    metadata=norm.get("metadata",{})
    manifest=norm.get("manifest")
    strings=norm.get("strings",[])
    locales=norm.get("locales",[])
    target_ok=(isinstance(target,dict) and target.get("sha256")==APK_SHA
               and target.get("bytes")==APK.stat().st_size)
    metadata_ok=(isinstance(metadata,dict)
            and metadata.get("package_name")=="io.appium.android.apis"
            and isinstance(metadata.get("min_sdk_version"),str)
            and isinstance(metadata.get("target_sdk_version"),str))
    content_ok=(isinstance(manifest,str)
            and "io.appium.android.apis" in manifest
            and isinstance(strings,list) and len(strings)>0
            and isinstance(norm.get("decoded_file_count"),int)
            and norm["decoded_file_count"]>0)
    decoded=check("rea_real_apk_decode_manifest_strings",bool(ok and target_ok and metadata_ok and content_ok),
            {"digest_verified":target_ok,"package":metadata.get("package_name") if isinstance(metadata,dict) else None,
             "strings":len(strings) if isinstance(strings,list) else None,
             "decoded_files":norm.get("decoded_file_count"),
             "coverage":norm.get("coverage")})
    if decoded and isinstance(locales,list) and locales:
        selected=next((l for l in locales if l in ("pt-BR","de")),locales[0])
        z,zo,zn=evidence("decode-apktool-locale",[
             "decode-android-resources",str(APK),"--locale",selected,
             "--string-tables-only"],env,timeout=360)
        tables=zn.get("string_tables",[])
        match=any(isinstance(t,dict) and t.get("locale")==selected and
                  t.get("status")=="present" for t in tables) if isinstance(tables,list) else False
        check("rea_locale_string_table_real_decode",
              bool(z and match and isinstance(zn.get("strings"),list) and not zn["strings"]
                   and zn.get("target",{}).get("sha256")==APK_SHA),
              {"locale":selected,"table_found":match})
    elif decoded:
        print("REA_APKTOOL_LOCALE_TEST=NOT_APPLICABLE_NO_LOCALES",flush=True)
    else:
        print("REA_APKTOOL_LOCALE_TEST=SKIPPED_DECODE_NOT_VALIDATED",flush=True)
    require(sha(APK)==original_digest==APK_SHA,"PINNED_APK_MODIFIED")
    capture(env,8)
    capture(env,30)

if __name__=="__main__":
    try:
        main()
        summary={"original":COMMIT,
                 "path":str(EVID),"tool_installations":0,"old_mcp_used":False,
                 "tests":checks,"calls":runs,
                 "passed":sum(t["result"]=="PASS" for t in checks),
                 "failed":sum(t["result"]=="FAIL" for t in checks),
                 "cleanup_incomplete":sum(bool(c["cleanup_incomplete"]) for c in runs),
                 "result":"PASS" if checks and all(c["result"]=="PASS" for c in checks)
                                    and not any(c["cleanup_incomplete"] for c in runs)
                           else "FAIL_OR_BLOCKED"}
        if EVID.is_dir():
            persist("summary",json.dumps(summary,indent=2,sort_keys=True),"json")
        print("REA_APKTOOL_PASS="+str(summary["passed"]),flush=True)
        print("REA_APKTOOL_FAIL="+str(summary["failed"]),flush=True)
        print("REA_APKTOOL_CLEANUP_INCOMPLETE="+str(summary["cleanup_incomplete"]),flush=True)
        print("REA_APKTOOL_STATUS="+summary["result"],flush=True)
        print("REA_APKTOOL_EVIDENCE="+str(EVID),flush=True)
        sys.exit(0 if summary["result"]=="PASS" else 31)
    except Exception as exc:
        print("REA_APKTOOL_FATAL="+type(exc).__name__+":"+str(exc)[:200],flush=True)
        sys.exit(32)
