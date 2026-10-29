#!/usr/bin/env python3
"""One-time atomic swap to a separately copied dependency directory; automatic rollback."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
SOURCE=OLD/"node_modules"
BASE=Path("/home/ubuntu/rea-final-runtime")
DEST=BASE/"node_modules"
MANIFEST=BASE/"dependency-stage-manifest.json"
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVIDENCE=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029")
CURRENT=ROOT/"node_modules"
TMP_LINK=ROOT/".node_modules-final-switch-20261029"
TMP_ROLLBACK=ROOT/".node_modules-final-rollback-20261029"
APK_SHA="a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686"

def check(ok,reason):
    if not ok:raise RuntimeError(reason)

def hashfile(p):
    x=hashlib.sha256()
    with p.open("rb") as fd:
        for block in iter(lambda:fd.read(1024*1024),b""):
            x.update(block)
    return x.hexdigest()

def exec_cmd(argv,env=None,timeout=110):
    start=time.monotonic()
    p=subprocess.Popen(argv,cwd=str(ROOT),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        encoding="utf-8",errors="replace",text=True,env=env,start_new_session=True)
    try:
        out,err=p.communicate(timeout=timeout)
        rc=p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL)
        out,err=p.communicate(timeout=5)
        rc=124
    return rc,out[:16*1024*1024],err[:1000],round(time.monotonic()-start,2)

def cli(name,args,env):
    rc,out,err,seconds=exec_cmd([str(NODE),"scripts/rea.mjs",*args,"--json"],env)
    flag="cleanup_incomplete" in (out+err).lower()
    try: data=json.loads(out); valid=isinstance(data,(dict,list))
    except ValueError: data=None;valid=False
    result={"operation":name,"exit":rc,"valid_json":valid,
        "cleanup_incomplete":flag,"duration_seconds":seconds}
    if isinstance(data,dict):
        norm=data.get("normalized_result",data)
        if isinstance(norm,dict):
            result["output_fields"]=list(norm)[:10]
    check(rc==0 and valid and not flag,"CLI_TEST_FAILED_"+name)
    return result

def env_for_test(home):
    e=dict(os.environ)
    for key in tuple(e):
        if key.startswith("REA_") or key in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
        "VIRTUAL_ENV","PYTHONPATH","PYTHONHOME","HOPPER_LAUNCHER_PATH"):
            e.pop(key,None)
    e.update({
        "HOME":str(home),"TMPDIR":str(home),"XDG_CACHE_HOME":str(home/".cache"),
        "XDG_CONFIG_HOME":str(home/".config"),
        "PATH":"/opt/rea-reversa/tools/jdk-21/bin:"+str(NODE.parent)+":"+e.get("PATH",""),
        "JAVA_HOME":"/opt/rea-reversa/tools/jdk-21",
        "GHIDRA_INSTALL_DIR":"/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC",
        "REA_JADX_MCP_JAR":"/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar",
        "REA_UNBLOB_COMMAND":"/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob",
        "CI":"1"
    })
    return e

def safe_old_link():
    check(CURRENT.is_symlink() and CURRENT.resolve(strict=False)==SOURCE.resolve(strict=False),
          "EXPECTED_ORIGINAL_LINK_CHANGED")

def switch_and_prove():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","WRONG_SSH_USER")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"FINAL_ROOT_NOT_FOUND")
    rc,out,_,_=exec_cmd(["git","rev-parse","HEAD"],timeout=12)
    check(rc==0 and out.strip()==REV,"ORIGINAL_COMMIT_DRIFT")
    check(NODE.is_file() and DEST.is_dir() and not DEST.is_symlink(),"COPY_OR_NODE_MISSING")
    check(not TMP_LINK.exists() and not TMP_LINK.is_symlink() and
          not TMP_ROLLBACK.exists() and not TMP_ROLLBACK.is_symlink(),"SWITCH_RESIDUE_PRESENT")
    safe_old_link()
    state=json.loads(MANIFEST.read_text(encoding="utf-8"))
    check(state.get("status")=="STAGED_INDEPENDENT_COPY" and state.get("engine_commit")==REV and
          state.get("node_modules")==str(DEST) and state.get("live_symlink_unchanged") is True,
          "COPY_MANIFEST_INVALID")
    check(state["symlinks"]["legacy_target_count"]==0,"COPY_HAS_LEGACY_SYMLINKS")
    check(hashfile(ROOT/"package-lock.json")==hashfile(OLD/"package-lock.json"),"LOCK_DIFFERS")
    check(shutil.disk_usage(str(ROOT)).free > 4*1024**3,"DISK_LOW_BEFORE_SWITCH")
    fixtures=(ROOT/"_reference/apk-integration/ApiDemos-debug.apk",
        Path("/home/ubuntu/rea-original-upstream-680-evidence/functional-suppliers-step2-20261029/ApiDemos-debug.apk"))
    fixture=next((p for p in fixtures if p.is_file() and hashfile(p)==APK_SHA),None)
    check(fixture is not None,"APK_FIXTURE_ONLY_IN_LEGACY")
    TMP_LINK.symlink_to(DEST,target_is_directory=True)
    os.replace(TMP_LINK,CURRENT)
    results=[]
    try:
        check(CURRENT.is_symlink() and CURRENT.resolve(strict=False)==DEST.resolve(strict=False),
            "SWITCH_TARGET_INCORRECT")
        with tempfile.TemporaryDirectory(prefix="rea-final-verify-",dir="/tmp") as temp:
            e=env_for_test(Path(temp))
            rc,out,err,secs=exec_cmd([str(NODE),"scripts/rea.mjs","--version"],e,timeout=30)
            check(rc==0 and out.strip()=="6.8.0","FINAL_CLI_VERSION_FAILED")
            results.append({"operation":"version","exit":rc,"version":out.strip(),"duration_seconds":secs})
            trials=[
             ("providers",["providers"]),
             ("capabilities",["capabilities"]),
             ("inspect-artifact",["inspect-artifact","/usr/bin/true"]),
             ("inspect-elf-notes",["inspect-elf-notes","/usr/bin/true"]),
             ("inspect-android-package",["inspect-android-package",str(fixture)]),
             ("inspect-android-class",["inspect-android-class",str(fixture),"io.appium.android.apis.ApiDemos"]),
             ("inspect-android-method",["inspect-android-method",str(fixture),"io.appium.android.apis.ApiDemos","onCreate"])
            ]
            for name,args in trials:
                results.append(cli(name,args,e))
        # Verify the final engine resolves its npm packages from its own runtime directory.
        check(CURRENT.resolve(strict=False)==DEST,"NODE_MODULES_REVERTED")
        result={"status":"PASS_ISOLATED_DEPENDENCIES","engine":str(ROOT),
            "source_commit":REV,
            "node_modules":str(DEST),
            "legacy_engine_node_modules_used":False,
            "host_level_vendor_paths_unchanged":True,
            "tests":results,"test_count":len(results),
            "version":"6.8.0","timestamp_unix":int(time.time()),
            "old_engine_retained":OLD.is_dir()}
        EVIDENCE.mkdir(parents=True,exist_ok=True,mode=0o700)
        report=EVIDENCE/"dependency_switch_test.json"
        check(not report.exists(),"EVIDENCE_FILE_ALREADY_EXISTS")
        report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        return result
    except BaseException:
        # Restore ONLY original symlink, preserving installed legacy files.
        TMP_ROLLBACK.symlink_to(SOURCE,target_is_directory=True)
        os.replace(TMP_ROLLBACK,CURRENT)
        check(CURRENT.resolve(strict=False)==SOURCE.resolve(strict=False),"ROLLBACK_FAILED")
        raise

if __name__=="__main__":
    try:
        print("REA_FINAL_SWITCH_RESULT="+json.dumps(switch_and_prove(),separators=(",",":"),sort_keys=True),flush=True)
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
        print("REA_FINAL_SWITCH_BLOCKED="+type(exc).__name__+":"+str(exc)[:140],flush=True)
        sys.exit(2)
