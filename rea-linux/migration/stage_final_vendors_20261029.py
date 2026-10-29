#!/usr/bin/env python3
"""One-shot copy of vetted Linux vendor distributions. Does not switch any running paths."""
import hashlib,json,os,pwd,shutil,subprocess,sys,time
from pathlib import Path
PIN="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
BASE=Path("/home/ubuntu/rea-final-runtime")
TEMP=BASE/".vendors-stage-20261029"
DEST=BASE/"vendors"
PROOF=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029/vendor-stage.json")
SOURCES=[
"providers/node-v24.22.1",
"tools/jdk-21",
"tools/ghidra_12.1.4_PUBLIC",
"tools/jadx-headless-mcp-0.7.1-all.jar",
"providers/unblob-26.6.4",
"providers/binwalk-3.1.0",
"providers/rizin-v0.9.1",
"providers/kuna-v1.833",
"providers/wakaru-1.14.0",
"providers/mitmproxy-12.2.3",
"providers/cutter-2.5.0",
"providers/wabt-1.0.42"]
BINARIES=[
"providers/node-v24.22.1/bin/node",
"tools/jdk-21/bin/java",
"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless",
"tools/jadx-headless-mcp-0.7.1-all.jar",
"providers/unblob-26.6.4/bin/unblob",
"providers/binwalk-3.1.0/bin/binwalk",
"providers/rizin-v0.9.1/bin/rizin",
"providers/kuna-v1.833/bin/kuna",
"providers/wakaru-1.14.0/bin/wakaru",
"providers/mitmproxy-12.2.3/bin/mitmdump",
"providers/cutter-2.5.0/bin/Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage",
"providers/wabt-1.0.42/bin/wasm2wat"]
def check(ok,msg):
    if not ok:raise RuntimeError(msg)
def run(args,timeout=110):
    p=subprocess.run(args,text=True,encoding="utf8",errors="replace",stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    return p.returncode,p.stdout.strip(),p.stderr[:180]
def size(path):
    rc,out,_=run(["sudo","-n","du","-s","-B1","--",str(path)],timeout=120)
    check(rc==0,"SOURCE_SIZE_FAILED:"+path.name)
    return int(out.split()[0])
def sha(path):
    rc,out,_=run(["sudo","-n","sha256sum","--",str(path)],timeout=100)
    check(rc==0,"CHECKSUM_FAILED:"+path.name)
    return out.split()[0]
def stage():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","USER_UNEXPECTED")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"ENGINE_WRONG")
    rc,revision,_=run(["git","-C",str(ROOT),"rev-parse","HEAD"])
    check(rc==0 and revision==PIN,"COMMIT_MISMATCH")
    check((ROOT/"node_modules").resolve(strict=False)==BASE/"node_modules",
          "NODE_DEPENDENCIES_NOT_ISOLATED")
    check(BASE.is_dir() and BASE.stat().st_uid==os.geteuid() and not BASE.is_symlink(),"RUNTIME_ROOT_WRONG")
    check(not TEMP.exists() and not TEMP.is_symlink(),"STAGING_PATH_ALREADY_PRESENT")
    check(not DEST.exists() and not DEST.is_symlink(),"VENDORS_ALREADY_PRESENT")
    check(not PROOF.exists(),"PROOF_EXISTS")
    check(run(["sudo","-n","true"])[0]==0,"SUDO_UNAVAILABLE")
    entries=[]
    for rel in SOURCES:
        src=Path("/opt/rea-reversa")/rel
        check(src.exists() and not src.is_symlink(),"VENDOR_MISSING:"+rel)
        entries.append({"name":rel,"source":str(src),"bytes":size(src)})
    total=sum(x["bytes"] for x in entries)
    check(shutil.disk_usage(str(BASE)).free>total+5*(1024**3),"NOT_ENOUGH_DISK")
    TEMP.mkdir(mode=0o700)
    try:
        for e in entries:
            src=Path(e["source"])
            target=TEMP/e["name"]
            target.parent.mkdir(parents=True,exist_ok=True)
            rc,_,error=run(["sudo","-n","cp","-a","--reflink=auto","--",str(src),str(target)],timeout=1050)
            check(rc==0,"COPY_FAILED:"+e["name"]+":"+error[:90])
            copied=size(target)
            check(abs(copied-e["bytes"])<max(20*1024*1024,e["bytes"]//20),
                  "COPIED_SIZE_MISMATCH:"+e["name"])
            e["copied_bytes"]=copied
        for rel in BINARIES:
            check((TEMP/rel).is_file(),"ENTRYPOINT_MISSING:"+rel)
            check(sha(TEMP/rel)==sha(Path("/opt/rea-reversa")/rel),
                  "ENTRYPOINT_SHA_DIFF:"+rel)
        os.replace(TEMP,DEST)
        result={"status":"STAGED_NOT_ACTIVATED","source_commit":PIN,
          "vendor_root":str(DEST),"entries":entries,
          "copied_count":len(entries),"total_source_bytes":total,
          "entrypoints_checked":len(BINARIES),
          "live_engine_unchanged":True,"legacy_not_touched":True,
          "excluded_optional":["chromium_blocked_by_apparmor","hopper_build_not_supported"],
          "free_bytes":shutil.disk_usage(str(BASE)).free,"timestamp":int(time.time())}
        PROOF.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
        return result
    except BaseException:
        if TEMP.is_dir() and not TEMP.is_symlink():
            run(["sudo","-n","rm","-rf","--",str(TEMP)],timeout=180)
        raise
if __name__=="__main__":
    try:
        print("REA_FINAL_VENDOR_STAGE_RESULT="+json.dumps(stage(),separators=(",",":"),sort_keys=True),flush=True)
    except (RuntimeError,ValueError,OSError,subprocess.TimeoutExpired) as err:
        print("REA_FINAL_VENDOR_STAGE_BLOCKED="+type(err).__name__+":"+str(err)[:180],flush=True)
        sys.exit(2)
