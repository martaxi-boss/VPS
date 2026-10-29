#!/usr/bin/env python3
"""ONE-SHOT stage of final engine npm dependencies, without changing live symlink or legacy.
Only an authorized GH Actions actor may trigger this via the existing pinned SSH workflow.
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

REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
SOURCE=OLD/"node_modules"
BASE=Path("/home/ubuntu/rea-final-runtime")
DEST=BASE/"node_modules"
TEMP=BASE/".node_modules-stage-20261029"
MANIFEST=BASE/"dependency-stage-manifest.json"
HASHES={
    "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
    "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655"
}

def h(path):
    dig=hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda:inp.read(1024*1024), b""):
            dig.update(chunk)
    return dig.hexdigest()

def check(ok, reason):
    if not ok:raise RuntimeError(reason)

def command(argv,timeout=50):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,text=True,errors="replace",timeout=timeout,check=False)
    return p.returncode,p.stdout.strip(),p.stderr[:250]

def du(path):
    rc,out,_=command(["du","-s","-B1",str(path)],timeout=90)
    check(rc==0,"CANNOT_MEASURE_DEPENDENCIES")
    return int(out.split()[0])

def check_external_links(directory):
    total=0
    old_links=[]
    outside_links=[]
    for current, dirs,files in os.walk(directory,followlinks=False):
        for name in dirs+files:
            p=Path(current)/name
            if not p.is_symlink():continue
            total+=1
            real=p.resolve(strict=False)
            if real == OLD or OLD in real.parents:
                old_links.append(str(p.relative_to(directory))[:120])
            elif not (real==directory or directory in real.parents):
                outside_links.append({"path":str(p.relative_to(directory))[:120],
                    "target":str(real)[:170],"exists":real.exists()})
    return {"count":total,"legacy_target_links":old_links[:15],
       "legacy_target_count":len(old_links),"other_external_links":outside_links[:12],
       "other_external_count":len(outside_links)}

def stage():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","WRONG_USER")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"FINAL_ROOT_WRONG")
    rc,got,_=command(["git","-C",str(ROOT),"rev-parse","HEAD"],timeout=12)
    check(rc==0 and got==REV,"SOURCE_COMMIT_MISMATCH")
    for file,digest in HASHES.items():
        check(h(ROOT/file)==digest,"FINAL_COMPILED_CODE_CHANGED")
    check((ROOT/"node_modules").is_symlink() and
        (ROOT/"node_modules").resolve(strict=False)==SOURCE.resolve(strict=False),
        "CURRENT_DEPENDENCIES_NOT_EXPECTED_LEGACY_LINK")
    check(h(ROOT/"package-lock.json")==h(OLD/"package-lock.json"),
          "LOCK_FILE_CHANGED")
    check(SOURCE.is_dir() and not SOURCE.is_symlink(),"SOURCE_NOT_DIR")
    available=shutil.disk_usage(str(ROOT)).free
    size_before=du(SOURCE)
    check(available > max(6*1024**3,2*size_before+4*1024**3),"INSUFFICIENT_SAFE_DISK_SPACE")
    check(not BASE.is_symlink() and
       (not BASE.exists() or BASE.is_dir()),"RUNTIME_ROOT_INVALID")
    if BASE.exists():
        check(not DEST.exists() and not DEST.is_symlink() and not TEMP.exists() and not TEMP.is_symlink(),
              "RUNTIME_ALREADY_STAGED_OR_TEMP_EXISTS")
    BASE.mkdir(mode=0o700,exist_ok=True)
    check(BASE.stat().st_uid==os.geteuid(),"RUNTIME_NOT_OWNED_BY_UBUNTU")
    os.chmod(BASE,0o700)
    TEMP.mkdir(mode=0o700)
    try:
        rc,_,err=command(["cp","-a","--reflink=auto","--",str(SOURCE)+"/.",str(TEMP)],timeout=760)
        check(rc==0,"COPY_FAILED_"+str(rc))
        size_after=du(TEMP)
        check(abs(size_after-size_before) <= max(10485760,size_before//50),
              "COPY_SIZE_MISMATCH")
        links=check_external_links(TEMP)
        check(links["legacy_target_count"]==0,"NESTED_SYMLINKS_REFERENCE_LEGACY")
        check(all(x["exists"] for x in links["other_external_links"]),
              "MISSING_EXTERNAL_DEPENDENCY_LINK")
        old_packages=sorted(x.name for x in SOURCE.iterdir())
        new_packages=sorted(x.name for x in TEMP.iterdir())
        check(old_packages==new_packages,"TOP_LEVEL_PACKAGES_DIFFER")
        # Verify package fingerprints, not just directory sizes.
        samples=[]
        for relative in ("frida/package.json","typescript/package.json",
              "zod/package.json","@modelcontextprotocol/sdk/package.json","commander/package.json"):
            a,b=SOURCE/relative,TEMP/relative
            if a.is_file():
                check(b.is_file() and h(a)==h(b),"DEPENDENCY_SAMPLE_DIFFERS")
                samples.append(relative)
        check(len(samples)>=1,"NO_DEPENDENCY_FINGERPRINTS")
        os.replace(TEMP,DEST)
        data={"status":"STAGED_INDEPENDENT_COPY","root":str(BASE),
            "node_modules":str(DEST),"source":str(SOURCE),
            "allocated_bytes_source":size_before,
            "allocated_bytes_destination":size_after,
            "sample_sha256_paths":samples,
            "symlinks":links,
            "engine_commit":REV,
            "timestamp_unix":int(time.time()),
            "live_symlink_unchanged":(ROOT/"node_modules").resolve(strict=False)==SOURCE.resolve(strict=False)}
        check(data["live_symlink_unchanged"],"LIVE_LINK_UNEXPECTEDLY_CHANGED")
        p=MANIFEST.with_name(".dependency-stage-manifest.new.json")
        with p.open("x",encoding="utf-8") as fd:
            json.dump(data,fd,indent=2,sort_keys=True)
        os.replace(p,MANIFEST)
        return data
    except BaseException:
        if TEMP.is_dir() and not TEMP.is_symlink():
            shutil.rmtree(TEMP)
        raise

if __name__=="__main__":
    try:
        res=stage()
        print("REA_FINAL_STAGE_RESULT="+json.dumps(res,separators=(",",":"),sort_keys=True),flush=True)
    except (OSError,RuntimeError,subprocess.TimeoutExpired) as exc:
        print("REA_FINAL_STAGE_BLOCKED="+type(exc).__name__+":"+str(exc)[:110],flush=True)
        sys.exit(2)
