#!/usr/bin/env python3
"""Make only the already-installed Unblob executable accessible to the original CLI.

Invoke through the established GitHub Actions -> pinned SSH -> ubuntu workflow.
No extra provider, no npm/apt packages on VPS, no MCP server/port, no service
change, no arbitrary chmod/chown. An ACL on ONE preverified provider directory
is permitted only if passwordless sudo and POSIX ACL tools are already present.
On functional test failure, remove the newly introduced ACL entry.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import time

ORIGINAL=Path("/home/ubuntu/rea-original-upstream-680")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/unblob-existing-20261029")
PREVIOUS=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
UNBLOB_ROOT=Path("/opt/rea-reversa/providers/unblob-26.6.4")
UNBLOB_BIN=UNBLOB_ROOT/"bin/unblob"
UPSTREAM_COMMIT="160d821ac9a0310afcb8d1fc427862dd6508add5"
DIGESTS={
 "dist/process/ProcessOwnership.js":
 "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
 "dist/process/ProcessOwnershipObservation.js":
 "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)

def require(cond,label):
    if not cond:raise RuntimeError(label)

def command(args,env=None,timeout=30):
    try:
        return subprocess.run(args,cwd=ORIGINAL,env=env,timeout=timeout,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,check=False)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(args,124,
            (e.stdout or b"").decode("utf8",errors="replace") if isinstance(e.stdout,bytes) else (e.stdout or ""),
            (e.stderr or b"").decode("utf8",errors="replace") if isinstance(e.stderr,bytes) else (e.stderr or ""))

def save(label,data):
    (EVID/label).write_text(data,encoding="utf8",errors="replace")

def preflight():
    require(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","ONLY_UBUNTU_USER")
    require(ORIGINAL.is_dir() and not ORIGINAL.is_symlink(),"ORIGINAL_ROOT_CHANGED")
    require((ORIGINAL/"node_modules").is_symlink(),"DEPENDENCIES_NO_LONGER_LINKED")
    require((ORIGINAL/"node_modules").resolve()==(PREVIOUS/"node_modules").resolve(),
            "ORIGINAL_DEPENDENCY_ORIGIN_CHANGED")
    require((ORIGINAL/"package-lock.json").read_bytes()==(PREVIOUS/"package-lock.json").read_bytes(),
            "ORIGINAL_LOCK_MISMATCH")
    require(NODE.is_file(),"NODE_NOT_INSTALLED")
    r=command(["git","-C",str(ORIGINAL),"rev-parse","HEAD"])
    require(r.returncode==0 and r.stdout.strip()==UPSTREAM_COMMIT,
            "ORIGINAL_GIT_REVISION_MISMATCH")
    for path,wanted in DIGESTS.items():
        p=ORIGINAL/path
        require(p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==wanted,
                "ORIGINAL_COMPILED_HASH_MISMATCH:"+path)
    require(UNBLOB_ROOT.is_dir() and not UNBLOB_ROOT.is_symlink(),
            "UNBLOB_PROVIDER_ROOT_CHANGED")
    s=UNBLOB_ROOT.lstat()
    require(s.st_uid==994,"UNBLOB_OWNER_CHANGED")
    require(stat.S_IMODE(s.st_mode)==0o750,"UNBLOB_ROOT_PERMISSIONS_UNEXPECTED")
    require(EVID.parent.is_dir(),"EXISTING_EVIDENCE_ROOT_MISSING")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_UNBLOB_ORIGINAL=PINNED_VERIFIED",flush=True)
    print("REA_UNBLOB_EXISTING_PROVIDER="+str(UNBLOB_BIN),flush=True)
    print("REA_UNBLOB_VPS_INSTALLS=ZERO",flush=True)
    print("REA_UNBLOB_CONNECTION=GITHUB_ACTIONS_SSH_ORIGINAL_CLI",flush=True)
    print("REA_UNBLOB_OLD_MCP_USED=NO",flush=True)

def test_env():
    home=EVID/"isolated-home"
    home.mkdir(mode=0o700,parents=True,exist_ok=True)
    env=dict(os.environ)
    for name in list(env):
        if name.startswith("REA_") or name in ("GHIDRA_INSTALL_DIR","HOPPER_LAUNCHER_PATH"):
            env.pop(name,None)
    env["PATH"]=str(NODE.parent)+":"+env.get("PATH","")
    env["HOME"]=str(home)
    env["XDG_CACHE_HOME"]=str(home/".cache")
    env["XDG_CONFIG_HOME"]=str(home/".config")
    env["XDG_DATA_HOME"]=str(home/".local/share")
    env["REA_UNBLOB_COMMAND"]=str(UNBLOB_BIN)
    env["CI"]="1"
    return env

def extract_real(env):
    # Genuine Unblob extraction of original deterministic bytes. This is NOT a
    # simulated producer, an altered engine or an MCP-mocked tool call.
    selected=EVID/"controlled-firmware-20261029.bin"
    target=EVID/"extracted-proof.txt"
    marker=(b"REA_UNBLOB_ORIGINAL_REAL_EXTRACTION_20261029\n"*100)
    archive_bytes=io.BytesIO()
    with tarfile.open(fileobj=archive_bytes,mode="w",format=tarfile.USTAR_FORMAT) as tf:
        info=tarfile.TarInfo(name="proof.txt")
        info.size=len(marker)
        info.mode=0o644
        info.mtime=0
        tf.addfile(info,io.BytesIO(marker))
    raw=b"\x00"*64+gzip.compress(archive_bytes.getvalue(),mtime=0)+b"\x00"*160
    selected.write_bytes(raw)
    target.write_bytes(marker)
    output=EVID/("extraction-output-"+str(time.time_ns()))
    cmd=[str(NODE),"scripts/rea.mjs","extract-firmware",str(selected),str(output),"--json"]
    result=command(cmd,env=env,timeout=200)
    save("extract-firmware.stdout.json",result.stdout)
    save("extract-firmware.stderr.txt",result.stderr)
    try:
        parsed=json.loads(result.stdout)
        if isinstance(parsed,dict) and isinstance(parsed.get("result"),dict):
            parsed=parsed["result"]
    except (ValueError,TypeError):
        parsed={}
    if not isinstance(parsed,dict):parsed={}
    normalized=parsed.get("normalized_result",{})
    if not isinstance(normalized,dict):normalized={}
    file_records=normalized.get("files",[])
    if not isinstance(file_records,list):file_records=[]
    wanted=hashlib.sha256(marker).hexdigest()
    matches=[item for item in file_records
             if isinstance(item,dict) and item.get("sha256")==wanted]
    original_integrity=hashlib.sha256(selected.read_bytes()).hexdigest()==hashlib.sha256(raw).hexdigest()
    genuine_files=[]
    for item in matches:
        v=item.get("path")
        if not isinstance(v,str):continue
        p=Path(v)
        try:
            if p.is_file() and p.is_relative_to(output) and hashlib.sha256(p.read_bytes()).hexdigest()==wanted:
                genuine_files.append(v)
        except (PermissionError,OSError):continue
    chunks=normalized.get("chunks",[])
    identified_gzip=isinstance(chunks,list) and any(
        isinstance(row,dict) and row.get("handler")=="gzip" for row in chunks)
    incomplete="cleanup_incomplete" in (result.stdout+result.stderr).lower()
    success=(result.returncode==0 and bool(matches) and
             bool(genuine_files) and identified_gzip and original_integrity and not incomplete)
    print("REA_UNBLOB_REAL_EXTRACTION="+("PASS" if success else "FAIL")+
          ";exit="+str(result.returncode)+";gzip="+str(identified_gzip).lower()+
          ";hash_match="+str(bool(genuine_files)).lower()+
          ";cleanup_incomplete="+str(incomplete).lower(),flush=True)
    return {"status":"PASS" if success else "FAIL",
            "cli_exit":result.returncode,"gzip_chunk":identified_gzip,
            "output_digest_match":bool(genuine_files),"original_digest_preserved":original_integrity,
            "cleanup_incomplete":incomplete,"output_files":len(file_records),
            "stdout_sha256":hashlib.sha256(result.stdout.encode()).hexdigest()}

def capture_regression(env,count):
    script=("import subprocess; p=[subprocess.Popen(['/usr/bin/true']) for _ in range("+
            str(count)+")]; r=[x.wait() for x in p]; print('REAP='+str(len(r)))")
    case=EVID/("capture-"+str(count)+".scenario.json")
    case.write_text(json.dumps({"executable":"/usr/bin/python3",
                "arguments":["-c",script],"timeout_ms":24000}),encoding="utf8")
    p=command([str(NODE),"scripts/rea.mjs","capture-process",str(case),"--json"],
              env=env,timeout=60)
    save("capture-"+str(count)+".json",p.stdout)
    save("capture-"+str(count)+".stderr",p.stderr)
    try:
        parsed=json.loads(p.stdout)
        if isinstance(parsed,dict) and isinstance(parsed.get("result"),dict):
            parsed=parsed["result"]
    except (ValueError,TypeError):parsed={}
    if not isinstance(parsed,dict):parsed={}
    normalized=parsed.get("normalized_result",{})
    if not isinstance(normalized,dict):normalized={}
    cleanup=normalized.get("cleanup",{})
    if not isinstance(cleanup,dict):cleanup={}
    complete=p.returncode==0 and (
      cleanup.get("owned_process_group") in ("verified","cleaned") and
      cleanup.get("temporary_root") in ("removed","cleaned") and
      "cleanup_incomplete" not in (p.stdout+p.stderr).lower())
    print("REA_UNBLOB_CAPTURE_"+str(count)+"="+("PASS" if complete else "FAIL")+
          ";cleanup_incomplete="+
          str("cleanup_incomplete" in (p.stdout+p.stderr).lower()).lower(),flush=True)
    return {"n":count,"status":"PASS" if complete else "FAIL","cleanup":cleanup}

def main():
    preflight()
    env=test_env()
    record={"source":UPSTREAM_COMMIT,"provider":str(UNBLOB_BIN),
            "provider_installed_this_run":False,"mcp_connected":False,
            "acl_added":False}
    # Check if provider was already available without changing permissions.
    initial=command([str(UNBLOB_BIN),"--version"],env=env,timeout=15)
    save("version-initial.stdout.txt",initial.stdout)
    save("version-initial.stderr.txt",initial.stderr)
    print("REA_UNBLOB_INITIAL_ACCESS="+
          ("PASS" if initial.returncode==0 else "BLOCKED")+
          ";rc="+str(initial.returncode),flush=True)
    setfacl=shutil.which("setfacl")
    getfacl=shutil.which("getfacl")
    sudo=shutil.which("sudo")
    added=False
    completed=False
    try:
        if initial.returncode!=0:
            if not sudo or not getfacl or not setfacl:
                record["blocker"]="POSIX_ACL_OR_SUDO_NOT_PREINSTALLED"
                print("REA_UNBLOB_ACCESS_BLOCKED="+record["blocker"],flush=True)
                return 42,record
            admin=command([sudo,"-n","/usr/bin/id","-u"],timeout=8)
            if admin.returncode!=0 or admin.stdout.strip()!="0":
                record["blocker"]="NONINTERACTIVE_SUDO_NOT_AVAILABLE"
                print("REA_UNBLOB_ACCESS_BLOCKED="+record["blocker"],flush=True)
                return 43,record
            preacl=command([sudo,"-n",getfacl,"-p",str(UNBLOB_ROOT)],timeout=9)
            if preacl.returncode!=0:
                record["blocker"]="CANNOT_BACKUP_EXISTING_ACL"
                return 44,record
            save("acl-original.txt",preacl.stdout)
            if any(line.startswith("user:ubuntu:") for line in preacl.stdout.splitlines()):
                record["blocker"]="EXISTING_CUSTOM_UBUNTU_ACL_REQUIRES_REVIEW"
                print("REA_UNBLOB_ACCESS_BLOCKED="+record["blocker"],flush=True)
                return 45,record
            grant=command([sudo,"-n",setfacl,"-m","u:ubuntu:--x",str(UNBLOB_ROOT)],
                          timeout=10)
            save("acl-grant.stderr.txt",grant.stderr)
            if grant.returncode!=0:
                record["blocker"]="MINIMAL_ACL_GRANT_REJECTED"
                print("REA_UNBLOB_ACCESS_BLOCKED="+record["blocker"],flush=True)
                return 46,record
            added=True
            record["acl_added"]=True
            print("REA_UNBLOB_ACL=UBUNTU_TRAVERSE_ONLY_PROVIDER_ROOT",flush=True)
            acl_now=command([sudo,"-n",getfacl,"-p",str(UNBLOB_ROOT)],timeout=8)
            save("acl-after.txt",acl_now.stdout)
            if acl_now.returncode!=0 or "user:ubuntu:--x" not in acl_now.stdout:
                record["blocker"]="ACL_READBACK_FAILED"
                return 47,record
        ver=command([str(UNBLOB_BIN),"--version"],env=env,timeout=20)
        save("version-final.stdout.txt",ver.stdout)
        save("version-final.stderr.txt",ver.stderr)
        usable=(ver.returncode==0 and
                "26.6." in (ver.stdout+ver.stderr))
        print("REA_UNBLOB_VERSION="+("PASS" if usable else "FAIL")+
              ";stdout="+(ver.stdout.strip()[:45] if ver.stdout else "none")+
              ";rc="+str(ver.returncode),flush=True)
        if not usable:
            record["blocker"]="UNBLOB_EXECUTION_OR_VERSION_CHECK_FAILED"
            return 48,record
        record["version"]="26.6.x verified"
        has7z=shutil.which("7z",path=env["PATH"]) is not None
        hasprlimit=shutil.which("prlimit",path=env["PATH"]) is not None
        record["dependencies"]={"7z_present":has7z,"prlimit_present":hasprlimit}
        print("REA_UNBLOB_PRLIMIT="+("PRESENT" if hasprlimit else "MISSING"),flush=True)
        print("REA_UNBLOB_7Z="+("PRESENT" if has7z else "MISSING"),flush=True)
        if not hasprlimit or not has7z:
            record["blocker"]="EXISTING_EXTRACTION_PREREQUISITE_MISSING"
            return 49,record
        extraction=extract_real(env)
        record["extraction"]=extraction
        if extraction["status"]!="PASS":
            record["blocker"]="EXTRACTION_NOT_VERIFIED"
            return 50,record
        cases=[capture_regression(env,n) for n in [8,30]]
        record["regression"]=cases
        if any(r["status"]!="PASS" for r in cases):
            record["blocker"]="REGRESSION_FAILED"
            return 51,record
        completed=True
        record["result"]="PASS"
        print("REA_UNBLOB_ACCEPTANCE=PASS",flush=True)
        return 0,record
    finally:
        if added and not completed:
            # Undo only the new scoped ACL entry, preserving the service user's
            # original group/mode/owner; never chmod or alter unrelated paths.
            undo=command([sudo,"-n",setfacl,"-x","u:ubuntu",str(UNBLOB_ROOT)],
                         timeout=10)
            record["rollback"]={"attempted":True,"success":undo.returncode==0}
            print("REA_UNBLOB_ACCESS_ROLLBACK="+
                  ("PASS" if undo.returncode==0 else "FAILED"),flush=True)
        if completed:
            record["rollback"]={"attempted":False,
                                 "policy":"keep verified ubuntu traverse ACL"}

if __name__=="__main__":
    try:
        code,out=main()
        EVID.mkdir(parents=True,exist_ok=True)
        save("summary.json",json.dumps(out,indent=2,sort_keys=True))
        sys.exit(code)
    except Exception as exc:
        print("REA_UNBLOB_FATAL="+type(exc).__name__+":"+str(exc)[:160],flush=True)
        sys.exit(52)
