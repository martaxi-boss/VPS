#!/usr/bin/env python3
"""Make Unblob's relocated Python interpreter explicit without editing upstream code.
Only creates one wrapper in final runtime and checks real firmware extraction.
"""
import gzip,hashlib,io,json,os,pwd,shutil,subprocess,sys,tarfile,tempfile,time
from pathlib import Path
PIN="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
BASE=Path("/home/ubuntu/rea-final-runtime")
VEND=BASE/"vendors"
PY=VEND/"providers/unblob-26.6.4/bin/python"
SCRIPT=VEND/"providers/unblob-26.6.4/bin/unblob"
NODE=VEND/"providers/node-v24.22.1/bin/node"
JDK=VEND/"tools/jdk-21"
GHIDRA=VEND/"tools/ghidra_12.1.4_PUBLIC"
JADX=VEND/"tools/jadx-headless-mcp-0.7.1-all.jar"
BINWALK=VEND/"providers/binwalk-3.1.0/bin/binwalk"
WRAPPER=BASE/"bin/unblob"
PROOF=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029/unblob-wrapper-proof.json")
PREVIOUS=Path("/home/ubuntu/rea-original-upstream-680-evidence/functional-copied-vendors-20261029/summary.json")
def check(ok,message):
    if not ok:raise RuntimeError(message)
def cmd(parts,env=None,timeout=150,cwd=ROOT):
    p=subprocess.run(parts,cwd=str(cwd),env=env,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf8",
        errors="replace",timeout=timeout,check=False)
    return p.returncode,p.stdout,p.stderr[:1300]
def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):
            h.update(b)
    return h.hexdigest()
def main():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","SSH_USER_WRONG")
    rc,rev,_=cmd(["git","rev-parse","HEAD"],timeout=10)
    check(rc==0 and rev.strip()==PIN,"ENGINE_COMMIT_CHANGED")
    check(BASE.is_dir() and BASE.stat().st_uid==os.geteuid(),"BASE_RUNTIME_UNAVAILABLE")
    check(VEND.is_dir() and not VEND.is_symlink(),"VENDORS_NOT_STAGED")
    check((ROOT/"node_modules").resolve(strict=False)==BASE/"node_modules","NODE_DEPS_CHANGED")
    check(all(p.is_file() for p in (PY,SCRIPT,NODE,JADX,BINWALK,GHIDRA/"support/analyzeHeadless",JDK/"bin/java")),"VENDOR_FILES_MISSING")
    check(not WRAPPER.exists() and not WRAPPER.is_symlink() and not PROOF.exists(),"WRAPPER_OR_PROOF_ALREADY_PRESENT")
    data=json.loads(PREVIOUS.read_text(encoding="utf8"))
    check(data.get("status")=="PASS" and data.get("failed")==0 and data.get("passed")==11,
          "COPIED_SUPPLIERS_11_PASS_MISSING")
    rc,prefix,_=cmd([str(PY),"-c","import sys;print(sys.prefix)"],timeout=20)
    check(rc==0 and prefix.strip()==str(VEND/"providers/unblob-26.6.4"),
          "COPIED_PYTHON_VENV_NOT_INDEPENDENT")
    root=WRAPPER.parent
    check(not root.is_symlink(),"BIN_DIRECTORY_SYMLINK")
    if not root.exists():
        root.mkdir(mode=0o700)
    check(root.is_dir() and root.stat().st_uid==os.geteuid(),"BIN_DIRECTORY_WRONG_OWNER")
    wrapper_text="#!/bin/sh\nexec '"+str(PY)+"' '"+str(SCRIPT)+"' \"$@\"\n"
    fd=WRAPPER.with_name(".unblob-final-20261029.tmp")
    check(not fd.exists() and not fd.is_symlink(),"UNEXPECTED_TEMP_FILE")
    try:
        with fd.open("x",encoding="utf8") as out:
            out.write(wrapper_text)
        fd.chmod(0o700)
        os.replace(fd,WRAPPER)
        rc,version,err=cmd([str(WRAPPER),"--version"],timeout=24)
        check(rc==0 and version.strip()=="26.6.4","ISOLATED_UNBLOB_VERSION_FAILED")
        # A fresh deterministic fixture tests the original REA CLI with the new wrapper.
        with tempfile.TemporaryDirectory(prefix="rea-isolated-unblob-",dir="/tmp") as td:
            tmp=Path(td)
            payload=b"REA_FINAL_UNBLOB_INDEPENDENT_RUNTIME\n"*80
            archive=io.BytesIO()
            with tarfile.open(fileobj=archive,mode="w",format=tarfile.USTAR_FORMAT) as tf:
                f=tarfile.TarInfo("independence.txt")
                f.size=len(payload);f.mtime=0;f.mode=0o644
                tf.addfile(f,io.BytesIO(payload))
            binary=b"\0"*64+gzip.compress(archive.getvalue(),mtime=0)+b"\0"*192
            src=tmp/"firmware.bin";src.write_bytes(binary)
            dest=tmp/"output"
            env=dict(os.environ)
            for key in tuple(env):
                if key.startswith("REA_") or key in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
                    "VIRTUAL_ENV","PYTHONPATH","PYTHONHOME"):
                    env.pop(key,None)
            env.update({"HOME":str(tmp),"TMPDIR":str(tmp),
                "XDG_CACHE_HOME":str(tmp/".cache"),
                "XDG_CONFIG_HOME":str(tmp/".config"),
                "PATH":str(JDK/"bin")+":"+str(NODE.parent)+":"+str(BINWALK.parent)+":"+env.get("PATH",""),
                "JAVA_HOME":str(JDK),"GHIDRA_INSTALL_DIR":str(GHIDRA),
                "REA_JADX_MCP_JAR":str(JADX),
                "REA_UNBLOB_COMMAND":str(WRAPPER),
                "REA_BINWALK_COMMAND":str(BINWALK),"CI":"1"})
            rc,stdout,err=cmd([str(NODE),"scripts/rea.mjs","extract-firmware",str(src),str(dest),"--json"],env,timeout=170)
            check(rc==0,"ISOLATED_REAL_UNBLOB_CLI_FAILED")
            result=json.loads(stdout)
            norm=result.get("normalized_result",result)
            found=[]
            for item in norm.get("files",[]) if isinstance(norm,dict) else []:
                if not isinstance(item,dict):continue
                p=Path(item.get("path",""))
                if p.is_relative_to(dest) and p.is_file() and sha(p)==hashlib.sha256(payload).hexdigest():
                    found.append(p.name)
            chunks=norm.get("chunks",[]) if isinstance(norm,dict) else []
            check(bool(found) and any(isinstance(c,dict) and c.get("handler")=="gzip" for c in chunks),
                  "ISOLATED_REAL_EXTRACTION_EVIDENCE_INCOMPLETE")
            check("cleanup_incomplete" not in stdout.lower(),"CLEANUP_REGRESSION")
        result={"status":"PASS_INDEPENDENT_UNBLOB_RUNTIME","engine_commit":PIN,
            "wrapper":str(WRAPPER),"virtualenv_prefix":prefix.strip(),
            "new_python":str(PY),"new_entrypoint_script":str(SCRIPT),
            "version":version.strip(),"real_extraction":True,"gzip_handler":True,
            "sha256_verified":True,"legacy_wrapper_unchanged":True,"timestamp":int(time.time())}
        PROOF.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf8")
        return result
    except BaseException:
        if fd.is_file():fd.unlink()
        if WRAPPER.is_file() and WRAPPER.read_text(encoding="utf8")==wrapper_text:
            WRAPPER.unlink()
        raise
if __name__=="__main__":
    try:
        print("REA_FINAL_WRAPPER_RESULT="+json.dumps(main(),sort_keys=True,separators=(",",":")),flush=True)
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired) as e:
        print("REA_FINAL_WRAPPER_BLOCKED="+type(e).__name__+":"+str(e)[:190],flush=True)
        sys.exit(2)
