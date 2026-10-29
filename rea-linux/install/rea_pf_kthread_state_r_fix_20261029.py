#!/usr/bin/env python3
"""REA 6.8.0 Linux: bounded PF_KTHREAD state-R parity repair.

Only the installed compiled overlay is changed, never official REA sources.
Kernel identity must still pass PF_KTHREAD, PPID=2, PGID=0, UID=0,
stable starttime and two independent native reads.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

TARGET=Path("/opt/rea-reversa/rea/dist/process/ProcessOwnershipObservation.js")
BACKUP=Path("/opt/rea-reversa/rea/.rea-local-fixes/ProcessOwnershipObservation.pre-state-r-20261029.js")
NODE="/opt/rea-reversa/providers/node-v24.22.1/bin/node"
OLD_SHA="eaf1c4c6b6086d1adf3e3b89a4b2831eddef8e4dbbf82bc46b304ab1e0a2d8fd"
OLD=b'!["I", "S", "D"].includes(f[0])'
NEW=b'!["I", "S", "D", "R"].includes(f[0])'
def digest(data):return hashlib.sha256(data).hexdigest()
def read(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("REA_STATE_R_INVALID_FILE_TYPE")
    fd=os.open(path,os.O_RDONLY | getattr(os,"O_NOFOLLOW",0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError("REA_STATE_R_INVALID_FILE_TYPE")
        with os.fdopen(fd,"rb") as f:return f.read()
    except:
        os.close(fd)
        raise
def validated():
    data=read(TARGET)
    if digest(data)!=OLD_SHA or data.count(OLD)!=1 or data.count(NEW)!=0:
        raise RuntimeError("REA_STATE_R_BASELINE_DRIFT")
    patch=data.replace(OLD,NEW,1)
    return data,patch
def selftest():
    source,patch=validated()
    assert digest(source)==OLD_SHA
    assert patch.count(NEW)==1 and patch.count(OLD)==0
    js=r'''
const isKernel=(o)=>["I","S","D","R"].includes(o.state)
 && Number.isSafeInteger(o.flags) && (o.flags&0x00200000)===0x00200000
 && o.ppid===2 && o.pgid===0 && o.realUid===0 && o.effectiveUid===0
 && o.before===o.after && /^\\d+$/u.test(o.before);
const ok={state:"R",flags:69238880,ppid:2,pgid:0,realUid:0,effectiveUid:0,before:"42978957",after:"42978957"};
if(!isKernel(ok))process.exit(1);
for(const change of [{state:"Z"},{flags:0},{ppid:1},{pgid:1},{realUid:1000},{effectiveUid:1000},{after:"123456"},{before:"not-a-generation"}]){
 if(isKernel({...ok,...change}))process.exit(2);
}
'''
    subprocess.run([NODE,"--input-type=module","-e",js],check=True,capture_output=True,timeout=12)
    with tempfile.NamedTemporaryFile(prefix=".rea-state-r-check-",suffix=".js",dir=TARGET.parent,delete=False) as f:
        check=Path(f.name)
        f.write(patch)
    try:subprocess.run([NODE,"--check",str(check)],check=True,capture_output=True,timeout=15)
    finally:check.unlink(missing_ok=True)
    print("REA_STATE_R_SELFTEST=PASS")
    print("REA_STATE_R_OLD_SHA="+OLD_SHA)
    print("REA_STATE_R_EXPECTED_SHA="+digest(patch))
def apply():
    source,patch=validated()
    meta=TARGET.stat()
    if not stat.S_ISREG(meta.st_mode):raise RuntimeError("REA_STATE_R_NOT_REGULAR")
    if BACKUP.exists():raise RuntimeError("REA_STATE_R_BACKUP_EXISTS_REFUSE")
    if BACKUP.parent.is_symlink() or not BACKUP.parent.is_dir():
        raise RuntimeError("REA_STATE_R_BACKUP_PARENT_INVALID")
    fd=os.open(BACKUP,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(source);out.flush();os.fsync(out.fileno())
    temp_fd,temp_name=tempfile.mkstemp(prefix=".rea-state-r-",suffix=".js",dir=TARGET.parent)
    temp=Path(temp_name)
    try:
        with os.fdopen(temp_fd,"wb") as out:
            out.write(patch);out.flush();os.fsync(out.fileno())
        os.chmod(temp,stat.S_IMODE(meta.st_mode))
        os.chown(temp,meta.st_uid,meta.st_gid)
        subprocess.run([NODE,"--check",str(temp)],check=True,capture_output=True,timeout=15)
        if digest(read(TARGET))!=OLD_SHA:raise RuntimeError("REA_STATE_R_CONCURRENT_DRIFT")
        os.replace(temp,TARGET)
    finally:temp.unlink(missing_ok=True)
    if digest(read(TARGET))!=digest(patch):raise RuntimeError("REA_STATE_R_READBACK_FAIL")
    print("REA_STATE_R_APPLY=PASS")
    print("REA_STATE_R_NEW_SHA="+digest(patch))
    print("REA_STATE_R_RESTART_REQUIRED=YES")
def status():
    value=read(TARGET)
    print("REA_STATE_R_CURRENT_SHA="+digest(value))
    print("REA_STATE_R_STATE_R_PRESENT="+str(value.count(NEW)==1))
    if BACKUP.exists():
        print("REA_STATE_R_BACKUP_VALID="+str(digest(read(BACKUP))==OLD_SHA))
def rollback():
    baseline=read(BACKUP)
    if digest(baseline)!=OLD_SHA:raise RuntimeError("REA_STATE_R_BAD_BACKUP")
    source=read(TARGET)
    if source.replace(NEW,OLD,1)!=baseline:raise RuntimeError("REA_STATE_R_ROLLBACK_DRIFT")
    meta=TARGET.stat()
    fd,name=tempfile.mkstemp(prefix=".rea-state-r-rollback-",suffix=".js",dir=TARGET.parent)
    temp=Path(name)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(baseline);f.flush();os.fsync(f.fileno())
        os.chmod(temp,stat.S_IMODE(meta.st_mode));os.chown(temp,meta.st_uid,meta.st_gid)
        subprocess.run([NODE,"--check",str(temp)],check=True,capture_output=True,timeout=15)
        os.replace(temp,TARGET)
    finally:temp.unlink(missing_ok=True)
    print("REA_STATE_R_ROLLBACK=PASS")
if __name__=="__main__":
    try:
        action=sys.argv[1] if len(sys.argv)==2 else ""
        if action=="selftest":selftest()
        elif action=="apply":selftest();apply()
        elif action=="status":status()
        elif action=="rollback":rollback()
        else:raise ValueError("usage: selftest|apply|status|rollback")
    except Exception as exc:
        print("REA_STATE_R_FAILED="+type(exc).__name__+":"+str(exc)[:220],file=sys.stderr)
        sys.exit(1)
