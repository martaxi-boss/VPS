#!/usr/bin/env python3
"""REA 6.8.0 local-only compiled PF_KTHREAD run-token correction.

A Linux kernel task, proved twice by native stat identity and PF_KTHREAD,
cannot be a user-owned PTY descendant. All user-process read failures remain
fail-closed. Original REA source and unrelated services are never changed.
"""
import hashlib, os, stat, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path("/opt/rea-reversa/rea")
TARGET=ROOT/"dist/process/ProcessOwnershipObservation.js"
BACKUP=ROOT/".rea-local-fixes/ProcessOwnershipObservation.pre-kthread-20261029.js"
NODE="/opt/rea-reversa/providers/node-v24.22.1/bin/node"
OLD_SHA="d96a5dd3d9482f15b09c610d942e849f3778264282c3111fe3d0f9f6ee5c67a2"
OLD=('            if (platform === "linux")\n'
     '                return parseProcessEnvironment(await readFile('+
     chr(96)+'/proc/'+'$'+'{pid}'+chr(96)+', { encoding: "utf8", signal }));')
NEW=r'''            if (platform === "linux") {
                try {
                    return parseProcessEnvironment(await readFile("/proc/" + pid + "/environ", { encoding: "utf8", signal }));
                }
                catch (cause) {
                    signal?.throwIfAborted();
                    // REA_680_PF_KTHREAD_GUARD: no unreadable user process is excused.
                    if (cause?.code === "ESRCH" || cause?.code === "ENOENT" ||
                        cause?.code === "EACCES" || cause?.code === "EPERM") {
                        const kernelIdentity = async () => {
                            const raw = await readFile("/proc/" + pid + "/stat", { encoding: "utf8", signal });
                            const close = raw.lastIndexOf(") ");
                            if (close < 0) return null;
                            const f = raw.slice(close + 2).trim().split(/\s+/u);
                            if (f.length < 20) return null;
                            const flags = Number(f[6]);
                            if (!Number.isSafeInteger(flags) ||
                                (flags & 0x00200000) !== 0x00200000 ||
                                Number(f[1]) !== 2 || Number(f[2]) !== 0 ||
                                !["I", "S", "D"].includes(f[0]) ||
                                !/^\d+$/u.test(f[19])) return null;
                            const status = await readFile("/proc/" + pid + "/status", { encoding: "utf8", signal });
                            const uid = /^Uid:\s+(\d+)\s+(\d+)/mu.exec(status);
                            if (uid === null || uid[1] !== "0" || uid[2] !== "0") return null;
                            return String(pid) + ":" + f[19] + ":" + flags + ":" + f[1] + ":" + f[2];
                        };
                        try {
                            const before = await kernelIdentity();
                            if (before !== null && before === await kernelIdentity())
                                return Object.create(null);
                        }
                        catch {
                            signal?.throwIfAborted();
                        }
                    }
                    throw cause;
                }
            }'''

def sha(x):return hashlib.sha256(x).hexdigest()
def read_regular(path):
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError("REA_KTHREAD=FILE_TYPE_REJECTED")
    return path.read_bytes()
def transform(x):
    if sha(x)!=OLD_SHA:raise RuntimeError("REA_KTHREAD=SOURCE_SHA_DRIFT")
    s=x.decode("utf8")
    if s.count(OLD)!=1 or "REA_680_PF_KTHREAD_GUARD" in s:
        raise RuntimeError("REA_KTHREAD=ANCHOR_DRIFT")
    return s.replace(OLD,NEW,1).encode("utf8")
def atomic_write(data,old_stat):
    fd,tmp=tempfile.mkstemp(prefix=".rea-kthread-",suffix=".js",dir=TARGET.parent)
    p=Path(tmp)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(p,stat.S_IMODE(old_stat.st_mode))
        os.chown(p,old_stat.st_uid,old_stat.st_gid)
        os.replace(p,TARGET)
    finally:p.unlink(missing_ok=True)
def syntax_test(data):
    fd,tmp=tempfile.mkstemp(prefix=".rea-kthread-verify-",suffix=".js",dir=TARGET.parent)
    p=Path(tmp)
    try:
        with os.fdopen(fd,"wb") as f:f.write(data)
        subprocess.run([NODE,"--check",str(p)],check=True,capture_output=True,timeout=25)
    finally:p.unlink(missing_ok=True)
    print("REA_KTHREAD_SYNTAX=PASS")
def native_tests():
    script=r'''
import {createSystemProcessOwnershipHost} from "file:///opt/rea-reversa/rea/dist/process/ProcessOwnershipObservation.js";
import {readdirSync,readFileSync} from "node:fs";
const host=createSystemProcessOwnershipHost("linux");
const own=await host.environment(process.pid);
if(own.REA_PROCESS_RUN_ID!=="rea680-token-canary")throw Error("USER_TOKEN_LOST");
let count=0;
for(const pid of readdirSync("/proc")){
 if(!/^\d+$/u.test(pid))continue;
 try{
  const raw=readFileSync("/proc/"+pid+"/stat","utf8");
  const f=raw.slice(raw.lastIndexOf(") ")+2).trim().split(/\s+/u);
  if(!((Number(f[6])&0x00200000)===0x00200000&&Number(f[1])===2&&Number(f[2])===0))continue;
  const result=await host.environment(Number(pid));
  if(Object.keys(result).length!==0)throw Error("KERNEL_TOKEN_NOT_EMPTY");
  if(++count>=8)break;
 }catch(e){
   if(e?.message==="KERNEL_TOKEN_NOT_EMPTY")throw e;
   if(e?.code!=="ESRCH"&&e?.code!=="ENOENT")throw e;
 }
}
if(count<4)throw Error("KERNEL_SAMPLES_INSUFFICIENT");
let rejected=false;
try{await host.environment(2147483646)}catch(e){rejected=e?.code==="ENOENT"||e?.code==="ESRCH"}
if(!rejected)throw Error("MISSING_PROCESS_NOT_REJECTED");
console.log("REA_KTHREAD_NATIVE_PASS="+count);
'''
    env=dict(os.environ,REA_PROCESS_RUN_ID="rea680-token-canary")
    for user in (None,"ubuntu"):
        cmd=[NODE,"--input-type=module","-e",script]
        if user:cmd=["runuser","-u",user,"--"]+cmd
        r=subprocess.run(cmd,env=env,check=True,text=True,capture_output=True,timeout=40)
        if "REA_KTHREAD_NATIVE_PASS=" not in r.stdout:raise RuntimeError("REA_KTHREAD_NO_PROOF")
        print("REA_KTHREAD_NATIVE_USER="+(user or "root")+" "+r.stdout.strip())
def apply():
    if os.geteuid()!=0:raise RuntimeError("REA_KTHREAD=ROOT_REQUIRED")
    if not Path(NODE).is_file():raise RuntimeError("REA_KTHREAD=NODE_MISSING")
    current=read_regular(TARGET)
    if sha(current)!=OLD_SHA:
        if BACKUP.is_file() and sha(read_regular(BACKUP))==OLD_SHA and current==transform(BACKUP.read_bytes()):
            print("REA_KTHREAD=ALREADY_APPLIED_SHA="+sha(current))
            return
        raise RuntimeError("REA_KTHREAD=REFUSE_UNEXPECTED_RUNTIME_SHA")
    new=transform(current);expected=sha(new)
    syntax_test(new)
    print("REA_KTHREAD_CANDIDATE_SHA="+expected)
    if BACKUP.exists() or BACKUP.is_symlink():
        if sha(read_regular(BACKUP))!=OLD_SHA:raise RuntimeError("REA_KTHREAD=BACKUP_DRIFT")
    else:
        BACKUP.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if BACKUP.parent.is_symlink():raise RuntimeError("REA_KTHREAD=UNSAFE_BACKUP")
        fd=os.open(BACKUP,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(current);f.flush();os.fsync(f.fileno())
    meta=TARGET.stat()
    atomic_write(new,meta)
    try:
        if sha(read_regular(TARGET))!=expected:raise RuntimeError("REA_KTHREAD=POSTWRITE_DRIFT")
        native_tests()
        subprocess.run(["systemctl","restart","rea-reversa-mcp.service"],
                       check=True,capture_output=True,timeout=45)
        r=subprocess.run(["systemctl","is-active","rea-reversa-mcp.service"],
                         check=True,capture_output=True,text=True,timeout=10)
        if r.stdout.strip()!="active":raise RuntimeError("REA_KTHREAD=SERVICE_INACTIVE")
    except Exception:
        atomic_write(current,meta)
        subprocess.run(["systemctl","restart","rea-reversa-mcp.service"],
                       capture_output=True,timeout=45,check=False)
        print("REA_KTHREAD_AUTOMATIC_ROLLBACK=PASS",file=sys.stderr)
        raise
    print("REA_KTHREAD_APPLY=PASS")
    print("REA_KTHREAD_RUNTIME_SHA="+expected)
    print("REA_KTHREAD_SERVICE=active")
def check():
    actual=read_regular(TARGET);backup=read_regular(BACKUP)
    if sha(backup)!=OLD_SHA or actual!=transform(backup):
        raise RuntimeError("REA_KTHREAD_CHECK=FAIL")
    print("REA_KTHREAD_CHECK=PASS;sha="+sha(actual))
if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="apply":apply()
    elif len(sys.argv)==2 and sys.argv[1]=="check":check()
    else:raise SystemExit("usage: apply|check")
