#!/usr/bin/env python3
"""REA 6.8.0: verified PF_KTHREAD exception for relation-free cleanup scans.

This changes only the deployed compiled ProcessOwnership.js overlay.
No upstream source, SSH transport, other services or process signals are changed.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT=Path("/opt/rea-reversa/rea")
TARGET=ROOT/"dist/process/ProcessOwnership.js"
BACKUP=ROOT/".rea-local-fixes/ProcessOwnership.pre-native-kthread-20261029.js"
NODE="/opt/rea-reversa/providers/node-v24.22.1/bin/node"
BASE_SHA="896032442deb6ee3aad314d5778e7310ff5598127a03d667387724085984cec6"
IMPORT='import { execFile } from "node:child_process";'
ANCHOR='''        if (fact.token.state !== "unavailable")
            continue;
        const relationBefore = fact.identityBefore.state === "readable"'''
NEW_ANCHOR='''        if (fact.token.state !== "unavailable")
            continue;
        // An independently native-verified kernel task is never capture-owned.
        // Missing relation context does not turn PF_KTHREAD into a user process.
        // Keep token-verified retained owners and all uncertain facts fail closed.
        if (await reaVerifiedNativeKernelTask(fact, retainedCandidate)) {
            unverified.push({
                pid: fact.process.pid,
                diagnostic: "verified_unrelated_pf_kthread:" + fact.token.reason,
            });
            continue;
        }
        const relationBefore = fact.identityBefore.state === "readable"'''
HELPER=r'''
/** No relation-free exceptions without two stable Linux native observations. */
const reaVerifiedNativeKernelTask = async (fact, retainedCandidate) => {
    if (process.platform !== "linux" ||
        retainedCandidate !== undefined ||
        fact.state !== "same-generation" ||
        fact.identityBefore.state !== "readable" ||
        fact.identityAfter.state !== "readable" ||
        fact.identityBefore.identity !== fact.identityAfter.identity)
        return false;
    const beforeRelation = fact.identityBefore.relation;
    const afterRelation = fact.identityAfter.relation;
    if (beforeRelation?.state !== "observed" ||
        afterRelation?.state !== "observed" ||
        beforeRelation.parentPid !== 2 || afterRelation.parentPid !== 2 ||
        beforeRelation.processGroupId !== 0 || afterRelation.processGroupId !== 0)
        return false;
    const pid = fact.process.pid;
    if (!Number.isSafeInteger(pid) || pid <= 2)
        return false;
    const read = async () => {
        const raw = await reaReadKernelFile("/proc/" + pid + "/stat", { encoding: "utf8" });
        const close = raw.lastIndexOf(") ");
        if (close < 0 || Number(raw.slice(0, raw.indexOf(" (")).trim()) !== pid)
            return null;
        const f = raw.slice(close + 2).trim().split(/\s+/u);
        if (f.length < 20 || !["I", "S", "D", "R"].includes(f[0]) ||
            Number(f[1]) !== 2 || Number(f[2]) !== 0 ||
            !/^\d+$/u.test(f[19]))
            return null;
        const flags = Number(f[6]);
        if (!Number.isSafeInteger(flags) || (flags & 0x00200000) !== 0x00200000)
            return null;
        const status = await reaReadKernelFile("/proc/" + pid + "/status",
            { encoding: "utf8" });
        const uids = /^Uid:\s+(\d+)\s+(\d+)/mu.exec(status);
        if (uids === null || uids[1] !== "0" || uids[2] !== "0")
            return null;
        return f[19] + ":" + String(flags);
    };
    try {
        const first = await read();
        if (first === null)
            return false;
        const second = await read();
        return second === first &&
            fact.identityAfter.identity === "linux-starttime:" + first.split(":")[0];
    }
    catch {
        return false;
    }
};
'''
TEST_JS=r'''
import { readdirSync, readFileSync } from "node:fs";
import { createSystemProcessOwnershipHost } from "file:///opt/rea-reversa/rea/dist/process/ProcessOwnershipObservation.js";
import { verifyNoTokenOwnedProcesses } from "file:///REA_TEST_CANDIDATE";
import { ProcessOwnershipEvidenceOwner } from "file:///opt/rea-reversa/rea/dist/process/ProcessOwnershipEvidence.js";
const validKernelPids = [];
for (const name of readdirSync("/proc")) {
 if (!/^\d+$/u.test(name)) continue;
 const pid=Number(name);
 if (pid<=2) continue;
 try {
  const raw=readFileSync("/proc/"+pid+"/stat","utf8");
  const fields=raw.slice(raw.lastIndexOf(") ")+2).split(/\s+/u);
  if (Number(fields[1])===2 && Number(fields[2])===0 &&
      (Number(fields[6])&0x00200000)===0x00200000 &&
      ["I","S","D","R"].includes(fields[0]))validKernelPids.push(pid);
 } catch {}
}
const base=createSystemProcessOwnershipHost("linux");
const forced = async()=>{const error=Object.assign(new Error("ESRCH: controlled unreadable environment"),{code:"ESRCH"});throw error;};
let success=null;
for (const pid of validKernelPids.slice(0,60)) {
 const row={pid,parentPid:2,processGroupId:0,uid:0,state:"I",command:"kworker"};
 const fake={...base,listProcesses:async()=>[row],environment:forced};
 const result=await verifyNoTokenOwnedProcesses("rea680-kthread-negative-scope",fake,[],undefined);
 if(result.cleaned===true && result.unverified?.some(x=>x.pid===pid)){
  success={pid,result};break;
 }
}
if(success===null)throw Error("REA_KTHREAD_NATIVE_POSITIVE_NOT_ESTABLISHED");
const own=process.pid;
const userHost={...base,listProcesses:async()=>[{pid:own,parentPid:1,processGroupId:own,uid:process.getuid(),state:"S",command:"node"}],environment:forced};
const denial=await verifyNoTokenOwnedProcesses("rea680-kthread-negative-scope",userHost,[],undefined);
if(denial.cleaned!==false || !denial.reason?.includes("environment_errno_ESRCH"))
 throw Error("REA_KTHREAD_USER_PROCESS_FALSE_ACCEPTANCE");
const badNativeHost={...base,listProcesses:async()=>[{pid:success.pid,parentPid:2,processGroupId:0,uid:0,state:"I",command:"kworker"}],environment:forced,
 processIdentities:async()=>new Map([[success.pid,{state:"readable",identity:"linux-starttime:99999999999",lifecycle:{state:"observed",lifecycle:"non-zombie"},relation:{state:"observed",parentPid:2,processGroupId:0},effectiveUid:0}]])};
const wrongGeneration=await verifyNoTokenOwnedProcesses("rea680-kthread-negative-scope",badNativeHost,[],undefined);
if(wrongGeneration.cleaned!==false)
 throw Error("REA_KTHREAD_CHANGED_GENERATION_FALSE_ACCEPTANCE");
const retainedRow={pid:success.pid,parentPid:2,processGroupId:0,uid:0,state:"I",command:"kworker"};
const retainedHost={...base,listProcesses:async()=>[retainedRow],environment:forced};
const retainedRecord={pid:success.pid,process:retainedRow,identity:undefined,applicability:"related-ownership-unresolved",scopeEvidence:"previously-related-generation"};
const retainedOwner={
 candidates:[retainedRecord],
 rowsForObservation:(rows)=>rows,
 reconcile:()=>[retainedRecord]
};
const retained=await verifyNoTokenOwnedProcesses("rea680-kthread-negative-scope",retainedHost,[],
 {leaderPid:900000,processGroupId:900000,evidenceOwner:retainedOwner});
if(retained.cleaned!==false || !retained.reason?.includes("environment_errno_ESRCH"))
 throw Error("REA_KTHREAD_RETAINED_CANDIDATE_FALSE_ACCEPTANCE");
console.log(JSON.stringify({native_kernel_pass:true,verified_pid:success.pid,normal_user_fail_closed:true,wrong_generation_fail_closed:true,retained_owner_fail_closed:true,unverified_count:success.result.unverified.length}));
'''
def sha(data):return hashlib.sha256(data).hexdigest()
def safe_read(path):
    if path.is_symlink() or not path.is_file():raise RuntimeError("REA_NATIVE_FILE_TYPE")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    with os.fdopen(fd,"rb") as stream:return stream.read()
def transform(data):
    if sha(data)!=BASE_SHA:raise RuntimeError("REA_NATIVE_BASE_DRIFT")
    source=data.decode("utf8")
    if (source.count(IMPORT)!=1 or source.count(ANCHOR)!=1 or
        "reaVerifiedNativeKernelTask" in source):
        raise RuntimeError("REA_NATIVE_ANCHOR_DRIFT")
    source=source.replace(IMPORT,IMPORT+'\nimport { readFile as reaReadKernelFile } from "node:fs/promises";',1)
    source=source.replace('const scanWithOwnershipEvidence = async ',HELPER+'\nconst scanWithOwnershipEvidence = async ',1)
    source=source.replace(ANCHOR,NEW_ANCHOR,1)
    return source.encode("utf8")
def write_candidate(data):
    fd,name=tempfile.mkstemp(prefix=".rea-native-kthread-candidate-",suffix=".js",dir=TARGET.parent)
    p=Path(name)
    with os.fdopen(fd,"wb") as f:f.write(data)
    return p
def selftest():
    baseline=safe_read(TARGET)
    patched=transform(baseline)
    candidate=write_candidate(patched)
    try:
        subprocess.run([NODE,"--check",str(candidate)],check=True,capture_output=True,timeout=12)
        test=TEST_JS.replace("file:///REA_TEST_CANDIDATE",candidate.as_uri())
        result=subprocess.run([NODE,"--input-type=module","-e",test],
             check=True,capture_output=True,timeout=30,text=True)
        print("REA_NATIVE_SELFTEST="+result.stdout.strip())
    finally:candidate.unlink(missing_ok=True)
    print("REA_NATIVE_EXPECTED_SHA="+sha(patched))
    return baseline,patched
def apply():
    baseline,patched=selftest()
    meta=TARGET.stat()
    if BACKUP.exists() or BACKUP.parent.is_symlink() or not BACKUP.parent.is_dir():
        raise RuntimeError("REA_NATIVE_BACKUP_PATH_INVALID")
    backup_fd=os.open(BACKUP,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(backup_fd,"wb") as f:
        f.write(baseline);f.flush();os.fsync(f.fileno())
    staged=write_candidate(patched)
    try:
        os.chmod(staged,stat.S_IMODE(meta.st_mode));os.chown(staged,meta.st_uid,meta.st_gid)
        subprocess.run([NODE,"--check",str(staged)],check=True,capture_output=True,timeout=12)
        if safe_read(TARGET)!=baseline:raise RuntimeError("REA_NATIVE_CONCURRENT_DRIFT")
        os.replace(staged,TARGET)
    finally:staged.unlink(missing_ok=True)
    if safe_read(TARGET)!=patched:raise RuntimeError("REA_NATIVE_READBACK_FAIL")
    print("REA_NATIVE_APPLY=PASS")
    print("REA_NATIVE_NEW_SHA="+sha(patched))
    print("REA_NATIVE_RESTART_REQUIRED=YES")
def rollback():
    old=safe_read(BACKUP)
    if sha(old)!=BASE_SHA:raise RuntimeError("REA_NATIVE_INVALID_BACKUP")
    current=safe_read(TARGET)
    if transform(old)!=current:raise RuntimeError("REA_NATIVE_ROLLBACK_DRIFT")
    meta=TARGET.stat()
    staged=write_candidate(old)
    try:
        os.chmod(staged,stat.S_IMODE(meta.st_mode));os.chown(staged,meta.st_uid,meta.st_gid)
        subprocess.run([NODE,"--check",str(staged)],check=True,capture_output=True,timeout=12)
        os.replace(staged,TARGET)
    finally:staged.unlink(missing_ok=True)
    print("REA_NATIVE_ROLLBACK=PASS")
def status():
    print("REA_NATIVE_ACTIVE_SHA="+sha(safe_read(TARGET)))
    print("REA_NATIVE_BACKUP_PRESENT="+str(BACKUP.exists()))
if __name__=="__main__":
    try:
        action=sys.argv[1] if len(sys.argv)==2 else ""
        if action=="selftest":selftest()
        elif action=="apply":apply()
        elif action=="rollback":rollback()
        elif action=="status":status()
        else:raise RuntimeError("usage selftest|apply|rollback|status")
    except Exception as exc:
        print("REA_NATIVE_ERROR="+type(exc).__name__+":"+str(exc)[:300],file=sys.stderr)
        sys.exit(1)
