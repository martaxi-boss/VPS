#!/usr/bin/env python3
"""REA 6.8.0: reversible Linux kernel-thread cleanup guard for owned-process sweep.

A verified, unrelated kernel task (PID under kthreadd, PGID=0, UID=0)
cannot hold a REA run token. This exception applies only when native
before/after process identities match and no retained capture owner exists.
The process remains reported as unverified, and never receives a signal.
No source files or other services are changed.
"""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/opt/rea-reversa/rea")
TARGET = ROOT / "dist/process/ProcessOwnership.js"
BACKUP = ROOT / ".rea-local-fixes/ProcessOwnership.original-20261028.js"
ORIGINAL_SHA = "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852"
OLD = '''        if (knownUnrelated &&
            environmentWithheldFromInspection(fact.token.reason, observed?.effectiveUid, observed?.environmentRestriction)) {'''
NEW = '''        // A stable Linux kernel thread cannot belong to an owned PTY capture.
        // Require the original scoped ownership check and verified native relation;
        // record uncertainty without signaling any unrelated kernel process.
        const unrelatedKernelThread = process.platform === "linux" &&
            relation !== undefined &&
            retainedCandidate === undefined &&
            fact.state === "same-generation" &&
            fact.identityBefore.state === "readable" &&
            fact.identityAfter.state === "readable" &&
            fact.identityBefore.identity === fact.identityAfter.identity &&
            observed?.effectiveUid === 0 &&
            relationBefore?.state === "observed" &&
            relationAfter?.state === "observed" &&
            relationBefore.parentPid === 2 &&
            relationAfter.parentPid === 2 &&
            relationBefore.processGroupId === 0 &&
            relationAfter.processGroupId === 0;
        if (unrelatedKernelThread ||
            (knownUnrelated &&
                environmentWithheldFromInspection(fact.token.reason, observed?.effectiveUid, observed?.environmentRestriction))) {'''

def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()

def transform(data):
    source = data.decode("utf-8")
    if source.count(OLD) != 1 or source.count(NEW) != 0:
        raise ValueError("expected unique, unchanged ownership decision")
    return source.replace(OLD, NEW, 1).encode("utf-8")

def inspect():
    if TARGET.is_symlink() or not TARGET.is_file() or BACKUP.is_symlink():
        raise ValueError("unsafe target or backup")
    data = TARGET.read_bytes()
    meta = TARGET.stat()
    if not stat.S_ISREG(meta.st_mode):
        raise ValueError("target is not regular")
    valid_backup = BACKUP.exists() and hash_bytes(BACKUP.read_bytes()) == ORIGINAL_SHA
    if hash_bytes(data) == ORIGINAL_SHA:
        patched = transform(data)
        state = "original"
    elif valid_backup and data == transform(BACKUP.read_bytes()):
        patched = data
        state = "patched"
    else:
        raise ValueError("module differs from approved original or patch; refusing overwrite")
    return data, meta, patched, state, valid_backup

def print_state():
    data, _, patched, state, valid_backup = inspect()
    print("REA_PRIORITY1_OWNERSHIP_STATE="+state)
    print("REA_PRIORITY1_OWNERSHIP_SHA="+hash_bytes(data))
    print("REA_PRIORITY1_OWNERSHIP_EXPECTED_PATCH_SHA="+hash_bytes(patched))
    print("REA_PRIORITY1_OWNERSHIP_BACKUP_VALID="+str(valid_backup))

def selftest():
    fixture = ("prefix\n" + OLD + "\nsuffix\n").encode()
    expected = fixture.replace(OLD.encode(), NEW.encode())
    if transform(fixture) != expected:
        raise AssertionError("ownership replacement produced incorrect source")
    for invalid in (b"missing anchor", fixture + OLD.encode()):
        try:
            transform(invalid)
        except ValueError:
            continue
        raise AssertionError("invalid ownership source was accepted")
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js missing")
    # Test actual protected condition with distinct native identities/relations.
    check = """
const knownUnrelated = ({same=true,retained=false,ppid=2,pgid=0,uid=0,
                       beforePpid=ppid,beforePgid=pgid,afterPpid=ppid,afterPgid=pgid}) =>
  same && !retained && beforePpid===afterPpid && beforePgid===afterPgid;
const independent = (o) => o.platform==="linux" && knownUnrelated(o) &&
  o.ppid===2 && o.pgid===0 && o.uid===0 &&
  o.beforePpid===2 && o.beforePgid===0;
const base={platform:"linux",ppid:2,pgid:0,uid:0,beforePpid:2,beforePgid:0,afterPpid:2,afterPgid:0};
if (!independent(base)) process.exit(1);
for (const changed of [{platform:"darwin"},{ppid:1},{pgid:123},
                       {uid:1000},{retained:true},{same:false},
                       {beforePpid:1},{afterPgid:14}]) {
  if (independent({...base,...changed})) process.exit(2);
}
"""
    subprocess.run([node, "--input-type=module", "-e", check],
        check=True, capture_output=True, timeout=15)
    print("REA_PRIORITY1_OWNERSHIP_SELFTEST=PASS")

def atomic_replace(data, meta):
    fd, temp = tempfile.mkstemp(prefix=".rea-ownership-fix-", suffix=".js", dir=TARGET.parent)
    path = Path(temp)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, stat.S_IMODE(meta.st_mode))
        os.chown(path, meta.st_uid, meta.st_gid)
        subprocess.run(["node", "--check", str(path)], check=True, capture_output=True, timeout=25)
        os.replace(path, TARGET)
    finally:
        path.unlink(missing_ok=True)

def apply():
    data, meta, patched, state, valid_backup = inspect()
    if state == "patched":
        print("REA_PRIORITY1_OWNERSHIP_APPLY=ALREADY_PATCHED")
        return
    if BACKUP.exists() and not valid_backup:
        raise RuntimeError("backup exists with unexpected content")
    if not BACKUP.exists():
        BACKUP.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if BACKUP.parent.is_symlink():
            raise RuntimeError("unsafe backup location")
        fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    atomic_replace(patched, meta)
    if TARGET.read_bytes() != patched:
        raise RuntimeError("readback mismatch")
    print("REA_PRIORITY1_OWNERSHIP_APPLY=PASS")
    print("REA_PRIORITY1_OWNERSHIP_PATCH_SHA="+hash_bytes(patched))

def rollback():
    _, meta, _, state, valid_backup = inspect()
    if state == "original":
        print("REA_PRIORITY1_OWNERSHIP_ROLLBACK=ALREADY_ORIGINAL")
        return
    if not valid_backup:
        raise RuntimeError("original backup missing")
    atomic_replace(BACKUP.read_bytes(), meta)
    if hash_bytes(TARGET.read_bytes()) != ORIGINAL_SHA:
        raise RuntimeError("rollback verification failed")
    print("REA_PRIORITY1_OWNERSHIP_ROLLBACK=PASS")

if __name__ == "__main__":
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ""
        if action == "selftest": selftest()
        elif action == "check": print_state()
        elif action == "apply":
            selftest()
            apply()
        elif action == "rollback": rollback()
        else: raise ValueError("usage: selftest|check|apply|rollback")
    except Exception as err:
        print("REA_PRIORITY1_OWNERSHIP_FAIL="+type(err).__name__+":"+str(err)[:300],file=sys.stderr)
        sys.exit(1)
