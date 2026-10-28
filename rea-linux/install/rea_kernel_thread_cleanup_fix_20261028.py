#!/usr/bin/env python3
"""Reversible REA 6.8.0 Linux kernel-thread cleanup correction.

Only the compiled ProcessOwnershipObservation module is overlaid. Official
source code and other services are left untouched. Never signal any PID here.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/opt/rea-reversa/rea")
TARGET = ROOT / "dist/process/ProcessOwnershipObservation.js"
BACKUP = ROOT / ".rea-local-fixes/ProcessOwnershipObservation.original-20261028.js"
ORIGINAL_SHA = "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655"
OLD = '''            .filter((match) => match !== null)
            .map((match) => ({
            pid: Number(match[1]),
            parentPid: Number(match[2]),
            processGroupId: Number(match[3]),'''
NEW = '''            .filter((match) => match !== null)
            // Linux kernel threads have process group zero; they are not PTY children.
            .filter((match) => platform !== "linux" || Number(match[3]) > 0)
            .map((match) => ({
            pid: Number(match[1]),
            parentPid: Number(match[2]),
            processGroupId: Number(match[3]),'''

def digest(data):
    return hashlib.sha256(data).hexdigest()

def transform(data):
    source = data.decode("utf-8")
    if source.count(OLD) != 1 or source.count(NEW) != 0:
        raise ValueError("expected unique, unchanged process-list selection")
    return source.replace(OLD, NEW, 1).encode("utf-8")

def inspect():
    if TARGET.is_symlink() or not TARGET.is_file() or BACKUP.is_symlink():
        raise ValueError("invalid target or backup path")
    data, metadata = TARGET.read_bytes(), TARGET.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("target is not a regular file")
    original = digest(data) == ORIGINAL_SHA
    backup_valid = BACKUP.exists() and digest(BACKUP.read_bytes()) == ORIGINAL_SHA
    if original:
        patched = transform(data)
        state = "original"
    elif backup_valid and data == transform(BACKUP.read_bytes()):
        patched = data
        state = "patched"
    else:
        raise ValueError("target SHA differs from approved version; refusal to overwrite")
    return data, metadata, patched, state, backup_valid

def selftest():
    sample = ("fixture\n" + OLD + "\n").encode()
    assert transform(sample) == sample.replace(OLD.encode(), NEW.encode())
    for invalid in [sample + OLD.encode(), b"no expected insertion point"]:
        try:
            transform(invalid)
            raise AssertionError("invalid insertion point accepted")
        except ValueError:
            pass
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("node executable not available")
    js = '''const data=["10 2 0 0 I [kworker]","11 1 11 1000 S owned","12 1 12 2000 S foreign"];
const filtered = (platform)=>data.map(x=>/\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(.*)/u.exec(x))
.filter(x=>x!==null).filter(x=>platform!=="linux"||Number(x[3])>0).map(x=>Number(x[1]));
if(JSON.stringify(filtered("linux"))!=="[11,12]")process.exit(1);
if(JSON.stringify(filtered("darwin"))!=="[10,11,12]")process.exit(2);'''
    subprocess.run([node, "-e", js], check=True, timeout=12, capture_output=True)
    print("REA_PRIORITY1_SELFTEST=PASS")

def replace_atomic(data, metadata):
    fd, name = tempfile.mkstemp(prefix=".rea-priority1-", suffix=".js", dir=TARGET.parent)
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, stat.S_IMODE(metadata.st_mode))
        os.chown(path, metadata.st_uid, metadata.st_gid)
        subprocess.run(["node", "--check", str(path)], check=True, timeout=20, capture_output=True)
        os.replace(path, TARGET)
    finally:
        path.unlink(missing_ok=True)

def apply():
    data, metadata, patched, state, backup_valid = inspect()
    if state == "patched":
        print("REA_PRIORITY1_APPLY=ALREADY_PATCHED")
        return
    if BACKUP.exists():
        if not backup_valid:
            raise ValueError("existing backup is not the exact upstream module")
    else:
        BACKUP.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if BACKUP.parent.is_symlink():
            raise ValueError("unsafe backup parent")
        fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    replace_atomic(patched, metadata)
    if digest(TARGET.read_bytes()) != digest(patched):
        raise RuntimeError("patched file readback mismatch")
    print("REA_PRIORITY1_APPLY=PASS")
    print("REA_PRIORITY1_PATCHED_SHA="+digest(patched))

def rollback():
    _, metadata, _, state, backup_valid = inspect()
    if state == "original":
        print("REA_PRIORITY1_ROLLBACK=ALREADY_ORIGINAL")
        return
    if not backup_valid:
        raise RuntimeError("original backup missing or hash mismatch")
    replace_atomic(BACKUP.read_bytes(), metadata)
    if digest(TARGET.read_bytes()) != ORIGINAL_SHA:
        raise RuntimeError("rollback readback mismatch")
    print("REA_PRIORITY1_ROLLBACK=PASS")

if __name__ == "__main__":
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ""
        if action == "selftest": selftest()
        elif action == "check":
            data, _, patched, state, backup_valid = inspect()
            print("REA_PRIORITY1_STATE="+json.dumps({"state":state,"sha256":digest(data),
                "patched_sha256":digest(patched),"backup_valid":backup_valid},sort_keys=True))
        elif action == "apply":
            selftest()
            apply()
        elif action == "rollback": rollback()
        else: raise ValueError("usage: selftest | check | apply | rollback")
    except Exception as cause:
        print("REA_PRIORITY1_FAIL="+type(cause).__name__+":"+str(cause)[:700],file=sys.stderr)
        sys.exit(1)
