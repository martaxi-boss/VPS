#!/usr/bin/env python3
"""Read-only inventory of external program prerequisites for original REA 6.8.0.

No package operations, sudo, chmod, MCP service calls, device access, dynamic
analysis, network targets, or vendor installation. Only known, bounded paths.
"""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/external-supplier-gaps-20261029")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
DIST={
 "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
 "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)

def ensure(check,desc):
    if not check:raise RuntimeError(desc)

def sh(cmd,timeout=12,env=None):
    try:
        return subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,cwd=ROOT,env=env,text=True,encoding="utf-8",
            errors="replace",timeout=timeout,check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd,124,"","TIMEOUT")
    except OSError as e:
        return subprocess.CompletedProcess(cmd,126,"",type(e).__name__)

def preflight():
    ensure(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","AUDIT_ONLY_UBUNTU")
    ensure(ROOT.is_dir() and not ROOT.is_symlink(),"OFFICIAL_ROOT_UNAVAILABLE")
    ensure((ROOT/"node_modules").is_symlink(),"ORIGINAL_DEPENDENCIES_NOT_SYMLINK")
    ensure((ROOT/"node_modules").resolve()==(OLD/"node_modules").resolve(),
           "ORIGINAL_DEPENDENCIES_ORIGIN_CHANGED")
    ensure((ROOT/"package-lock.json").read_bytes()==(OLD/"package-lock.json").read_bytes(),
           "ORIGINAL_LOCK_CHANGED")
    ensure(NODE.is_file(),"EXISTING_NODE_UNAVAILABLE")
    p=sh(["git","-C",str(ROOT),"rev-parse","HEAD"])
    ensure(p.returncode==0 and p.stdout.strip()==REV,"OFFICIAL_ENGINE_GIT_CHANGED")
    p=sh([str(NODE),"scripts/rea.mjs","--version"],timeout=30)
    ensure(p.returncode==0 and p.stdout.strip()=="6.8.0","OFFICIAL_ENGINE_VERSION_CHANGED")
    for file,digest in DIST.items():
        dest=ROOT/file
        ensure(dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest()==digest,
               "OFFICIAL_COMPILED_FILE_DRIFT:"+file)
    ensure(EVID.parent.is_dir(),"EVIDENCE_ROOT_NOT_FOUND")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_GAP_ORIGINAL_SOURCE_PIN=PASS",flush=True)
    print("REA_GAP_SOURCE_COMPILED_DIGEST=PASS",flush=True)
    print("REA_GAP_TRANSPORT=GITHUB_ACTIONS_SSH_TO_ORIGINAL_CLI_ONLY",flush=True)
    print("REA_GAP_INSTALLS_ON_VPS=ZERO",flush=True)
    print("REA_GAP_OLD_MCP_OR_SERVICE=UNTOUCHED",flush=True)

def env():
    e=dict(os.environ)
    for k in list(e):
        if k.startswith("REA_") or k in (
            "JAVA_HOME","GHIDRA_INSTALL_DIR","PLAYWRIGHT_BROWSERS_PATH",
            "HOPPER_LAUNCHER_PATH"):
            e.pop(k,None)
    e["PATH"]="/opt/rea-reversa/tools/jdk-21/bin:"+str(NODE.parent)+":"+e.get("PATH","")
    e["CI"]="1"
    e["HOME"]=str(EVID/"isolated-home")
    e["XDG_CACHE_HOME"]=str(EVID/"isolated-home/.cache")
    e["XDG_CONFIG_HOME"]=str(EVID/"isolated-home/.config")
    e["XDG_DATA_HOME"]=str(EVID/"isolated-home/.local/share")
    (EVID/"isolated-home").mkdir(parents=True,exist_ok=True,mode=0o700)
    return e

def checkbin(candidate):
    try:
        x=Path(candidate)
        return x.is_file() and os.access(x,os.X_OK)
    except (OSError,PermissionError):
        return False

def checkfile(candidate):
    try:
        return Path(candidate).is_file() and os.access(candidate,os.R_OK)
    except (OSError,PermissionError):
        return False

def find_entry(commands,patterns,envmap,kind="bin"):
    test=checkfile if kind=="file" else checkbin
    # Select via the login user's actual PATH, then well-known preinstalled
    # non-PATH vendor roots. Do not traverse roots owned by other projects.
    for cmd in commands:
        found=shutil.which(cmd,path=envmap.get("PATH"))
        if found and test(found):return {"found":True,"path":str(found),"source":"PATH"}
    for pattern in patterns:
        if "*" not in pattern and "?" not in pattern:
            candidates=[Path(pattern)]
        else:
            anchor=Path("/")
            candidates=list(anchor.glob(pattern.lstrip("/")))[:75]
        for p in candidates:
            if test(p):return {"found":True,"path":str(p),"source":"KNOWN_INSTALL_DIR"}
    return {"found":False,"path":None,"source":"NOT_FOUND_IN_ALLOWED_SEARCH"}

def inspect_browser():
    root=Path("/opt/rea-reversa/providers")
    for p in sorted(root.glob("chromium-playwright-*"))[:8]:
        if not p.is_dir():continue
        # Browser distribution may have different dir layouts; don't start a GUI.
        located=[]
        total=0
        for base,dirs,files in os.walk(p,followlinks=False):
            total+=1
            if total>3500:break
            dirs[:]=[name for name in dirs if name not in ("node_modules",".git","locales","resources","swiftshader")]
            for binary in ("chrome","chromium","headless_shell","chrome-headless-shell"):
                if binary in files and checkbin(Path(base)/binary):
                    located.append(str(Path(base)/binary))
                    break
            if located:break
        return {"found":True,"path":str(p),"browser_executable":located[0] if located else None,
                "source":"KNOWN_INSTALL_DIR"}
    return {"found":False,"path":None,"browser_executable":None,"source":"NOT_FOUND"}

def supplier_inventory(e):
    specs={
      "ghidra_headless":([],
        ["/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"]),
      "jdk_21":([],
        ["/opt/rea-reversa/tools/jdk-21/bin/java"]),
      "jadx_headless_jar":([],
        ["/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar"]),
      "unblob":([],
        ["/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob"]),
      "kuna":(["kuna"],
        ["/opt/rea-reversa/providers/kuna*/bin/kuna"]),
      "wakaru":(["wakaru"],
        ["/opt/rea-reversa/providers/wakaru-*/bin/wakaru"]),
      "mitmdump":(["mitmdump"],
        ["/opt/rea-reversa/providers/mitmproxy-*/bin/mitmdump"]),
      "rizin":(["rizin","rz-bin"],
        ["/opt/rea-reversa/providers/rizin*/bin/rizin",
         "/opt/rea-reversa/providers/rizin*/bin/rz-bin"]),
      "radare2":(["r2","radare2"],[]),
      "gdb":(["gdb"],[]),
      "gdb_multiarch":(["gdb-multiarch"],[]),
      "objdump":(["objdump"],[]),
      "binwalk":(["binwalk"],
        ["/opt/rea-reversa/providers/binwalk*/bin/binwalk"]),
      "apktool":(["apktool"],[]),
      "adb":(["adb"],[]),
      "tshark":(["tshark"],[]),
      "capinfos":(["capinfos"],[]),
      "tcpdump":(["tcpdump"],[]),
      "sigrok_cli":(["sigrok-cli"],[]),
      "ffmpeg":(["ffmpeg"],[]),
      "wasm2wat":(["wasm2wat"],
        ["/opt/rea-reversa/providers/wabt*/bin/wasm2wat"]),
      "wasm_objdump":(["wasm-objdump"],
        ["/opt/rea-reversa/providers/wabt*/bin/wasm-objdump"]),
      "sevenzip":(["7z"],[]),
      "debugfs":(["debugfs"],[]),
      "prlimit":(["prlimit"],[]),
      "python3":(["python3"],[]),
      "ilspycmd":(["ilspycmd"],
        ["/home/ubuntu/.dotnet/tools/ilspycmd",
         "/opt/rea-reversa/providers/ilspy*/ilspycmd"]),
      "dotnet":(["dotnet"],
        ["/home/ubuntu/.dotnet/dotnet","/usr/share/dotnet/dotnet"]),
      "mono":(["mono"],[]),
      "pwndbg_gdbinit":([],
        ["/opt/pwndbg/gdbinit.py","/home/ubuntu/pwndbg/gdbinit.py",
         "/opt/rea-reversa/providers/pwndbg*/gdbinit.py"]),
      "pwndbg_venv_python":([],
        ["/opt/rea-reversa/providers/pwndbg*/.venv/bin/python",
         "/opt/pwndbg/.venv/bin/python",
         "/home/ubuntu/pwndbg/.venv/bin/python"]),
      "frida_cli":(["frida"],[]),
      "ida_engine":(["idat64","ida64","idalib-mcp","ida"],
        ["/opt/ida*/idat64","/opt/ida*/ida64",
         "/opt/rea-reversa/providers/ida*/ida64",
         "/opt/rea-reversa/providers/ida*/idat64"]),
      "jeb_launcher":(["jeb_linux.sh","jeb"],
        ["/opt/jeb*/jeb_linux.sh",
         "/opt/rea-reversa/providers/jeb*/jeb_linux.sh"]),
      "hopper_launcher":([],
        ["/opt/hopper/bin/Hopper"]),
      "cutter_appimage":(["cutter"],
        ["/opt/rea-reversa/providers/cutter-*/bin/Cutter*.AppImage"]),
      "clang":(["clang"],[]),
      "lld":(["ld.lld","lld"],[]),
      "lld_link":(["lld-link"],[])
    }
    found={}
    for key,(commands,patterns) in specs.items():
        t="file" if key in ("jadx_headless_jar","pwndbg_gdbinit") else "bin"
        found[key]=find_entry(commands,patterns,e,kind=t)
    found["chromium_playwright"]=inspect_browser()
    found["frida_node_binding"]={"found":(ROOT/"node_modules/frida").exists(),
                "path":"existing_node_modules/frida" if (ROOT/"node_modules/frida").exists() else None,
                "source":"PREEXISTING_NODE_PACKAGE"}
    try:
        found["pwntools_python"]={"found":importlib.util.find_spec("pwn") is not None,
                    "source":"UBUNTU_PYTHON_MODULE","path":None}
    except (ImportError,ModuleNotFoundError):
        found["pwntools_python"]={"found":False,"source":"UBUNTU_PYTHON_MODULE","path":None}
    return found

def safe_versions(found,e):
    versions={}
    for key,flag in [
      ("apktool","--version"),("unblob","--version"),
      ("binwalk","--version"),("kuna","--version"),("wakaru","--version"),
      ("mitmdump","--version"),("rizin","--version"),("gdb","--version"),
      ("dotnet","--version"),("ilspycmd","--version"),("sigrok_cli","--version"),
      ("tshark","--version"),("ffmpeg","-version"),("wasm2wat","--version"),
      ("adb","version")
    ]:
        row=found.get(key,{})
        if row.get("found") and row.get("path") and Path(row["path"]).is_file():
            versions[key]=(row["path"],flag)
    def probe(entry):
        name,(path,flag)=entry
        res=sh([path,flag],timeout=12,env=e)
        raw=(res.stdout+"\n"+res.stderr).strip()
        # Numeric version and fixed header only; never dump entire output.
        head=raw.splitlines()[0][:100] if raw else ""
        return (name,{"exit_code":res.returncode,
                    "first_line":head if res.returncode==0 else ""})
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        probes=list(pool.map(probe,versions.items()))
    return dict(probes)

def main():
    preflight()
    e=env()
    suppliers=supplier_inventory(e)
    versions=safe_versions(suppliers,e)
    expected_ready=["ghidra_headless","jdk_21","jadx_headless_jar",
        "unblob","kuna","wakaru","mitmdump","rizin","gdb",
        "objdump","binwalk","apktool","adb","tshark",
        "sigrok_cli","ffmpeg","wasm2wat","sevenzip","prlimit"]
    optional_missing=["ilspycmd","dotnet","mono","pwndbg_gdbinit",
       "pwndbg_venv_python","frida_cli","ida_engine","jeb_launcher"]
    ready=[k for k in expected_ready if suppliers[k]["found"]]
    unclear=[k for k in expected_ready if not suppliers[k]["found"]]
    optional_absent=[k for k in optional_missing if not suppliers[k]["found"]]
    report={
      "engine":"REA_original_6.8.0", "source_sha":REV,
      "host":"Ubuntu 24.04 x86_64, ubuntu SSH principal",
      "transport":"GitHub Actions pinned SSH, one-shot original CLI",
      "old_mcp_used":False,"changed_original_source":False,
      "installed_packages_on_vps":0,"changed_services":0,
      "supplier_inventory":suppliers,"read_only_version_probes":versions,
      "expected_binaries_observed":ready,
      "expected_binaries_not_found_at_allowed_paths":unclear,
      "optional_binaries_not_found_at_allowed_paths":optional_absent,
      "limitations":[
       "Discovery uses only the ubuntu PATH and bounded known vendor paths.",
       "A file present does not prove a licensed session, authenticated GUI, or usable remote target.",
       "No MCP server or supplier was started; only preinstalled CLI --version probes.",
       "Optional ILSpyCmd requires .NET but is not required for built-in managed parser.",
       "Frida Node binding, not frida CLI, is used by official REA dynamic Frida provider.",
       "Cutter requires authenticated GUI v2 session; browser needs authorized CDP target.",
       "Apktool 2.7.0-dirty has security advisory; verify distribution backports before untrusted APKs.",
       "No Android device, Apple macOS host or paid IDA/JEB license is assumed."
      ]
    }
    (EVID/"summary.json").write_text(json.dumps(report,indent=2,sort_keys=True),encoding="utf8")
    print("REA_GAP_EXPECTED_PRESENT="+str(len(ready)),flush=True)
    print("REA_GAP_EXPECTED_NOT_FOUND="+str(len(unclear)),flush=True)
    for k in expected_ready:
        row=suppliers[k]
        print("REA_GAP_CORE_"+k.upper()+"="+("FOUND" if row["found"] else "NOT_FOUND")+
              ((";path="+str(row["path"])) if row.get("path") else ""),flush=True)
    for k in optional_missing+["hopper_launcher","cutter_appimage","chromium_playwright",
                              "frida_node_binding","pwntools_python","gdb_multiarch","radare2"]:
        row=suppliers[k]
        print("REA_GAP_OPTIONAL_"+k.upper()+"="+
              ("FOUND" if row["found"] else "NOT_FOUND")+
              (";path="+str(row["path"]) if row.get("path") else ""),flush=True)
    for key,row in versions.items():
        print("REA_GAP_VERSION_"+key.upper()+"="+row["first_line"][:85]+
              ";exit="+str(row["exit_code"]),flush=True)
    print("REA_GAP_EVIDENCE="+str(EVID/"summary.json"),flush=True)
    print("REA_GAP_STATUS=COMPLETE_READ_ONLY",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("REA_GAP_FATAL="+type(exc).__name__+":"+str(exc)[:160],flush=True)
        sys.exit(42)
