#!/usr/bin/env python3
"""P1: locate existing compatible Ghidra, JADX and Unblob on Ubuntu (read-only).

Runs as ubuntu via existing GitHub Actions -> pinned SSH, never uses/starts MCP,
never installs, changes daemon settings, symlinks providers, or copies old code.
Only original independent checkout and its own evidence directory are used.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import time
import zipfile

ROOT=pathlib.Path("/home/ubuntu/rea-original-upstream-680")
EVID=pathlib.Path("/home/ubuntu/rea-original-upstream-680-evidence/provider-paths-20261029")
PREVIOUS=pathlib.Path("/opt/rea-reversa/rea")
NODE=pathlib.Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
COMMIT="160d821ac9a0310afcb8d1fc427862dd6508add5"
GHIDRA_JS_SHA256="2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852"
OWNERSHIP_OBS_SHA256="81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655"
JADX_CLASSES={
    "com/atxx/jhmcp/JadxSession.class",
    "com/atxx/jhmcp/SessionHolder.class",
    "jadx/api/JadxDecompiler.class",
    "com/google/gson/Gson.class",
    "io/modelcontextprotocol/kotlin/sdk/server/Server.class",
}
os.umask(0o077)

def check(value, tag):
    if not value:
        raise RuntimeError(tag)

def run(cmd,env=None,timeout=20):
    try:
        return subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,env=env,cwd=ROOT,timeout=timeout,check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd,124,"","TIMED_OUT")

def validate_original():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","REQUIRES_UBUNTU_USER")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"ORIGINAL_ROOT_INVALID")
    check(NODE.is_file(),"REUSED_NODE_NOT_FOUND")
    check((ROOT/"node_modules").is_symlink(),"ORIGINAL_DEPS_NOT_REUSED")
    check((ROOT/"node_modules").resolve()==(PREVIOUS/"node_modules").resolve(),
          "REUSED_DEPS_ARE_NOT_EXPECTED_TREE")
    check((ROOT/"package-lock.json").read_bytes()==(PREVIOUS/"package-lock.json").read_bytes(),
          "ORIGINAL_DEPENDENCY_LOCK_MISMATCH")
    rev=run(["git","-C",str(ROOT),"rev-parse","HEAD"])
    check(rev.returncode==0 and rev.stdout.strip()==COMMIT,"ORIGINAL_SOURCE_CHANGED")
    for file,wanted in [
      ("dist/process/ProcessOwnership.js",GHIDRA_JS_SHA256),
      ("dist/process/ProcessOwnershipObservation.js",OWNERSHIP_OBS_SHA256)
    ]:
        selected=ROOT/file
        check(selected.is_file() and hashlib.sha256(selected.read_bytes()).hexdigest()==wanted,
              "ORIGINAL_BUILD_CHANGED:"+file)
    check(EVID.parent.is_dir(),"EXPECTED_EVIDENCE_ROOT_MISSING")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_P1_ORIGINAL_VERIFIED=PASS",flush=True)
    print("REA_P1_TRANSPORT=GITHUB_ACTIONS_SSH_CLI_NO_MCP",flush=True)
    print("REA_P1_PROVIDER_INSTALLS=ZERO",flush=True)
    print("REA_P1_ORIGINAL_FILES_CHANGED=ZERO",flush=True)

def allowed_path(raw):
    # Only supplier path metadata is admitted, never credentials or arbitrary
    # daemon environment variables; never display any raw systemd output.
    if not raw or "\n" in raw or len(raw)>500:
        return None
    try:
        p=pathlib.Path(raw)
        if not p.is_absolute():
            return None
        if not any(raw==prefix or raw.startswith(prefix+"/")
                   for prefix in ("/opt","/usr","/home/ubuntu","/srv")):
            return None
        return p
    except (OSError,TypeError,ValueError):
        return None

def read_provider_hints_only():
    result={"read_only":True,"service_called":False,"service_modified":False,
            "hints":{},"unavailable":None}
    # Read only the service manager's published path metadata; this does not
    # connect to or start the previous MCP. The value of any unrelated setting
    # is discarded without logging.
    p=run(["systemctl","show","rea-reversa-mcp.service","--property=Environment",
           "--value","--no-pager"],timeout=8)
    if p.returncode!=0:
        result["unavailable"]="systemd_read_unavailable"
        return result
    try:
        items=shlex.split(p.stdout)
    except ValueError:
        result["unavailable"]="systemd_environment_parse_unavailable"
        return result
    for item in items:
        key,sep,val=item.partition("=")
        if not sep or key not in {
          "GHIDRA_INSTALL_DIR","REA_JADX_MCP_JAR",
          "REA_UNBLOB_COMMAND","REA_UNBLOB_PYTHON",
        }:
            continue
        loc=allowed_path(val)
        if loc is not None:
            result["hints"][key]=str(loc)
    return result

def walk_for_candidates():
    candidates={"ghidra":[],"jadx":[],"unblob":[],"java_jdk":[]}
    dirs_scanned=0
    skipped_access=0
    bases=[
      pathlib.Path("/opt/rea-reversa"),pathlib.Path("/opt/ghidra"),
      pathlib.Path("/opt"),pathlib.Path("/usr/local"),
      pathlib.Path("/usr/share"),pathlib.Path("/usr/lib/jvm"),
      pathlib.Path("/home/ubuntu"),
      pathlib.Path("/srv"),
    ]
    # Avoid rescanning nested paths, and avoid globbing unreadable /root.
    roots=[]
    for path in bases:
        if not path.exists() or not path.is_dir():
            continue
        if any(path.is_relative_to(x) for x in roots):
            continue
        roots=[x for x in roots if not x.is_relative_to(path)]
        roots.append(path)
    # Enforce finite per-root traversal; do not crawl source code/node_modules
    # or sensitive private application directories.
    for base in roots:
        rootdepth=len(base.parts)
        for current, dirs, files in os.walk(base,topdown=True,followlinks=False):
            dirs_scanned+=1
            if dirs_scanned>28000:
                return candidates,{"directories_scanned":dirs_scanned,
                                   "access_skipped":skipped_access,
                                   "limit_reached":True}
            current_dir=pathlib.Path(current)
            depth=len(current_dir.parts)-rootdepth
            if depth>=10:
                dirs[:]=[]
            else:
                dirs[:]=[d for d in dirs if d not in {
                   ".git","node_modules",".turbo",".cache",".npm","__pycache__",
                   ".venv-cache","proc","sys","dev","postgresql",
                   "lost+found",
                } and not (d.startswith(".") and d not in {".venv",".local"})]
            # A full JDK has java and javac, unlike a JRE-only directory.
            if (current_dir/"release").is_file() and (
                current_dir/"bin/java").is_file() and (
                current_dir/"bin/javac").is_file():
                candidates["java_jdk"].append(str(current_dir))
            # Official Ghidra root is the parent of Ghidra/application.properties.
            if current_dir.name=="Ghidra" and "application.properties" in files:
                p=current_dir.parent
                if (p/"support/analyzeHeadless").is_file():
                    candidates["ghidra"].append(str(p))
            if current_dir.name=="support" and "analyzeHeadless" in files:
                p=current_dir.parent
                if (p/"Ghidra/application.properties").is_file():
                    candidates["ghidra"].append(str(p))
            for filename in files:
                low=filename.lower()
                file=current_dir/filename
                if low.endswith(".jar") and "jadx" in low:
                    candidates["jadx"].append(str(file))
                elif low=="unblob" and current_dir.name in {"bin","scripts","sbin"}:
                    candidates["unblob"].append(str(file))
            # Spot symlinked provider roots without walking through arbitrary links.
            if current_dir.name=="providers":
                for d in dirs:
                    p=current_dir/d
                    if p.is_symlink():
                        try:
                            dest=p.resolve(strict=True)
                            if (dest/"Ghidra/application.properties").is_file() and (
                                dest/"support/analyzeHeadless").is_file():
                                candidates["ghidra"].append(str(dest))
                        except (OSError,RuntimeError):
                            skipped_access+=1
    return candidates,{"directories_scanned":dirs_scanned,
                       "access_skipped":skipped_access,"limit_reached":False}

def safe_is_file(path):
    try:
        return path.is_file()
    except (OSError,PermissionError):
        return False

def safe_exists(path):
    try:
        return path.exists()
    except (OSError,PermissionError):
        return False

def safe_access(path,mode):
    try:
        return os.access(path,mode)
    except (OSError,PermissionError):
        return False

def ghidra_test(path):
    p=pathlib.Path(path)
    props=p/"Ghidra/application.properties"
    headless=p/"support/analyzeHeadless"
    metadata=safe_is_file(props) and safe_access(props,os.R_OK)
    launcher=safe_is_file(headless) and safe_access(headless,os.X_OK)
    return {"path":str(p),"exists":safe_exists(p),
            "readable_metadata":metadata,
            "headless_exists":safe_is_file(headless),
            "headless_executable":launcher,
            "accessible_for_ubuntu":metadata and launcher}

def jadx_test(path):
    p=pathlib.Path(path)
    is_file=safe_is_file(p)
    readable=is_file and safe_access(p,os.R_OK)
    data={"path":str(p),"is_file":is_file,
          "readable":readable,
          "official_bridge_classes_present":False}
    if readable:
        try:
            with zipfile.ZipFile(p) as z:
                # ZIP index only; never extract, run Java or modify the JAR.
                names=set(z.namelist())
                data["official_bridge_classes_present"]=JADX_CLASSES.issubset(names)
                data["missing_class_count"]=len(JADX_CLASSES-names)
        except (zipfile.BadZipFile,OSError,PermissionError):
            data["archive_invalid_or_unreadable"]=True
    return data

def unblob_test(path):
    p=pathlib.Path(path)
    is_file=safe_is_file(p)
    executable=is_file and safe_access(p,os.X_OK)
    result={"path":str(p),"is_file":is_file,"executable":executable}
    if not is_file:
        result["note"]="NOT_VISIBLE_AS_REGULAR_FILE_TO_UBUNTU_OR_NOT_FOUND"
    if executable:
        try:
            with p.open("rb") as f:
                first=f.readline(300)
            if first.startswith(b"#!"):
                target=first[2:].decode("utf-8",errors="replace").strip().split(" ")[0]
                result["shebang_interpreter_exists"]=safe_is_file(pathlib.Path(target)) if target.startswith("/") else None
        except (OSError,PermissionError):
            result["shebang_interpreter_exists"]=None
            result["note"]="EXECUTE_PERMISSION_PRESENT_BUT_READING_HEADER_BLOCKED"
    return result

def jdk_test(path):
    p=pathlib.Path(path)
    java=p/"bin/java"
    javac=p/"bin/javac"
    result={"path":str(p),"java_executable":safe_is_file(java) and safe_access(java,os.X_OK),
            "javac_executable":safe_is_file(javac) and safe_access(javac,os.X_OK),
            "major":None}
    release=p/"release"
    if safe_is_file(release) and safe_access(release,os.R_OK):
        try:
            text=release.read_text(encoding="utf-8",errors="replace")[:10000]
            match=re.search(r'(?m)^JAVA_VERSION="?(\d+)(?:\.|")',text)
            if match:result["major"]=int(match.group(1))
        except (OSError,PermissionError):
            pass
    result["usable_for_ghidra"]=(result["java_executable"] and
                                result["javac_executable"] and
                                result["major"] is not None and result["major"] >= 21)
    return result

def unblob_permission_chain(path):
    # List only exact provider path components and their POSIX metadata;
    # no parent directory enumeration, permissions changes or process signals.
    p=pathlib.Path(path)
    chain=[]
    curr=pathlib.Path("/")
    for component in p.parts[1:]:
        curr=curr/component
        try:
            st=curr.lstat()
            chain.append({"path":str(curr),"mode":oct(st.st_mode & 0o777),
                          "uid":st.st_uid,"gid":st.st_gid,
                          "ubuntu_can_traverse":safe_access(curr,os.X_OK)})
        except (OSError,PermissionError) as e:
            chain.append({"path":str(curr),"error":type(e).__name__})
            break
    return chain

def scoped_doctor(label,env,provider):
    output=run([str(NODE),"scripts/rea.mjs","doctor","--provider",provider,"--json"],
               env=env,timeout=85)
    (EVID/(label+".json")).write_text(output.stdout,encoding="utf-8")
    (EVID/(label+".stderr")).write_text(output.stderr,encoding="utf-8")
    try:
        data=json.loads(output.stdout)
        if isinstance(data,dict) and isinstance(data.get("result"),dict):
            data=data["result"]
        if not isinstance(data,dict):data={}
    except (ValueError,TypeError):
        data={}
    return {"provider":provider,"exit_code":output.returncode,
            "json":bool(data),"healthy":data.get("healthy",None)}

def main():
    validate_original()
    hints=read_provider_hints_only()
    scanned,scope=walk_for_candidates()
    names=list(pathlib.Path("/usr/bin").glob("unblob")) + list(pathlib.Path("/usr/local/bin").glob("unblob"))
    unblob_path=shutil.which("unblob")
    if unblob_path:names.append(pathlib.Path(unblob_path))
    scanned["unblob"] += [str(p) for p in names if p.is_file()]
    for key,kind in [("GHIDRA_INSTALL_DIR","ghidra"),
                     ("REA_JADX_MCP_JAR","jadx"),("REA_UNBLOB_COMMAND","unblob")]:
        if key in hints["hints"]:
            scanned[kind].insert(0,hints["hints"][key])
    info={
      "source_commit":COMMIT,
      "transport":"GitHub Actions SSH, no legacy MCP used",
      "installations":0,"changed_engine":False,"changed_old_service":False,
      "scan_scope":scope,"systemd_hints":hints,
      "ghidra":[ghidra_test(x) for x in dict.fromkeys(scanned["ghidra"])][:15],
      "jadx":[jadx_test(x) for x in dict.fromkeys(scanned["jadx"])][:20],
      "unblob":[unblob_test(x) for x in dict.fromkeys(scanned["unblob"])][:20],
      "jdk":[jdk_test(x) for x in dict.fromkeys(scanned["java_jdk"])][:20],
    }
    # Check only own user's read-only CLI environment.
    isolated=EVID/"isolated-home"
    isolated.mkdir(mode=0o700,parents=True,exist_ok=True)
    env=dict(os.environ)
    for name in list(env):
        if name.startswith("REA_") or name in ("GHIDRA_INSTALL_DIR","JAVA_HOME",
                                                  "HOPPER_LAUNCHER_PATH"):
            env.pop(name,None)
    env["HOME"]=str(isolated)
    env["XDG_CACHE_HOME"]=str(isolated/".cache")
    env["XDG_CONFIG_HOME"]=str(isolated/".config")
    env["XDG_DATA_HOME"]=str(isolated/".local/share")
    env["PATH"]=str(NODE.parent)+":"+env.get("PATH","")
    goodgh=next((c["path"] for c in info["ghidra"] if c["accessible_for_ubuntu"]),None)
    goodjadx=next((c["path"] for c in info["jadx"] if c["official_bridge_classes_present"]),None)
    goodunblob=next((c["path"] for c in info["unblob"] if c["executable"] and
                     c.get("shebang_interpreter_exists",True) is not False),None)
    if goodgh:env["GHIDRA_INSTALL_DIR"]=goodgh
    if goodjadx:env["REA_JADX_MCP_JAR"]=goodjadx
    # Existing JDK 21+ is required for official Ghidra 12.1.4.
    selected_jdk=next((c["path"] for c in info["jdk"] if c["usable_for_ghidra"]),None)
    if selected_jdk:
        env["JAVA_HOME"]=selected_jdk
    else:
        javac=shutil.which("javac",path=env["PATH"])
        if javac:
            java_home=pathlib.Path(javac).resolve().parent.parent
            if safe_is_file(java_home/"bin/java"):
                env["JAVA_HOME"]=str(java_home)
    info["unblob_permission_chain"]=[
        unblob_permission_chain(c["path"])
        for c in info["unblob"] if not c["executable"]
    ][:4]
    info["selected_paths"]={
      "ghidra":goodgh,"jadx_jar":goodjadx,"unblob":goodunblob,
      "java_home":env.get("JAVA_HOME")
    }
    info["doctor"]={
      "ghidra":scoped_doctor("doctor-ghidra",env,"ghidra"),
      "jadx":scoped_doctor("doctor-jadx",env,"jadx")
    }
    # Persist only provider path metadata, not the raw systemd environment.
    (EVID/"summary.json").write_text(json.dumps(info,indent=2,sort_keys=True),encoding="utf-8")
    print("REA_P1_DIRECTORIES_SCANNED="+str(scope["directories_scanned"]),flush=True)
    print("REA_P1_GHIDRA_CANDIDATES="+str(len(info["ghidra"])),flush=True)
    print("REA_P1_JADX_CANDIDATES="+str(len(info["jadx"])),flush=True)
    print("REA_P1_UNBLOB_CANDIDATES="+str(len(info["unblob"])),flush=True)
    print("REA_P1_JDK_CANDIDATES="+str(len(info["jdk"])),flush=True)
    for candidate in info["jdk"][:12]:
        print("REA_P1_JDK="+candidate["path"]+";major="+
              str(candidate["major"])+";ghidra_compatible="+
              str(candidate["usable_for_ghidra"]).lower(),flush=True)
    for chain in info["unblob_permission_chain"]:
        problem=next((q for q in chain if not q.get("ubuntu_can_traverse",False)),None)
        if problem:
            print("REA_P1_UNBLOB_FIRST_DENIED="+problem["path"]+
                  ";mode="+str(problem.get("mode","UNKNOWN"))+
                  ";uid="+str(problem.get("uid","UNKNOWN")),flush=True)

    for kind,records,checkfield in [
       ("GHIDRA",info["ghidra"],"accessible_for_ubuntu"),
       ("JADX",info["jadx"],"official_bridge_classes_present"),
       ("UNBLOB",info["unblob"],"executable")]:
        for record in records[:10]:
            print("REA_P1_PATH_"+kind+"="+record["path"]+";usable="+
                  str(record.get(checkfield,False)).lower(),flush=True)
    for kind,value in info["selected_paths"].items():
        print("REA_P1_SELECTED_"+kind.upper()+"="+str(value or "NONE"),flush=True)
    for kind,record in info["doctor"].items():
        print("REA_P1_DOCTOR_"+kind.upper()+"="+
              ("PASS" if record["exit_code"]==0 and record["healthy"] is True else "NOT_READY")+
              ";rc="+str(record["exit_code"]),flush=True)
    print("REA_P1_READONLY_ACCEPTANCE=PASS",flush=True)
    print("REA_P1_EVIDENCE="+str(EVID),flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print("REA_P1_EXECUTION_ERROR="+type(e).__name__+":"+str(e)[:190],flush=True)
        sys.exit(41)
