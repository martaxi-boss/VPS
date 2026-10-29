#!/usr/bin/env python3
"""Independent REA original supplier/certified-capability comparison.

Execution: existing GitHub Actions -> pinned SSH -> ubuntu -> official upstream
REA CLI. Never start the old MCP, alter services, install packages, or copy
compiled modules/old runtime configuration into the original.
"""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path("/home/ubuntu/rea-original-upstream-680")
EVID = pathlib.Path("/home/ubuntu/rea-original-upstream-680-evidence/vendor-matrix-20261029")
PREVIOUS = pathlib.Path("/opt/rea-reversa/rea")
NODE = pathlib.Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
REV = "160d821ac9a0310afcb8d1fc427862dd6508add5"
COMPILED = {
 "dist/process/ProcessOwnership.js":
 "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
 "dist/process/ProcessOwnershipObservation.js":
 "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)

def verify(condition, error):
    if not condition:
        raise RuntimeError(error)

def run(cmd, env=None, timeout=40):
    try:
        return subprocess.run(cmd, cwd=ROOT, env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "REMOTE_TEST_TIMEOUT")

def preflight():
    verify(pwd.getpwuid(os.geteuid()).pw_name == "ubuntu", "UNPRIVILEGED_UBUNTU_REQUIRED")
    verify(ROOT.is_dir() and not ROOT.is_symlink(), "ORIGINAL_ROOT_NOT_PRESENT")
    verify(NODE.is_file(), "EXISTING_NODE_NOT_FOUND")
    verify((ROOT/"node_modules").is_symlink(), "NO_NEW_DEPENDENCIES_ALLOWED")
    verify((ROOT/"node_modules").resolve() == (PREVIOUS/"node_modules").resolve(),
           "ONLY_EXISTING_DEPENDENCIES_ALLOWED")
    verify((ROOT/"package-lock.json").read_bytes() == (PREVIOUS/"package-lock.json").read_bytes(),
           "DIFFERENT_DEPENDENCY_LOCK")
    verify((ROOT/"node_modules/.package-lock.json").is_file(),
           "EXISTING_LOCK_UNAVAILABLE")
    rev = run(["git","-C",str(ROOT),"rev-parse","HEAD"])
    verify(rev.returncode == 0 and rev.stdout.strip() == REV, "ORIGINAL_COMMIT_CHANGED")
    deps = run([str(NODE),"scripts/check-dependency-install.mjs"], timeout=40)
    verify(deps.returncode == 0, "DEPENDENCY_LOCK_CHECK_FAILED")
    version = run([str(NODE),"scripts/rea.mjs","--version"],timeout=30)
    verify(version.returncode == 0 and version.stdout.strip()=="6.8.0",
           "ORIGINAL_VERSION_CHANGED")
    for path,digest in COMPILED.items():
        target=ROOT/path
        verify(target.is_file() and not target.is_symlink(),"EXPECTED_ORIGINAL_COMPILED_MISSING:"+path)
        verify(hashlib.sha256(target.read_bytes()).hexdigest()==digest,
               "COMPILED_ORIGINAL_DIFFERS:"+path)
    verify(EVID.parent.is_dir(), "EVIDENCE_ROOT_MISSING")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    (EVID/"isolated-home").mkdir(mode=0o700,exist_ok=True)
    print("REA_VENDOR_MATRIX_ORIGINAL_SOURCE=PINNED_UNMODIFIED", flush=True)
    print("REA_VENDOR_MATRIX_EXISTING_DEPENDENCIES=VERIFIED_REUSED",flush=True)
    print("REA_VENDOR_MATRIX_EXTERNAL_INSTALLS=0",flush=True)
    print("REA_VENDOR_MATRIX_TRANSPORT=GITHUB_ACTIONS_TO_SSH_TO_ORIGINAL_CLI",flush=True)
    print("REA_VENDOR_MATRIX_OLD_MCP_CONNECTION=NOT_USED",flush=True)

def save(label, suffix, val):
    path=EVID/(label+"."+suffix)
    path.write_text(val,encoding="utf8",errors="replace")

def environment():
    env = dict(os.environ)
    env["PATH"] = str(NODE.parent)+":"+env.get("PATH","")
    env["HOME"] = str(EVID/"isolated-home")
    for key,val in {
       "XDG_CACHE_HOME":str(EVID/"isolated-home/.cache"),
       "XDG_CONFIG_HOME":str(EVID/"isolated-home/.config"),
       "XDG_DATA_HOME":str(EVID/"isolated-home/.local/share"),
       "CI":"1",
    }.items():
        env[key]=val
    # No persistent service context, credentials, previous connection or tokens.
    for key in list(env):
        if key.startswith("REA_") or key in ("GHIDRA_INSTALL_DIR","HOPPER_LAUNCHER_PATH",
                                            "PLAYWRIGHT_BROWSERS_PATH"):
            env.pop(key,None)
    return env

def installed_path(patterns, is_accepted):
    for root_pattern in patterns:
        for item in sorted(pathlib.Path("/").glob(root_pattern.lstrip("/"))):
            try:
                if is_accepted(item):
                    return item.resolve()
            except (OSError,PermissionError):
                pass
    return None

def existing_vendor_env(plain):
    env=plain.copy()
    candidates = {}
    roots = [
        "/opt/ghidra*","/opt/ghidra*/ghidra*",
        "/opt/rea-reversa/providers/ghidra*",
        "/opt/rea-reversa/providers/ghidra*/ghidra*",
        "/opt/rea-reversa/providers/*/ghidra*",
        "/opt/rea-reversa/providers/*/*/ghidra*",
        "/opt/rea-reversa/ghidra*",
        "/usr/share/ghidra","/usr/local/share/ghidra*",
    ]
    home = installed_path(roots,
        lambda p:p.is_dir() and (p/"support/analyzeHeadless").is_file()
            and (p/"Ghidra/application.properties").is_file())
    # Discover existing, non-standard vendor locations by scanning only
    # bounded /opt supplier roots. Never load the old REA daemon's environment,
    # read its credential files or add any provider package.
    vendor_bases = [pathlib.Path("/opt/rea-reversa/providers")]
    for entry in sorted(pathlib.Path("/opt").glob("*ghidra*")):
        if entry.is_dir():vendor_bases.append(entry)
    for entry in sorted(pathlib.Path("/opt").glob("*jadx*")):
        if entry.is_dir():vendor_bases.append(entry)
    jar=None
    examined=0
    for base in vendor_bases:
        if not base.is_dir():continue
        for current,dirs,files in os.walk(base,followlinks=False):
            examined+=1
            if examined > 25000:break
            dirs[:]=[d for d in dirs if d not in (".git","node_modules","__pycache__",".turbo")]
            folder=pathlib.Path(current)
            if home is None and folder.name=="support" and "analyzeHeadless" in files:
                possible=folder.parent
                if (possible/"Ghidra/application.properties").is_file():
                    home=possible.resolve()
            for filename in files:
                if filename=="jadx-headless-mcp-0.7.1-all.jar":
                    candidate=folder/filename
                    if jar is None and candidate.is_file() and os.access(candidate,os.R_OK):
                        jar=candidate.resolve()
        if examined>25000:break
    if jar is not None:
        env["REA_JADX_MCP_JAR"]=str(jar)
        candidates["jadx_headless_mcp_jar"]=str(jar)
    else:
        candidates["jadx_headless_mcp_jar"]=None
    print("REA_VENDOR_SCANNED_DIRECTORIES="+str(examined),flush=True)
    if home is not None:
        env["GHIDRA_INSTALL_DIR"]=str(home)
        candidates["ghidra"]=str(home)
    else:
        # No old daemon environment or custom bridge is imported.
        candidates["ghidra"]=None
    for name,env_key,patterns in [
        ("kuna","REA_KUNA_COMMAND",
         ["/opt/rea-reversa/providers/kuna*/bin/kuna",
          "/opt/rea-reversa/providers/kuna*/kuna","/opt/kuna*/bin/kuna"]),
        ("wakaru","REA_WAKARU_COMMAND",
         ["/opt/rea-reversa/providers/wakaru-*/bin/wakaru"]),
        ("mitmdump","REA_MITMDUMP_COMMAND",
         ["/opt/rea-reversa/providers/mitmproxy-*/bin/mitmdump"]),
    ]:
        located=installed_path(patterns,lambda p:p.is_file() and os.access(p,os.X_OK))
        if located is None:
            fallback=shutil.which(name)
            located=pathlib.Path(fallback).resolve() if fallback else None
        if located:
            env[env_key]=str(located)
            candidates[name]=str(located)
        else:
            candidates[name]=None
    browser_root=installed_path(["/opt/rea-reversa/providers/chromium-playwright-*"],
                                lambda p:p.is_dir())
    if browser_root:
        env["PLAYWRIGHT_BROWSERS_PATH"]=str(browser_root)
        candidates["chromium_playwright"]=str(browser_root)
    else:
        candidates["chromium_playwright"]=None
    # For executables installed outside the Ubuntu login PATH, locate only
    # existing bounded provider paths. Do not copy or install anything.
    missing_execs = {
      "jadx": ["/opt/rea-reversa/providers/jadx*/bin/jadx",
               "/opt/rea-reversa/providers/jadx*/jadx",
               "/opt/rea-reversa/providers/*/jadx/bin/jadx"],
      "rizin": ["/opt/rea-reversa/providers/rizin*/bin/rizin",
                "/opt/rea-reversa/providers/rizin*/bin/rz-bin"],
      "unblob": ["/opt/rea-reversa/providers/unblob*/bin/unblob"],
      "wabt": ["/opt/rea-reversa/providers/wabt*/bin/wasm2wat"],
    }
    discovered_bins=[]
    for name, patterns in missing_execs.items():
        p=installed_path(patterns,lambda x:x.is_file() and os.access(x,os.X_OK))
        if p is not None:
            discovered_bins.append(str(p.parent))
    for directory in dict.fromkeys(discovered_bins):
        env["PATH"] += ":"+directory
    javac = shutil.which("javac",path=env["PATH"])
    if home is not None and javac:
        jdk = pathlib.Path(javac).resolve().parent.parent
        if (jdk/"bin/java").is_file() and (jdk/"bin/javac").is_file():
            env["JAVA_HOME"] = str(jdk)
    # Existing binary dependencies are exposed by PATH in child processes only.
    for label,commands in [
        ("gdb",["gdb"]),("rizin",["rizin","rz-bin"]),("radare2",["radare2"]),
        ("jadx",["jadx"]),("apktool",["apktool"]),("adb",["adb"]),
        ("binwalk",["binwalk"]),("unblob",["unblob"]),("tshark",["tshark"]),
        ("sigrok",["sigrok-cli"]),("java",["java"]),("ffmpeg",["ffmpeg"]),
        ("wabt",["wasm2wat"]),("objdump",["objdump"]),("pwntools_python",["python3"])
    ]:
        found=next((shutil.which(c, path=env["PATH"]) for c in commands
                    if shutil.which(c,path=env["PATH"])),None)
        candidates[label]=found
    # Never print secret values, arbitrary process environments or configuration.
    save("supplier_inventory","json",json.dumps(candidates,indent=2,sort_keys=True))
    for label,path in candidates.items():
        print("REA_VENDOR_PRESENT_"+label.upper()+"="+("YES" if path else "NO"),flush=True)
    return env,candidates

def cli(label,args,env,timeout=60):
    p=run([str(NODE),"scripts/rea.mjs",*args,"--json"],env=env,timeout=timeout)
    save(label,"json",p.stdout)
    save(label,"stderr",p.stderr)
    try:
        obj=json.loads(p.stdout)
        if isinstance(obj,dict) and isinstance(obj.get("result"),dict):
            obj=obj["result"]
        if not isinstance(obj,dict):obj={}
    except (ValueError,TypeError):
        obj={}
    errtype = None
    if isinstance(obj.get("error"),dict):
        errtype=obj["error"].get("code")
    return {"label":label,"command":args,"exit_code":p.returncode,
            "valid_json":bool(obj),"reported_healthy":obj.get("healthy"),
            "error_code":errtype,
            "cleanup_incomplete":"cleanup_incomplete" in (p.stdout+p.stderr).lower()}

def capture(label,count,env):
    script=("import subprocess; "
            "p=[subprocess.Popen(['/usr/bin/true']) for _ in range("+str(count)+")];"
            "r=[x.wait() for x in p];"
            "print('SUPPLIER_CHILDREN="+str(count)+" FAILED='+str(sum(bool(v) for v in r)))")
    scenario={"executable":"/usr/bin/python3","arguments":["-c",script],
              "timeout_ms":25000}  # default settlement, no forced longer window
    file=EVID/(label+".scenario.json")
    save(label,"scenario.json",json.dumps(scenario,sort_keys=True))
    p=run([str(NODE),"scripts/rea.mjs","capture-process",str(file),"--json"],env=env,timeout=65)
    save(label,"evidence.json",p.stdout)
    save(label,"stderr",p.stderr)
    try:
        data=json.loads(p.stdout)
        if isinstance(data,dict) and isinstance(data.get("result"),dict):
            data=data["result"]
        if not isinstance(data,dict):data={}
    except (TypeError,ValueError):
        data={}
    norm=data.get("normalized_result",{})
    if not isinstance(norm,dict):norm={}
    cleanup=norm.get("cleanup",{})
    if not isinstance(cleanup,dict):cleanup={}
    exit_data=norm.get("exit",{})
    if not isinstance(exit_data,dict):exit_data={}
    settle=norm.get("settlement",{})
    if not isinstance(settle,dict):settle={}
    failure="cleanup_incomplete" in (p.stdout+p.stderr).lower()
    accepted=(p.returncode==0 and exit_data.get("code")==0
       and cleanup.get("owned_process_group") in ("verified","cleaned")
       and cleanup.get("temporary_root") in ("removed","cleaned") and not failure)
    print("REA_VENDOR_CAPTURE="+label+";result="+("PASS" if accepted else "FAIL")+
          ";cleanup_incomplete="+str(failure).lower()+
          ";settlement="+str(settle.get("state")),flush=True)
    return {"name":label,"result":"PASS" if accepted else "FAIL",
            "cleanup_incomplete":failure,"settlement":settle.get("state"),
            "cleanup":cleanup,"cli_exit_code":p.returncode}

def main():
    preflight()
    base=environment()
    vendor,candidates=existing_vendor_env(base)
    checks=[]
    # Compare original without provider-specific override to original with only
    # installed vendor paths; neither environment includes an existing MCP client.
    for stage,env in [("baseline",base),("existing",vendor)]:
        for count,repeat in [(8,6),(30,8)]:
            for i in range(1,repeat+1):
                checks.append(capture("%s-children-%d-%02d"%(stage,count,i),count,env))
    # Controlled provider-loaded parallel cases on the original only.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        pending=[
            pool.submit(capture,"existing-parallel-%s"%letter,30,vendor)
            for letter in ["a","b"]
        ]
        for f in concurrent.futures.as_completed(pending):checks.append(f.result())
    print("REA_VENDOR_MATRIX_BASELINE_COMPLETE=YES",flush=True)
    doctor=[]
    for label,args,timeout in [
       ("catalog-providers",["providers"],45),
       ("catalog-capabilities",["capabilities"],45),
       ("doctor-existing-ghidra",["doctor","--provider","ghidra"],110),
       ("doctor-existing-jadx",["doctor","--provider","jadx"],95),
       ("doctor-existing-kuna",["doctor","--provider","kuna"],95),
       ("doctor-existing-hopper",["doctor","--provider","hopper"],95),
    ]:
        v=cli(label,args,vendor,timeout)
        doctor.append(v)
        print("REA_VENDOR_DIAGNOSTIC="+label+";exit="+str(v["exit_code"])+
              ";json="+str(v["valid_json"]).lower()+
              ";healthy="+str(v["reported_healthy"]),flush=True)
    # Use only static read-only CLI commands backed by an earlier certified
    # tool family; certification status is not copied into the new original.
    real=[]
    for label,args,limit in [
       ("certified-elf-notes",["inspect-elf-notes","/usr/bin/true"],60),
       ("certified-inspect-artifact",["inspect-artifact","/usr/bin/true"],60),
    ]:
        v=cli(label,args,vendor,limit)
        v["status"]="PASS" if v["exit_code"]==0 and v["valid_json"] and not v["cleanup_incomplete"] else "FAIL"
        real.append(v)
        print("REA_VENDOR_PRIOR_CERTIFIED_FAMILY="+label+";result="+v["status"],flush=True)
    # Ghidra actual provider-owned analysis on an installed, immutable Linux
    # binary. Only try if a scoped doctor reported readiness. Do not start
    # unauthorised GUI/provider bridges or trigger package installation.
    gh=next((x for x in doctor if x["label"]=="doctor-existing-ghidra"),None)
    if gh and gh["exit_code"]==0:
        v=cli("ghidra-original-analyze-true",
              ["analyze","/usr/bin/true","--provider","ghidra"],vendor,320)
        v["status"]="PASS" if v["exit_code"]==0 and v["valid_json"] and not v["cleanup_incomplete"] else "FAIL"
        real.append(v)
        print("REA_VENDOR_REAL_GHIDRA="+v["status"]+
              ";error="+str(v["error_code"]),flush=True)
    else:
        print("REA_VENDOR_REAL_GHIDRA=NOT_READY_NO_SCOPED_DOCTOR_PASS",flush=True)
    # Kuna one-shot has a separate project-export path and has limits. Run a
    # read-only native overview only if its scoped doctor is ready.
    kn=next((x for x in doctor if x["label"]=="doctor-existing-kuna"),None)
    if kn and kn["exit_code"]==0:
        v=cli("kuna-original-inspect-true",
              ["analyze","/usr/bin/true","--provider","kuna"],vendor,210)
        v["status"]="PASS" if v["exit_code"]==0 and v["valid_json"] and not v["cleanup_incomplete"] else "FAIL"
        real.append(v)
        print("REA_VENDOR_REAL_KUNA="+v["status"],flush=True)
    else:
        print("REA_VENDOR_REAL_KUNA=NOT_READY_NO_SCOPED_DOCTOR_PASS",flush=True)
    failures=[x for x in checks if x["result"]!="PASS"]
    real_fails=[x for x in real if x["status"]!="PASS"]
    issue=sum(1 for x in checks if x["cleanup_incomplete"])
    summary={
        "source":"morluto/rea@"+REV,
        "no_new_vendor_installs":True,
        "no_original_mcp":True,
        "certification_rule":"Prior 170/229 tool roster is a test selection reference, not a transferable certificate.",
        "captures_total":len(checks),"captures_pass":len(checks)-len(failures),
        "captures_failed":len(failures),"cleanup_incomplete":issue,
        "provider_candidates":candidates,
        "provider_diagnostics":doctor,
        "retested_certified_tool_families":real,
        "tool_family_failed":len(real_fails),
        "cases":checks,
        "outcome":"PASS" if not failures and not real_fails else "FAIL",
    }
    save("summary","json",json.dumps(summary,indent=2,sort_keys=True))
    print("REA_VENDOR_MATRIX_TOTAL="+str(len(checks)),flush=True)
    print("REA_VENDOR_MATRIX_CAPTURE_PASS="+str(len(checks)-len(failures)),flush=True)
    print("REA_VENDOR_MATRIX_CAPTURE_FAIL="+str(len(failures)),flush=True)
    print("REA_VENDOR_MATRIX_CLEANUP_INCOMPLETE="+str(issue),flush=True)
    print("REA_VENDOR_MATRIX_TOOL_FAMILY_TESTS="+str(len(real)),flush=True)
    print("REA_VENDOR_MATRIX_TOOL_FAMILY_FAIL="+str(len(real_fails)),flush=True)
    print("REA_VENDOR_MATRIX_EVIDENCE="+str(EVID),flush=True)
    print("REA_VENDOR_MATRIX_OUTCOME="+summary["outcome"],flush=True)
    if failures or real_fails:sys.exit(35)

if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print("REA_VENDOR_MATRIX_FATAL="+type(exc).__name__+":"+str(exc)[:220],flush=True)
        sys.exit(36)
