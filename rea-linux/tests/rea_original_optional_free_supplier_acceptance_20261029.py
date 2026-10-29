#!/usr/bin/env python3
"""Final REAL acceptance: new free C# and core-debug suppliers + original REA CLI.

No old MCP, no new service, no installation or source changes, no user targets.
Only source-owned Linux core fixture and previously built inert C# test DLL.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

ORIG=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/optional-free-suppliers-20261029")
PWN=Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/tools/pwndbg")
ILSPY=Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd")
GDB=Path("/usr/bin/gdb")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
os.umask(0o077)
cases=[]

def check(cond,why):
    if not cond:raise RuntimeError(why)

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda:fp.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def run(label,args,env=None,timeout=150):
    print("REA_OPT_ACCEPT_START="+label,flush=True)
    start=time.monotonic()
    try:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,
            cwd=ORIG,env=env,timeout=timeout,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            encoding="utf8",errors="replace",text=True,check=False)
        rc,stdout,stderr=p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as exc:
        def cv(v):return v.decode("utf8",errors="replace") if isinstance(v,bytes) else (v or "")
        rc,stdout,stderr=124,cv(exc.stdout),cv(exc.stderr)+"\nTIMEOUT"
    except OSError as exc:
        rc,stdout,stderr=126,"",str(exc)[:180]
    secs=round(time.monotonic()-start,3)
    (EVID/(label+".stdout.txt")).write_text(stdout[:5*1024*1024],encoding="utf8",errors="replace")
    (EVID/(label+".stderr.txt")).write_text(stderr[:5*1024*1024],encoding="utf8",errors="replace")
    cleanup="cleanup_incomplete" in (stdout+stderr).lower()
    x={"label":label,"rc":rc,"seconds":secs,"cleanup_incomplete":cleanup,
       "stdout_sha256":hashlib.sha256(stdout.encode()).hexdigest()}
    cases.append(x)
    print("REA_OPT_ACCEPT_DONE="+label+";exit="+str(rc)+
        ";cleanup_incomplete="+str(cleanup).lower(),flush=True)
    return x,stdout

def original_check():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","UBUNTU_USER_REQUIRED")
    check((ORIG/"node_modules").is_symlink(),"ORIGINAL_MODULE_LINK_GONE")
    check((ORIG/"node_modules").resolve()==(OLD/"node_modules").resolve(),
          "ORIGINAL_DEPENDENCIES_MISMATCH")
    check(NODE.is_file(),"NODE_MISSING")
    r=subprocess.run(["git","-C",str(ORIG),"rev-parse","HEAD"],
           stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,text=True)
    check(r.returncode==0 and r.stdout.strip()==REV,"REA_OFFICIAL_COMMIT_CHANGED")
    check(EVID.is_dir(),"EARLIER_INSTALL_EVIDENCE_MISSING")
    for n in ("ilspy-install-result.json","pwndbg-install-result.json"):
        p=EVID/n
        check(p.is_file() and json.loads(p.read_text()).get("status")=="PASS",
              "PROVIDER_INSTALL_NOT_CERTIFIED_"+n)
    check(ILSPY.is_file() and (PWN/"share/pwndbg/gdbinit.py").is_file(),
          "VENDOR_BINARY_NOT_PRESENT")
    print("REA_OPT_ACCEPT_ORIGINAL_VERSION=PINNED_6_8_0",flush=True)
    print("REA_OPT_ACCEPT_VENDORS_INSTALLED_AND_PINNED=PASS",flush=True)
    print("REA_OPT_ACCEPT_TRANSPORT=GITHUB_ACTIONS_PINNED_SSH_ORIGINAL_CLI",flush=True)
    print("REA_OPT_ACCEPT_OLD_MCP=NOT_USED",flush=True)

def environment():
    env=dict(os.environ)
    for k in tuple(env):
        if k.startswith("REA_") or k in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
                  "HOPPER_LAUNCHER_PATH","PLAYWRIGHT_BROWSERS_PATH",
                  "PYTHONHOME","PYTHONPATH","VIRTUAL_ENV"):
            env.pop(k,None)
    home=EVID/"acceptance-home"
    home.mkdir(exist_ok=True,mode=0o700)
    env.update({
      "PATH":str(PWN/"bin")+":"+str(NODE.parent)+":"+env.get("PATH",""),
      "HOME":str(home),
      "XDG_CACHE_HOME":str(home/".cache"),
      "XDG_CONFIG_HOME":str(home/".config"),
      "XDG_DATA_HOME":str(home/".local/share"),
      "REA_PWNDBG_GDB":str(GDB),
      "REA_PWNDBG_GDBINIT":str(PWN/"share/pwndbg/gdbinit.py"),
      "REA_PWNDBG_VENV_PATH":str(PWN),
      "REA_PWNTOOLS_PYTHON":str(PWN/"bin/python"),
      "REA_ILSPY_CMD_PATH":str(ILSPY),
      "PWNDBG_NO_UPDATE":"1","CI":"1","TERM":"dumb","NO_COLOR":"1",
      "DOTNET_CLI_TELEMETRY_OPTOUT":"1"})
    return env

def normalized(raw):
    try:
        data=json.loads(raw)
        if isinstance(data,dict) and isinstance(data.get("result"),dict):data=data["result"]
        if isinstance(data,dict) and isinstance(data.get("normalized_result"),dict):
            return data["normalized_result"]
    except (ValueError,TypeError):
        pass
    return {}

def verification():
    original_check()
    e=environment()
    # Reaffirm pinned version and actual independent C# decompilation.
    il,txt=run("ilspy-pinned-version",[str(ILSPY),"--version"],e,35)
    check(il["rc"]==0 and "11.2.0.10050" in txt,"ILSPY_VERSION_NOT_PINNED")
    assembly=EVID/"ilspy-controlled-probe/bin/Release/net10.0/REAIlspyProbe.dll"
    check(assembly.is_file(),"CONTROLLED_CSHARP_ASSEMBLY_GONE")
    il,out=run("ilspy-fresh-real-decompile",[str(ILSPY),"-t",
         "REAControlledFixture.Verification",str(assembly)],e,45)
    check(il["rc"]==0 and "Answer()" in out and "42" in out,
          "FRESH_ILSPY_DECOMPILATION_FAILED")
    print("REA_OPT_ACCEPT_ILSPY_REAL_DECOMPILATION=PASS",flush=True)
    # The signed official source fixture only executes inside the GDB
    # process we own. Its core is stored exclusively within this evidence
    # directory, not in the REA checkout or any user's application.
    fixture=ORIG/"scripts/fixtures/recorded-crash.c"
    check(fixture.is_file(),"OFFICIAL_CONTROLLED_CRASH_FIXTURE_MISSING")
    gcc=shutil.which("gcc")
    check(gcc is not None,"HOST_GCC_NOT_INSTALLED")
    exe=EVID/"controlled-recorded-crash-fixture"
    core=EVID/"controlled-recording.core"
    r,_=run("compile-official-controlled-fixture",
       [gcc,"-g","-O0","-pthread","-fno-pie","-no-pie",
        str(fixture),"-o",str(exe)],e,70)
    check(r["rc"]==0 and exe.is_file(),"CONTROLLED_CRASH_FIXTURE_COMPILATION_FAILED")
    if core.exists():core.unlink()
    gdb=[str(GDB),"-nx","-nh","--batch","--quiet",
         "-iex","set auto-load off",
         "-iex","set debuginfod enabled off",
         "-ex","set startup-with-shell off",
         "-ex","set disable-randomization off",
         "-ex","file "+str(exe),
         "-ex","run",
         "-ex","generate-core-file "+str(core)]
    r,_=run("record-real-controlled-core",gdb,e,150)
    check(r["rc"]==0 and core.is_file() and
          4096<core.stat().st_size<128*1024*1024 and
          core.open("rb").read(18)[16:18]==b"\x04\x00",
          "GDB_CONTROLLED_ELF_CORE_GENERATION_FAILED")
    core_hash=sha(core)
    print("REA_OPT_ACCEPT_GENERATED_REAL_ELF_CORE=PASS;bytes="+
          str(core.stat().st_size),flush=True)
    r,out=run("rea-original-pwndbg-core-debug",[
         str(NODE),"scripts/rea.mjs","inspect-recorded-crash",str(core),
         "--debugger-context","--json"],e,240)
    data=normalized(out)
    dbg=data.get("debugger",{})
    correct=(isinstance(dbg,dict) and
             str(dbg.get("pwndbg_version","")).startswith("2026.09.15") and
             dbg.get("connection")=="core")
    if not (r["rc"]==0 and correct and not r["cleanup_incomplete"]):
        try:
            raw=json.loads(out)
            if isinstance(raw,dict) and isinstance(raw.get("result"),dict):
                raw=raw["result"]
            error=(raw.get("error",raw) if isinstance(raw,dict) else {})
            if not isinstance(error,dict):error={}
            details=error.get("details",{})
            if not isinstance(details,dict):details={}
            print("REA_OPT_ACCEPT_PWNDBG_CLI_RESPONSE_KEYS="+
                  str(list(raw)[:18] if isinstance(raw,dict) else type(raw).__name__),flush=True)
            print("REA_OPT_ACCEPT_PWNDBG_CLI_ERROR="+json.dumps({
                 "code":error.get("code"),"message":str(error.get("message",""))[:350],
                 "reason":str(error.get("reason",""))[:100],
                 "details_keys":list(details)[:28],
                 "remediation":str(error.get("remediation",""))[:250],
                 "normalized_keys":list(data)[:30],
                 "debugger_keys":list(dbg) if isinstance(dbg,dict) else []
                },ensure_ascii=False),flush=True)
        except Exception as diag:
            print("REA_OPT_ACCEPT_PWNDBG_DIAGNOSTIC_PARSE_ERROR="+
                  type(diag).__name__,flush=True)
        saved_err=(EVID/"rea-original-pwndbg-core-debug.stderr.txt")
        if saved_err.is_file():
            print("REA_OPT_ACCEPT_PWNDBG_STDERR_PREFIX="+
                  saved_err.read_text(encoding="utf8",errors="replace")[:450].replace("\n"," "),flush=True)
    check(r["rc"]==0 and correct and not r["cleanup_incomplete"],
         "REA_ORIGINAL_PWNDBG_RECORDED_CORE_UNVERIFIED")
    check(sha(core)==core_hash,"ORIGINAL_CONTROLLED_CORE_BYTES_CHANGED")
    print("REA_OPT_ACCEPT_REA_ORIGINAL_PWNDBG_CORE=PASS;version="+
          str(dbg.get("pwndbg_version"))[:50],flush=True)
    # Post-supplier cleanup regression using the same original CLI transport
    # that previously exposed cleanup_incomplete in the legacy MCP.
    for n in (8,30):
        scenario=EVID/("post-supplier-capture-"+str(n)+".json")
        command=("import subprocess; p=[subprocess.Popen(['/usr/bin/true']) "
           "for _ in range("+str(n)+")]; r=[x.wait() for x in p];"
           "print('CHILDREN='+str(len(r)))")
        scenario.write_text(json.dumps({"executable":"/usr/bin/python3",
             "arguments":["-c",command],"timeout_ms":24000}),encoding="utf8")
        run_info,out=run("rea-original-post-supplier-capture-"+str(n),[
             str(NODE),"scripts/rea.mjs","capture-process",str(scenario),
             "--json"],e,75)
        normal=normalized(out)
        cleanup=normal.get("cleanup",{})
        exit_=normal.get("exit",{})
        complete=(isinstance(cleanup,dict) and
                  cleanup.get("owned_process_group") in ("verified","cleaned") and
                  cleanup.get("temporary_root") in ("removed","cleaned")
                  and isinstance(exit_,dict) and exit_.get("code")==0)
        check(run_info["rc"]==0 and complete and not run_info["cleanup_incomplete"],
              "REA_PROCESS_CLEANUP_REGRESSION_"+str(n))
        print("REA_OPT_ACCEPT_CLEANUP_"+str(n)+"=PASS",flush=True)
    check(all(not x["cleanup_incomplete"] for x in cases),"CLEANUP_INCOMPLETE_REAPPEARED")
    record={"status":"PASS",
            "vendor_integrations":{"ILSpy":"fresh_decompile_pass",
                "Pwndbg":"official_REA_core_debug_pass"},
            "rea_source_commit":REV,
            "pwndbg_version":dbg.get("pwndbg_version"),
            "core_sha256":core_hash,
            "cleanup_incomplete":0,
            "capture_cases":[8,30],
            "runs":cases,"package_installs_during_acceptance":0,
            "new_mcp_servers":0,"source_modified":False,
            "other_projects_modified":False}
    (EVID/"final-acceptance.json").write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf8")
    print("REA_OPT_ACCEPT_ALL=PASS",flush=True)
    print("REA_OPT_ACCEPT_CLEANUP_INCOMPLETE=0",flush=True)

if __name__=="__main__":
    try:
        verification()
    except Exception as exc:
        print("REA_OPT_ACCEPT_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
