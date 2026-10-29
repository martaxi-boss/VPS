#!/usr/bin/env python3
"""REA official 6.8.0: preflight, then optional isolated supplier installation.

Entry point is GitHub Actions -> pinned SSH -> ubuntu. No new MCP or service.
Phase=preflight is strictly read only. Install phase is intentionally not yet
enabled: records precise aptitude, storage, versions and rights before writes.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

ROOT=Path("/home/ubuntu/rea-original-upstream-680")
OLD=Path("/opt/rea-reversa/rea")
NODE=Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
DIST={
"dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
"dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655"}
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/optional-free-suppliers-20261029")
os.umask(0o077)

def run(a,timeout=28):
    try:
        return subprocess.run(a,stdin=subprocess.DEVNULL,cwd=ROOT,
            timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            encoding="utf-8",errors="replace",text=True,check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(a,124,"","TIMEOUT")
    except OSError as e:
        return subprocess.CompletedProcess(a,126,"",type(e).__name__+":"+str(e)[:110])

def check(x,s):
    if not x:raise RuntimeError(s)

def verify_original():
    check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","EXPECTED_SSH_UBUNTU")
    check(ROOT.is_dir() and not ROOT.is_symlink(),"PINNED_ORIGINAL_ROOT_MISSING")
    check(NODE.is_file(),"PINNED_NODE_MISSING")
    check((ROOT/"node_modules").is_symlink(),"EXISTING_DEP_LINK_CHANGED")
    check((ROOT/"node_modules").resolve()==(OLD/"node_modules").resolve(),"EXISTING_DEPS_ORIGIN_CHANGED")
    check((ROOT/"package-lock.json").read_bytes()==(OLD/"package-lock.json").read_bytes(),"PACKAGE_LOCK_CHANGED")
    rev=run(["git","-C",str(ROOT),"rev-parse","HEAD"],12)
    check(rev.returncode==0 and rev.stdout.strip()==REV,"ORIGINAL_SOURCE_COMMIT_CHANGED")
    for path,want in DIST.items():
        f=ROOT/path
        check(f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==want,"ORIGINAL_COMPILED_DIGEST_CHANGED")
    check(EVID.parent.is_dir(),"EVIDENCE_PARENT_UNAVAILABLE")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    print("REA_OPT_SOURCE_PIN=PASS",flush=True)
    print("REA_OPT_TRANSPORT=GITHUB_ACTIONS_PINNED_SSH_UBUNTU_CLI",flush=True)
    print("REA_OPT_MCP_USED=NO",flush=True)

def simple(a,limit=500,timeout=15):
    p=run(a,timeout)
    return {"rc":p.returncode,"out":p.stdout.strip()[:limit],"err":p.stderr.strip()[:250]}

def preflight():
    verify_original()
    pre={}
    pre["system"]={
        "os":simple(["lsb_release","-ds"]),
        "arch":simple(["dpkg","--print-architecture"]),
        "disk_home":simple(["df","-Pk","/home/ubuntu"]),
        "disk_opt":simple(["df","-Pk","/opt/rea-reversa"]),
        "mem":simple(["free","-m"]),
        "sudo_n":simple(["sudo","-n","/usr/bin/id","-u"],timeout=9)
    }
    pre["runtime"]={
        "python3":simple(["python3","--version"]),
        "gdb":simple(["/usr/bin/gdb","--version"]),
        "gdb_python":simple(["/usr/bin/gdb","-nx","--batch","-ex",
                "python import sysconfig;print(sysconfig.get_config_var('VERSION'))"],timeout=15),
        "dotnet":simple(["dotnet","--list-sdks"]) if shutil.which("dotnet") else None,
        "uv":simple(["uv","--version"]) if shutil.which("uv") else None,
        "pipx":simple(["pipx","--version"]) if shutil.which("pipx") else None,
        "python_venv":simple(["python3","-c","import venv;print('VENV_MODULE_PRESENT')"]),
        "python_ensurepip":simple(["python3","-c","import ensurepip;print(ensurepip.version())"])
    }
    pre["apt"]={
        "dotnet_sdk_10":simple(["apt-cache","policy","dotnet-sdk-10.0"],limit=1100),
        "dotnet_runtime_10":simple(["apt-cache","policy","dotnet-runtime-10.0"],limit=1100),
        "uv_package":simple(["apt-cache","policy","uv"],limit=1100),
        "python3_venv":simple(["apt-cache","policy","python3-venv"],limit=1100),
        "dotnet_sdk_10_simulation":simple(["apt-get","-s","-o","Debug::NoLocking=1",
         "install","--no-install-recommends","--no-remove","--no-upgrade","dotnet-sdk-10.0"],limit=2400,timeout=40),
    }
    paths={
      "ilspycmd_existing_user":Path("/home/ubuntu/.dotnet/tools/ilspycmd"),
      "ilspycmd_existing_scoped":Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd"),
      "pwndbg_gdbinit_source":Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/gdbinit.py"),
      "pwndbg_gdbinit_uv":Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/share/pwndbg/gdbinit.py"),
      "pwn_debug_old_source":Path("/opt/pwndbg/gdbinit.py"),
    }
    pre["preexisting"]={k:{"file":v.is_file(),"accessible":os.access(v,os.R_OK)} for k,v in paths.items()}
    for k,path in (("ssh_user","/home/ubuntu"),("evidence","/home/ubuntu/rea-original-upstream-680-evidence")):
        pre["preexisting"][k]={"writable":os.access(path,os.W_OK)}
    (EVID/"preflight.json").write_text(json.dumps(pre,sort_keys=True,indent=2),encoding="utf8")
    for k,v in pre["system"].items():
        if k in ("disk_home","disk_opt","mem"):continue
        print("REA_OPT_SYSTEM_"+k.upper()+"="+str(v["rc"])+";"+v["out"].replace("\n"," ")[:180],flush=True)
    for k,v in pre["runtime"].items():
        if v is None:
            print("REA_OPT_RUNTIME_"+k.upper()+"=NOT_FOUND",flush=True)
        else:
            print("REA_OPT_RUNTIME_"+k.upper()+"="+str(v["rc"])+";"+
                  v["out"].replace("\n"," ")[:220],flush=True)
    for k,v in pre["apt"].items():
        print("REA_OPT_APT_"+k.upper()+"="+str(v["rc"])+";"+
              v["out"].replace("\n"," | ")[:530]+
              ";stderr="+v["err"].replace("\n"," ")[:110],flush=True)
    for k,v in pre["preexisting"].items():
        print("REA_OPT_EXISTING_"+k.upper()+"="+json.dumps(v,separators=(",",":")),flush=True)
    for k in ("disk_home","disk_opt"):
        print("REA_OPT_"+k.upper()+"="+pre["system"][k]["out"].replace("\n"," | ")[:210],flush=True)
    print("REA_OPT_PREFLIGHT=PASS",flush=True)


def run_record(name,cmd,env=None,timeout=420):
    """A provider command with bounded stdout and private full evidence."""
    print("REA_OPT_STAGE_START="+name,flush=True)
    try:
        p=subprocess.run(cmd,stdin=subprocess.DEVNULL,cwd=ROOT,env=env,
            timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,encoding="utf-8",errors="replace",check=False)
        status=p.returncode
        out=p.stdout
        err=p.stderr
    except subprocess.TimeoutExpired as e:
        status=124
        out=(e.stdout or b"").decode("utf8",errors="replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
        err=(e.stderr or b"").decode("utf8",errors="replace") if isinstance(e.stderr,bytes) else (e.stderr or "")
        err+="\nTIMEOUT_EXCEEDED"
    except OSError as e:
        status=126
        out=""
        err=type(e).__name__+":"+str(e)[:250]
    # The install commands use explicit approved public package sources only.
    (EVID/(name+".stdout.txt")).write_text(out[:5*1024*1024],encoding="utf8",errors="replace")
    (EVID/(name+".stderr.txt")).write_text(err[:5*1024*1024],encoding="utf8",errors="replace")
    print("REA_OPT_STAGE_END="+name+";exit="+str(status),flush=True)
    return {"rc":status,"out":out,"err":err}

def disk_preflight():
    space=shutil.disk_usage("/home/ubuntu")
    check(space.free>=4*1024**3,"INSUFFICIENT_DISK_FOR_OPTIONAL_INSTALL")
    check((EVID.parent).is_dir() and os.access(EVID.parent,os.W_OK),"EVIDENCE_STORAGE_NOT_WRITABLE")
    print("REA_OPT_AVAILABLE_GIB="+str(round(space.free/1024**3,1)),flush=True)

def tool_env():
    home=EVID/"dotnet-cli-home"
    home.mkdir(parents=True,exist_ok=True,mode=0o700)
    env=dict(os.environ)
    for key in tuple(env):
        if key.startswith("REA_") or key.startswith("NUGET_") or key in (
           "DOTNET_ROOT","DOTNET_CLI_HOME","DOTNET_TOOLS_PATH",
           "DOTNET_MULTILEVEL_LOOKUP","PLAYWRIGHT_BROWSERS_PATH",
           "GHIDRA_INSTALL_DIR","JAVA_HOME","HOPPER_LAUNCHER_PATH"):
            env.pop(key,None)
    env.update({
      "DOTNET_CLI_HOME":str(home),
      "DOTNET_CLI_TELEMETRY_OPTOUT":"1",
      "DOTNET_SKIP_FIRST_TIME_EXPERIENCE":"1",
      "DOTNET_NOLOGO":"1",
      "NUGET_PACKAGES":str(EVID/"nuget-packages"),
      "HOME":str(Path("/home/ubuntu")),
      "CI":"1"})
    return env

def install_dotnet_ilspy():
    verify_original()
    disk_preflight()
    arch=run(["dpkg","--print-architecture"])
    check(arch.returncode==0 and arch.stdout.strip()=="amd64","UBUNTU_AMD64_REQUIRED")
    pkg="dotnet-sdk-10.0"
    sdk=Path("/usr/bin/dotnet")
    # Install only the official Ubuntu 24.04 packages; no third-party apt feed,
    # no removals or upgrades, and no install if already present.
    if not sdk.is_file():
        sudo=run(["sudo","-n","/usr/bin/id","-u"],timeout=10)
        check(sudo.returncode==0 and sudo.stdout.strip()=="0","ROOT_AUTHORIZATION_NOT_AVAILABLE")
        update=run_record("apt-update",["sudo","-n","/usr/bin/apt-get","update","-qq"],timeout=210)
        check(update["rc"]==0,"UBUNTU_APT_INDEX_UPDATE_FAILED")
        simulation=run_record("apt-dotnet-simulation",["/usr/bin/apt-get","-s","-o",
           "Debug::NoLocking=1","install","--no-install-recommends","--no-remove",
           "--no-upgrade",pkg],timeout=60)
        check(simulation["rc"]==0,"DOTNET_APT_SIMULATION_FAILED")
        lines=simulation["out"].splitlines()
        check(not any(row.startswith(("Remv ","Purg ")) for row in lines),
              "DOTNET_APT_REQUIRES_REMOVAL")
        # Ubuntu package resolver may add brand-new dependencies, but is explicitly
        # forbidden from upgrading or removing any pre-existing package.
        for row in lines:
            if row.startswith("Inst ") and " [" in row.split("(",1)[0]:
                raise RuntimeError("DOTNET_APT_ATTEMPTED_EXISTING_PACKAGE_UPGRADE")
        print("REA_OPT_APT_POLICY=NO_EXISTING_PACKAGE_UPGRADES_OR_REMOVALS",flush=True)
        real=run_record("apt-dotnet-install",["sudo","-n","/usr/bin/env",
              "DEBIAN_FRONTEND=noninteractive","NEEDRESTART_MODE=l",
              "/usr/bin/apt-get","install","-y","-qq","--no-install-recommends",
              "--no-remove","--no-upgrade",pkg],timeout=720)
        check(real["rc"]==0,"OFFICIAL_UBUNTU_DOTNET_SDK_INSTALL_FAILED")
    else:
        print("REA_OPT_DOTNET_SDK_ALREADY_PRESENT=YES",flush=True)
    check(sdk.is_file() and os.access(sdk,os.X_OK),"DOTNET_SDK_NOT_ACCESSIBLE")
    e=tool_env()
    versions=run_record("dotnet-list-sdks",[str(sdk),"--list-sdks"],e,timeout=50)
    check(versions["rc"]==0 and any(v.strip().startswith("10.0.") for v in versions["out"].splitlines()),
          "DOTNET_SDK_10_NOT_READY")
    print("REA_OPT_DOTNET_10=PASS",flush=True)
    target=Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0")
    cli=target/"ilspycmd"
    desired="11.2.0.10050"
    if cli.is_file() and os.access(cli,os.X_OK):
        ver=run_record("ilspy-existing-version",[str(cli),"--version"],e,timeout=30)
        check(ver["rc"]==0 and desired in ver["out"]+ver["err"],"EXISTING_ILSPY_VERSION_CONFLICT")
        print("REA_OPT_ILSPY_ALREADY_INSTALLED=YES",flush=True)
    else:
        check(not target.exists() or (target.is_dir() and not any(target.iterdir())),
              "ILSPY_TOOL_DIR_ALREADY_NONEMPTY_CANNOT_OVERWRITE")
        target.parent.mkdir(parents=True,exist_ok=True)
        # NuGet official signed client package pinned; never a global dotnet
        # tool install and never touches another project or old REA source.
        r=run_record("ilspy-tool-install",[str(sdk),"tool","install",
             "--tool-path",str(target),"--version",desired,
             "--source","https://api.nuget.org/v3/index.json","ilspycmd"],e,timeout=500)
        check(r["rc"]==0,"PINNED_ILSPYCMD_NUGET_INSTALL_FAILED")
    check(cli.is_file() and os.access(cli,os.X_OK),"ILSPY_EXECUTABLE_MISSING")
    r=run_record("ilspy-version",[str(cli),"--version"],e,timeout=40)
    check(r["rc"]==0 and desired in r["out"]+r["err"],"ILSPY_PINNED_VERSION_MISMATCH")
    print("REA_OPT_ILSPYCMD_VERSION="+desired,flush=True)
    # This completely local test builds an inert C# library in the test-only
    # directory and checks that ILSpy recovers the exact answer from its IL.
    project=EVID/"ilspy-controlled-probe"
    project.mkdir(exist_ok=True,mode=0o700)
    empty=EVID/"offline-nuget-source"
    empty.mkdir(exist_ok=True,mode=0o700)
    proj=project/"REAIlspyProbe.csproj"
    cs=project/"Verification.cs"
    proj.write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'+
        '<TargetFramework>net10.0</TargetFramework>'+
        '<AssemblyName>REAIlspyProbe</AssemblyName>'+
        '<EnableDefaultCompileItems>true</EnableDefaultCompileItems>'+
        '</PropertyGroup></Project>',encoding="utf8")
    cs.write_text('namespace REAControlledFixture; public static class Verification { public static int Answer() => 42; }',encoding="utf8")
    restore=run_record("ilspy-probe-restore",[str(sdk),"restore",
                    str(proj),"--source",str(empty),"--ignore-failed-sources"],e,timeout=150)
    check(restore["rc"]==0,"DOTNET_OFFLINE_TEST_PROJECT_RESTORE_FAILED")
    build=run_record("ilspy-probe-build",[str(sdk),"build",str(proj),
             "-c","Release","--no-restore","--nologo"],e,timeout=150)
    check(build["rc"]==0,"DOTNET_INERT_TEST_ASSEMBLY_BUILD_FAILED")
    assembly=project/"bin/Release/net10.0/REAIlspyProbe.dll"
    check(assembly.is_file(),"DOTNET_INERT_ASSEMBLY_NOT_FOUND")
    decompile=run_record("ilspy-real-decompile",[str(cli),"-t",
             "REAControlledFixture.Verification",str(assembly)],e,timeout=100)
    check(decompile["rc"]==0 and "Answer()" in decompile["out"] and
          "42" in decompile["out"],"ILSPY_REAL_DECOMPILATION_NOT_VERIFIED")
    print("REA_OPT_ILSPY_REAL_DECOMPILE=PASS",flush=True)
    # Baseline official REA already includes a managed metadata parser.
    original_e=e.copy()
    original_e["PATH"]=str(NODE.parent)+":"+original_e.get("PATH","")
    original_e["REA_ILSPY_CMD_PATH"]=str(cli)
    # This environment affects only this invocation; no persistent changes.
    official=run_record("rea-managed-original-cli",
        [str(NODE),"scripts/rea.mjs","inspect-managed-artifact",
         str(assembly),"--json"],original_e,timeout=100)
    try:
        j=json.loads(official["out"])
        if isinstance(j,dict) and isinstance(j.get("result"),dict):j=j["result"]
        normalized=j.get("normalized_result",{}) if isinstance(j,dict) else {}
    except (ValueError,TypeError):
        normalized={}
    check(official["rc"]==0 and isinstance(normalized,dict)
          and bool(normalized),"ORIGINAL_REA_MANAGED_INSPECTION_FAILED")
    print("REA_OPT_OFFICIAL_REA_MANAGED_INSPECTION=PASS",flush=True)
    info={"dotnet_sdk":versions["out"].strip().splitlines(),
          "ilspy_version":desired,
          "ilspy_path":str(cli),
          "ilspy_decoded_controlled_assembly_sha256":hashlib.sha256(assembly.read_bytes()).hexdigest(),
          "rea_official_managed_inspection":"PASS",
          "dotnet_install_scope":"official Ubuntu dotnet-sdk-10.0 only",
          "ilspy_install_scope":"user-owned isolated tool path",
          "new_mcp":0,"changes_to_original_rea":0,"service_changes":0,
          "status":"PASS"}
    (EVID/"ilspy-install-result.json").write_text(json.dumps(info,sort_keys=True,indent=2),encoding="utf8")
    print("REA_OPT_DOTNET_ILSPY_STATUS=PASS",flush=True)

if __name__=="__main__":
    try:
        if len(sys.argv)==1:
            preflight()
        elif len(sys.argv)==2 and sys.argv[1]=="install-ilspy":
            install_dotnet_ilspy()
        else:
            raise RuntimeError("INVALID_PHASE")
    except Exception as exc:
        print("REA_OPT_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
