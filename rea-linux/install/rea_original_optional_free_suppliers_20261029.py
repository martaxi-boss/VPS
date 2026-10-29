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


def install_pwndbg():
    """Install only isolated Python venvs, do not change system GDB or gdbinit."""
    verify_original()
    disk_preflight()
    ready=EVID/"ilspy-install-result.json"
    check(ready.is_file(),"FIRST_ILSPY_PHASE_NOT_COMPLETED")
    installed=json.loads(ready.read_text(encoding="utf8"))
    check(installed.get("status")=="PASS","FIRST_ILSPY_PHASE_NOT_VERIFIED")
    gdb=Path("/usr/bin/gdb")
    check(gdb.is_file(),"EXISTING_GDB_MISSING")
    res=run([str(gdb),"-nx","--batch","-ex",
               "python import sysconfig;print(sysconfig.get_config_var('VERSION'))"],timeout=18)
    check(res.returncode==0 and res.stdout.strip()=="3.12",
          "GDB_PYTHON_NOT_SYSTEM_3_12")
    source_sha="55596aa676a2756efb8d67034f31675170eabe48"
    version="2026.09.15"
    uv_version="0.13.6"
    uvhome=Path("/home/ubuntu/.local/share/rea-optional-uv-0.13.6")
    uvpy=uvhome/"bin/python3"
    uv=uvhome/"bin/uv"
    installbase=Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15")
    toolroot=installbase/"tools"
    binroot=installbase/"bin"
    venv=toolroot/"pwndbg"
    gdbinit=venv/"share/pwndbg/gdbinit.py"
    python=venv/"bin/python"
    cache=EVID/"uv-cache"
    exclusions=EVID/"pwndbg-nonessential-exclusions.txt"
    exclusions.write_text("ziglang\ndecomp2dbg\nipython\n",encoding="utf8")
    ue=dict(os.environ)
    for key in tuple(ue):
        if key.startswith("REA_") or key.startswith("UV_") or key in (
            "VIRTUAL_ENV","PYTHONPATH","PYTHONHOME","PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL","PIP_CONFIG_FILE","GHIDRA_INSTALL_DIR",
            "JAVA_HOME","HOPPER_LAUNCHER_PATH","PLAYWRIGHT_BROWSERS_PATH"):
            ue.pop(key,None)
    ue.update({
      "HOME":"/home/ubuntu",
      "UV_TOOL_DIR":str(toolroot),
      "UV_TOOL_BIN_DIR":str(binroot),
      "UV_CACHE_DIR":str(cache),
      "UV_NO_CONFIG":"1",
      "UV_NO_PROGRESS":"1",
      "UV_NO_MANAGED_PYTHON":"1",
      "UV_PYTHON_DOWNLOADS":"never",
      "CI":"1",
      "PIP_NO_INPUT":"1",
      "PIP_DISABLE_PIP_VERSION_CHECK":"1"})
    if not uv.is_file():
        check(not uvhome.exists(),"UV_ISOLATED_DIRECTORY_EXISTS_BUT_UV_MISSING")
        uvhome.parent.mkdir(parents=True,exist_ok=True)
        r=run_record("uv-isolated-venv",["/usr/bin/python3","-m","venv",
                        str(uvhome)],timeout=65)
        check(r["rc"]==0,"ISOLATED_UV_BOOTSTRAP_VENV_FAILED")
        r=run_record("uv-pypi-pin",[str(uvpy),"-m","pip","install","--no-input",
             "--disable-pip-version-check","--no-cache-dir","--index-url",
             "https://pypi.org/simple","uv=="+uv_version],ue,timeout=260)
        check(r["rc"]==0,"PINNED_UV_INSTALL_FAILED")
    check(uv.is_file() and os.access(uv,os.X_OK),"ISOLATED_UV_MISSING")
    r=run_record("uv-version",[str(uv),"--version"],ue,timeout=30)
    check(r["rc"]==0 and (" "+uv_version) in r["out"],"ISOLATED_UV_VERSION_NOT_PINNED")
    print("REA_OPT_UV_BOOTSTRAP=PASS;version="+uv_version,flush=True)
    if not gdbinit.is_file():
        check(not venv.exists(),"PWNDBG_VENV_EXISTS_WITHOUT_GDBINIT_DO_NOT_OVERWRITE")
        installbase.mkdir(parents=True,exist_ok=True)
        source="git+https://github.com/pwndbg/pwndbg@"+source_sha
        # Git SHA pin (upstream verified 2026.09.15); no GDB/LLDB extras,
        # no package-manager writes to system, no user profile changes.
        r=run_record("pwndbg-pinned-uv-install",[
             str(uv),"tool","install","--python","/usr/bin/python3",
             "--no-managed-python","--no-python-downloads",
             "--excludes",str(exclusions),source],ue,timeout=1050)
        check(r["rc"]==0,"PINNED_PWNDBG_UV_INSTALL_FAILED")
    check(gdbinit.is_file() and python.is_file(),"PWNDBG_VENV_OR_GDBINIT_UNAVAILABLE")
    metadata=run_record("pwndbg-wheel-version",[str(python),"-c",
        "import importlib.metadata as m;print(m.version('pwndbg'))"],ue,timeout=30)
    check(metadata["rc"]==0 and version in metadata["out"],
          "PWNDBG_PACKAGE_VERSION_UNEXPECTED")
    print("REA_OPT_PWNDBG_PINNED_VERSION="+version,flush=True)
    # Validate actual Pwndbg inside a fresh GDB 15.1 process: -nx prevents
    # any inherited ~/.gdbinit; no target process is attached or modified.
    ge=ue.copy()
    ge["PWNDBG_VENV_PATH"]=str(venv)
    ge["XDG_CACHE_HOME"]=str(EVID/"gdb-cache")
    ge["XDG_CONFIG_HOME"]=str(EVID/"gdb-config")
    ge["XDG_DATA_HOME"]=str(EVID/"gdb-data")
    ge["NO_COLOR"]="1"
    ge["TERM"]="dumb"
    ge["PWNDBG_NO_UPDATE"]="1"
    ge["PATH"]=str(venv/"bin")+":"+ge.get("PATH","")
    smoke=run_record("pwndbg-real-gdb-import",[
        str(gdb),"-nx","--quiet","--batch",
        "-ex","set pagination off",
        "-ex","source "+str(gdbinit),
        "-ex","python import pwndbg; print('REA_PWNDBG_REAL_GDB_LOADED')"],ge,timeout=150)
    check(smoke["rc"]==0 and "REA_PWNDBG_REAL_GDB_LOADED" in smoke["out"] and
          not ("Traceback" in smoke["out"]+smoke["err"]),
          "PWNDBG_REAL_GDB_PLUGIN_IMPORT_FAILED")
    print("REA_OPT_PWNDBG_REAL_GDB_IMPORT=PASS",flush=True)
    # Check the same GDB import against an actual Linux ELF listing.
    native=run_record("pwndbg-native-elf-probe",[
        str(gdb),"-nx","--quiet","--batch",
        "-ex","set pagination off",
        "-ex","source "+str(gdbinit),
        "-ex","file /usr/bin/true",
        "-ex","info files"],ge,timeout=120)
    check(native["rc"]==0 and
          ("Symbols from" in native["out"] or "Local exec file" in native["out"]),
          "PWNDBG_GDB_NATIVE_ELF_PROBE_FAILED")
    print("REA_OPT_PWNDBG_NATIVE_ELF_PROBE=PASS",flush=True)
    info={"pwndbg_version":version,
          "pwndbg_source_git_sha":source_sha,
          "gdb_version":"15.1", "gdb_python_version":"3.12",
          "gdbinit":str(gdbinit),"venv":str(venv),
          "uv_bootstrap_version":uv_version,
          "user_isolated_paths_only":True,
          "no_global_gdbinit_edit":True,
          "gdb_plugin_import":"PASS",
          "native_elf_listing":"PASS",
          "rea_pwndbg_gdb":str(gdb),
          "rea_pwndbg_gdbinit":str(gdbinit),
          "rea_pwndbg_venv_path":str(venv),
          "new_mcp":0,"changes_to_original_rea":0,"service_changes":0,
          "status":"PASS"}
    (EVID/"pwndbg-install-result.json").write_text(json.dumps(info,indent=2,sort_keys=True),encoding="utf8")
    print("REA_OPT_PWNDBG_STATUS=PASS",flush=True)


def install_scoped_pwntools():
    """Install only the original REA core adapter's pinned pwntools 4.15.0.

    Keep pwndbg's own compatible 4.14.1 wheel untouched inside its separate
    private tool venv. The adapter requires the exact 4.15.0 producer version.
    """
    verify_original()
    disk_preflight()
    for receipt in ("ilspy-install-result.json","pwndbg-install-result.json"):
        p=EVID/receipt
        check(p.is_file() and json.loads(p.read_text()).get("status")=="PASS",
              "PRIOR_OPTIONAL_VENDOR_PHASE_NOT_COMPLETE:"+receipt)
    uv=Path("/home/ubuntu/.local/share/rea-optional-uv-0.13.6/bin/uv")
    check(uv.is_file() and os.access(uv,os.X_OK),"PREVIOUS_PINNED_UV_UNAVAILABLE")
    target=Path("/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0")
    python=target/"bin/python"
    version="4.15.0"
    env=dict(os.environ)
    for k in tuple(env):
        if k.startswith("UV_") or k.startswith("REA_") or k in (
             "VIRTUAL_ENV","PIP_INDEX_URL","PIP_EXTRA_INDEX_URL",
             "PYTHONHOME","PYTHONPATH","JAVA_HOME","GHIDRA_INSTALL_DIR"):
            env.pop(k,None)
    env.update({
       "HOME":"/home/ubuntu","UV_CACHE_DIR":str(EVID/"uv-cache"),
       "UV_NO_MANAGED_PYTHON":"1","UV_NO_CONFIG":"1",
       "UV_NO_PROGRESS":"1","UV_PYTHON_DOWNLOADS":"never",
       "CI":"1"})
    if not python.is_file():
        check(not target.exists(),"PWNTOOLS_SCOPED_VENV_PARTIAL_OR_UNEXPECTED")
        target.parent.mkdir(parents=True,exist_ok=True)
        z=run_record("pwntools-isolated-venv",[
           str(uv),"venv","--python","/usr/bin/python3",
           "--no-managed-python","--no-python-downloads",str(target)],env,timeout=60)
        check(z["rc"]==0,"PWNTOOLS_ISOLATED_VENV_FAILED")
    z=run_record("pwntools-existing-version",[str(python),"-I","-c",
              "import importlib.metadata as m;print(m.version('pwntools'))"],env,timeout=25)
    already=z["rc"]==0 and z["out"].strip()==version
    if not already:
        z=run_record("pwntools-pypi-4_15_0",[
            str(uv),"pip","install","--python",str(python),
            "--index-url","https://pypi.org/simple",
            "pwntools=="+version],env,timeout=340)
        check(z["rc"]==0,"PINNED_PWNTOOLS_VENV_INSTALL_FAILED")
    z=run_record("pwntools-final-version",[str(python),"-I","-c",
          "import importlib.metadata as m;print(m.version('pwntools'))"],env,timeout=25)
    check(z["rc"]==0 and z["out"].strip()==version,
          "PWNTOOLS_REQUIRED_VERSION_NOT_AVAILABLE")
    z=run_record("pwntools-real-import",[str(python),"-I","-c",
          "from pwn import context;print('PWNTOOLS_REAL_IMPORT_PASS')"],env,timeout=35)
    check(z["rc"]==0 and "PWNTOOLS_REAL_IMPORT_PASS" in z["out"],
          "PWNTOOLS_REAL_IMPORT_FAILED")
    info={"status":"PASS","version":version,"interpreter_path":str(python),
          "REA_PWNTOOLS_PYTHON":str(python),
          "pwndbg_existing_env_untouched":True,
          "modified_original":False,"changed_services":False,"new_mcp":0}
    (EVID/"pwntools-install-result.json").write_text(
          json.dumps(info,indent=2,sort_keys=True),encoding="utf8")
    print("REA_OPT_PWNTOOLS_4_15=PASS;path="+str(python),flush=True)

if __name__=="__main__":
    try:
        if len(sys.argv)==1:
            preflight()
        elif len(sys.argv)==2 and sys.argv[1]=="install-ilspy":
            install_dotnet_ilspy()
        elif len(sys.argv)==2 and sys.argv[1]=="install-pwndbg":
            install_pwndbg()
        elif len(sys.argv)==2 and sys.argv[1]=="install-pwntools":
            install_scoped_pwntools()
        else:
            raise RuntimeError("INVALID_PHASE")
    except Exception as exc:
        print("REA_OPT_FATAL="+type(exc).__name__+":"+str(exc)[:180],flush=True)
        sys.exit(44)
