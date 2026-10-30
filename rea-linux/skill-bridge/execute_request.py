#!/usr/bin/env python3
"""Bounded read-only bridge: ChatGPT Skill -> GitHub Actions -> original REA CLI.
No arbitrary paths, shell commands, installs, services, device access or MCP.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import tempfile
import time

PIN = "160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT = Path("/home/ubuntu/rea-original-upstream-680")
OLD = Path("/opt/rea-reversa/rea")
NODE = Path("/home/ubuntu/rea-final-runtime/vendors/providers/node-v24.22.1/bin/node")
DIGESTS = {
    "dist/process/ProcessOwnership.js": "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
    "dist/process/ProcessOwnershipObservation.js": "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
PROGRAMS = {
    "node": NODE,
    "java21": Path("/home/ubuntu/rea-final-runtime/vendors/tools/jdk-21/bin/java"),
    "ghidra": Path("/home/ubuntu/rea-final-runtime/vendors/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"),
    "jadx": Path("/home/ubuntu/rea-final-runtime/vendors/tools/jadx-headless-mcp-0.7.1-all.jar"),
    "unblob": Path("/home/ubuntu/rea-final-runtime/bin/unblob"),
    "binwalk": Path("/home/ubuntu/rea-final-runtime/vendors/providers/binwalk-3.1.0/bin/binwalk"),
    "apktool": Path("/usr/bin/apktool"),
    "gdb": Path("/usr/bin/gdb"),
    "rizin": Path("/home/ubuntu/rea-final-runtime/vendors/providers/rizin-v0.9.1/bin/rizin"),
    "kuna": Path("/home/ubuntu/rea-final-runtime/vendors/providers/kuna-v1.833/bin/kuna"),
    "wakaru": Path("/home/ubuntu/rea-final-runtime/vendors/providers/wakaru-1.14.0/bin/wakaru"),
    "mitmdump": Path("/home/ubuntu/rea-final-runtime/vendors/providers/mitmproxy-12.2.3/bin/mitmdump"),
    "dotnet": Path("/usr/bin/dotnet"),
    "ilspy": Path("/home/ubuntu/rea-final-runtime/optional/rea-optional-ilspycmd-11.2.0/ilspycmd"),
    "pwndbg_gdbinit": Path("/home/ubuntu/rea-final-runtime/optional/rea-optional-pwndbg-2026.09.15/tools/pwndbg/share/pwndbg/gdbinit.py"),
    "pwntools": Path("/home/ubuntu/rea-final-runtime/optional/rea-optional-pwntools-4.15.0/bin/python"),
    "cutter": Path("/home/ubuntu/rea-final-runtime/vendors/providers/cutter-2.5.0/bin/Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage"),
    "chromium": Path("/home/ubuntu/rea-final-runtime/vendors/providers/chromium-playwright-1.58.2/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell"),
    "adb": Path("/usr/bin/adb"),
    "tshark": Path("/usr/bin/tshark"),
    "sigrok": Path("/usr/bin/sigrok-cli"),
    "ffmpeg": Path("/usr/bin/ffmpeg"),
    "wasm2wat": Path("/home/ubuntu/rea-final-runtime/vendors/providers/wabt-1.0.42/bin/wasm2wat"),
    "7z": Path("/usr/bin/7z"),
}

def validate(raw):
    if len(raw) > 2500:
        raise ValueError("TOO_LARGE")
    value = json.loads(raw)
    required = {"schema_version", "project", "engine_commit", "request_id", "operation"}
    if isinstance(value, dict) and value.get("operation") == "analyze_project_javascript":
        required |= {"source_repo", "revision", "javascript_dir", "source_paths"}
    if isinstance(value, dict) and value.get("operation") in ("mcp_describe", "mcp_call"):
        required.add("tool_name")
        if value["operation"] == "mcp_call":
            required.add("arguments")
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("SCHEMA_DENIED")
    if value["schema_version"] != 1 or value["project"] != "engenharia-reversa-final" or value["engine_commit"] != PIN:
        raise ValueError("PROJECT_DENIED")
    if not isinstance(value["request_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", value["request_id"]):
        raise ValueError("REQUEST_ID_DENIED")
    if value["operation"] not in ("health", "providers", "inspect_elf", "apk_demo", "isolation_audit", "environment_audit", "provider_diagnostics", "strict_separation_audit", "optional_source_symlinks", "hygiene_inventory", "analyze_project_javascript", "mcp_catalog", "mcp_describe", "mcp_call"):
        raise ValueError("OPERATION_DENIED")
    if value["operation"] in ("mcp_describe", "mcp_call"):
        name = value["tool_name"]
        if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_]{2,90}", name) is None:
            raise ValueError("TOOL_NAME_DENIED")
        if value["operation"] == "mcp_call":
            args = value["arguments"]
            if not isinstance(args, dict) or len(json.dumps(args)) > 1400:
                raise ValueError("TOOL_ARGUMENTS_DENIED")
            # Fail closed on host paths or shell/process directives from a request.
            for key, entry in args.items():
                if not isinstance(key, str) or key.startswith("__"):
                    raise ValueError("TOOL_ARGUMENT_KEY_DENIED")
    if value["operation"] == "analyze_project_javascript":
        if not isinstance(value["source_repo"], str) or re.fullmatch(r"martaxi-boss/[A-Za-z0-9_-]{1,65}", value["source_repo"]) is None:
            raise ValueError("SOURCE_REPO_DENIED")
        if not isinstance(value["revision"], str) or re.fullmatch(r"[0-9a-f]{40}", value["revision"]) is None:
            raise ValueError("SOURCE_REVISION_DENIED")
        def safe_path(p):
            return (isinstance(p, str) and len(p) <= 220 and not p.startswith("/")
                    and all(re.fullmatch(r"[A-Za-z0-9_.-]{1,90}", s) and s not in (".", "..")
                            for s in p.split("/")))
        if not safe_path(value["javascript_dir"]):
            raise ValueError("SOURCE_DIR_DENIED")
        sources = value["source_paths"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 5 or len(set(map(str, sources))) != len(sources):
            raise ValueError("SOURCE_FILES_DENIED")
        if not all(safe_path(s) and s.endswith((".js", ".mjs", ".cjs")) for s in sources):
            raise ValueError("SOURCE_FILENAME_DENIED")
    return value

def execute(args, env=None, timeout=50):
    start = time.monotonic()
    try:
        p = subprocess.Popen(args, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", start_new_session=True)
        try:
            stdout, stderr = p.communicate(timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            stdout, stderr = p.communicate(timeout=5)
            rc = 124
        return {"exit": rc, "seconds": round(time.monotonic()-start, 2),
            "output": stdout[:(16 * 1024 * 1024)], "error": stderr[:1000]}
    except (OSError, subprocess.TimeoutExpired) as err:
        return {"exit": 126, "seconds": round(time.monotonic()-start, 2),
            "output": "", "error": type(err).__name__}

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def engine_state():
    if pwd.getpwuid(os.geteuid()).pw_name != "ubuntu":
        return {"ready": False, "error": "WRONG_SSH_USER"}
    if not ROOT.is_dir() or ROOT.is_symlink() or not NODE.is_file():
        return {"ready": False, "error": "EXPECTED_ENGINE_OR_NODE_MISSING"}
    revision = execute(["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=10)
    try:
        package = json.loads((ROOT/"package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        package = {}
    checks = {}
    for path, expected in DIGESTS.items():
        try:
            checks[Path(path).name] = sha256(ROOT/path) == expected
        except OSError:
            checks[Path(path).name] = False
    status = {"commit_correct": revision["exit"] == 0 and revision["output"].strip() == PIN,
        "package_correct": package.get("name") == "rea-agents" and package.get("version") == "6.8.0",
        "compiled_hashes_correct": all(checks.values())}
    modules = ROOT/"node_modules"
    if modules.is_symlink():
        status["dependencies"] = ("ISOLATED_FINAL_RUNTIME" if modules.resolve(strict=False) == Path("/home/ubuntu/rea-final-runtime/node_modules") else ("SHARED_LEGACY" if modules.resolve(strict=False) == (OLD/"node_modules").resolve(strict=False) else "OTHER_SYMLINK"))
    elif modules.is_dir():
        status["dependencies"] = "LOCAL_NOT_VERIFIED"
    else:
        status["dependencies"] = "MISSING"
    status["ready"] = status["commit_correct"] and status["package_correct"] and status["compiled_hashes_correct"] and status["dependencies"] == "ISOLATED_FINAL_RUNTIME"
    return status

# Paid Hopper is not installed as a provider of this FINAL project.
# Its host-level /opt installation is unrelated and must never be reused implicitly.
def supplier_state():
    values = {}
    for name, path in PROGRAMS.items():
        exists = path.is_file()
        values[name] = {"present": exists, "usable_executable": exists and os.access(path, os.X_OK),
                        "shared_with_legacy": str(path.resolve(strict=False)).startswith("/opt/rea-reversa/"),
                        "owned_by_final": str(path.resolve(strict=False)).startswith(("/home/ubuntu/rea-final-runtime/", "/home/ubuntu/rea-original-upstream-680/")),
                        "host_os_tool": str(path.resolve(strict=False)).startswith(("/usr/", "/bin/"))}
    values["frida_node_binding"] = {"present": (ROOT/"node_modules"/"frida").exists(),
                                    "shared_with_legacy": (ROOT/"node_modules").resolve(strict=False).is_relative_to(OLD)}
    return values

def cli_summary(name, args, env):
    trial = execute([str(NODE), "scripts/rea.mjs", *args, "--json"], env, timeout=55)
    output = trial["output"]
    row = {"name": name, "exit": trial["exit"], "seconds": trial["seconds"],
           "cleanup_incomplete": "cleanup_incomplete" in (output+trial["error"]).lower()}
    try:
        doc = json.loads(output)
        if isinstance(doc, dict) and isinstance(doc.get("result"), dict):
            doc = doc["result"]
        norm = doc.get("normalized_result", doc) if isinstance(doc, dict) else doc
        row["json"] = isinstance(doc, (dict, list))
        if isinstance(norm, dict):
            row["fields"] = list(norm)[:15]
            if isinstance(norm.get("healthy"), bool):
                row["healthy"] = norm["healthy"]
            for key in ("format", "architecture", "build_id", "status"):
                if isinstance(norm.get(key), (str, int, float, bool)):
                    row[key] = norm[key]
        if isinstance(norm, list):
            row["entries"] = len(norm)
    except (ValueError, TypeError):
        row["json"] = False
    return row


def isolation_inventory():
    """Read-only facts about disk, paths and likely consumers. No content dumps."""
    import shutil
    state = {"read_only": True, "engine_path": str(ROOT)}
    disk = shutil.disk_usage(str(ROOT))
    state["disk_bytes"] = {"total": disk.total, "used": disk.used, "free": disk.free}
    nm = ROOT/"node_modules"
    state["node_modules"] = {"is_symlink": nm.is_symlink(),
       "target": str(nm.resolve(strict=False)),
       "target_exists": nm.exists(),
       "same_device_as_root": nm.exists() and nm.stat().st_dev == ROOT.stat().st_dev}
    units = {
       "engine": ROOT,
       "engine_evidence": Path("/home/ubuntu/rea-original-upstream-680-evidence"),
       "legacy_engine": OLD,
       "legacy_node_modules": OLD/"node_modules",
       "legacy_providers": Path("/opt/rea-reversa/providers"),
       "legacy_tools": Path("/opt/rea-reversa/tools"),
       "final_runtime": Path("/home/ubuntu/rea-final-runtime"),
       "final_vendor_copies": Path("/home/ubuntu/rea-final-runtime/vendors"),
       "final_unblob_wrapper": Path("/home/ubuntu/rea-final-runtime/bin/unblob"),
       "ghidra": Path("/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC"),
       "jdk21": Path("/opt/rea-reversa/tools/jdk-21"),
       "node24": Path("/opt/rea-reversa/providers/node-v24.22.1"),
       "cutter": Path("/opt/rea-reversa/providers/cutter-2.5.0"),
       "chromium": Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2"),
       "unblob": Path("/opt/rea-reversa/providers/unblob-26.6.4"),
       "binwalk": Path("/opt/rea-reversa/providers/binwalk-3.1.0"),
       "rizin": Path("/opt/rea-reversa/providers/rizin-v0.9.1"),
       "kuna": Path("/opt/rea-reversa/providers/kuna-v1.833"),
       "wakaru": Path("/opt/rea-reversa/providers/wakaru-1.14.0"),
       "mitmproxy": Path("/opt/rea-reversa/providers/mitmproxy-12.2.3"),
       "jadx": Path("/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar")
    }
    sizes = {}
    for key,path in units.items():
        if not path.exists():
            sizes[key]={"present":False}
            continue
        try:
            stat=path.stat()
            entry={"present":True,"is_symlink":path.is_symlink(),
                "owner_uid":stat.st_uid, "same_device_as_engine":stat.st_dev == ROOT.stat().st_dev}
            p=subprocess.run(["du","-s","-B1",str(path)],stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=55,check=False)
            if p.returncode==0:
                entry["allocated_bytes"]=int(p.stdout.split()[0])
            else:
                # Size-only privileged read when a service-owned cache blocks du.
                try:
                    elevated=subprocess.run(["sudo","-n","du","-s","-B1",str(path)],
                        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                        text=True,timeout=115,check=False)
                    if elevated.returncode==0:
                        entry["allocated_bytes"]=int(elevated.stdout.split()[0])
                        entry["measurement"]="sudo_read_only"
                    else:
                        entry["du_rc"]=elevated.returncode
                except (OSError,ValueError,subprocess.TimeoutExpired):
                    entry["du_rc"]=p.returncode
            sizes[key]=entry
        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            sizes[key]={"present":True,"error":type(e).__name__}
    state["units"]=sizes
    try:
        state["root_entries"]=sorted(x.name for x in ROOT.iterdir()
            if x.name in ("node_modules","package.json","package-lock.json","dist","scripts","src","_reference",".git"))
        state["legacy_entries"]=sorted(x.name for x in OLD.iterdir()
            if x.name in ("node_modules","package.json","package-lock.json","dist","scripts","src","_reference",".git"))
    except OSError:
        pass
    # Process evidence is only a hint: unreadable processes are not enumerated.
    users=[]
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():continue
        try:
            raw=(item/"cmdline").read_bytes()
            if b"/opt/rea-reversa" in raw or b"/home/ubuntu/rea-original-upstream-680" in raw:
                parts=raw.split(b"\0")
                users.append({"pid":int(item.name),
                    "binary":Path(os.fsdecode(parts[0])).name[:70],
                    "references_old":b"/opt/rea-reversa" in raw,
                    "references_old_engine":b"/opt/rea-reversa/rea/" in raw,
                    "references_old_providers":b"/opt/rea-reversa/providers/" in raw,
                    "references_old_tools":b"/opt/rea-reversa/tools/" in raw,
                    "references_final":b"/home/ubuntu/rea-original-upstream-680" in raw})
        except (OSError, UnicodeError):
            pass
        if len(users)>=45:break
    # Non-destructive access probe. No escalation is performed.
    access={}
    for key,path in units.items():
        if not path.exists():continue
        access[key]={"read":os.access(path,os.R_OK),"traverse":os.access(path,os.X_OK),
                     "list":False,"sample_bad":[]}
        if path.is_dir():
            try:
                children=list(path.iterdir())
                access[key]["list"]=True
                for p in children[:20]:
                    if not os.access(p,os.R_OK):
                        access[key]["sample_bad"].append(p.name[:70])
            except OSError:
                pass
        else:
            access[key]["list"]=None
        if "du_rc" in sizes.get(key,{}):
            access[key]["du_rc"]=sizes[key]["du_rc"]
    state["path_access"]=access
    try:
        p=subprocess.run(["sudo","-n","true"],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=7,check=False)
        state["sudo_non_interactive_available"]=(p.returncode==0)
    except (OSError,subprocess.TimeoutExpired):
        state["sudo_non_interactive_available"]=False
    for process in users:
        pid=process["pid"]
        try:
            process["cwd_is_old"]=str((Path("/proc")/str(pid)/"cwd").resolve(strict=False)).startswith("/opt/rea-reversa")
            stat_data=(Path("/proc")/str(pid)/"status").read_text(encoding="utf-8",errors="replace")
            parent=next((z.split()[1] for z in stat_data.splitlines() if z.startswith("PPid:")),None)
            process["parent_pid"]=int(parent) if parent else None
        except (OSError,ValueError):
            pass
    state["known_legacy_engine_process_count"]=sum(x.get("references_old_engine",False) for x in users)
    state["matching_processes"]=users
    state["observed_process_count"]=len(users)
    return state


def environment_audit():
    """Read-only audit against the pinned author's package and selected Linux providers.

    Presence and --version probes do NOT certify the function. No network, installs,
    service starts/stops, target file execution, arbitrary commands, or file writes.
    """
    import platform
    import shutil
    r={"read_only":True,"source_commit":PIN,"source_root":str(ROOT),
       "runtime_modules_path":str((ROOT/"node_modules").resolve(strict=False)),
       "host":{"platform":sys.platform,"arch":platform.machine(),"kernel":platform.release()},
       "package":{},"host_prerequisites":{},"programs":{},"doctor":{},
       "not_for_linux":[],"policy":{"installation_requested":False,"legacy_modified":False}}
    if Path("/etc/os-release").is_file():
        try:
            osr={}
            for ln in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                if "=" in ln:
                    k,v=ln.split("=",1)
                    if k in ("ID","VERSION_ID","PRETTY_NAME","ID_LIKE"):
                        osr[k]=v.strip().strip('"')
            r["host"]["distro"]=osr
        except OSError:
            pass
    try:
        mem=Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
        vals={}
        for line in mem:
            if line.startswith(("MemTotal:","MemAvailable:")):
                key,raw=line.split(":",1); vals[key]=int(raw.split()[0])*1024
        r["host"]["memory_bytes"]=vals
    except (OSError,ValueError):
        pass
    d=shutil.disk_usage(str(ROOT))
    r["host"]["disk_free_bytes"]=d.free
    def small(argv,timeout=11,environment=None):
        t=execute(argv,env=environment,timeout=timeout)
        out=(t["output"]+"\n"+t["error"]).strip().splitlines()
        return {"exit":t["exit"],"first_line":out[0][:170] if out else "",
                "duration_seconds":t["seconds"]}
    try:
        pkg=json.loads((ROOT/"package.json").read_text(encoding="utf8"))
        lock=json.loads((ROOT/"package-lock.json").read_text(encoding="utf8"))
        pinned=execute(["git","-C",str(ROOT),"show",PIN+":package.json"],timeout=12)
        upstream=json.loads(pinned["output"]) if pinned["exit"]==0 else {}
        lock_root=lock.get("packages",{}).get("",{})
        r["package"]["upstream_package_exact"]=pkg==upstream
        r["package"]["name"]=pkg.get("name")
        r["package"]["version"]=pkg.get("version")
        r["package"]["node_engines"]=pkg.get("engines",{}).get("node")
        r["package"]["lock_has_root_package"]=bool(lock_root)
        r["package"]["lock_root_declared_required_matches"]=lock_root.get("dependencies",{})==pkg.get("dependencies",{})
        r["package"]["lock_root_declared_optional_matches"]=lock_root.get("optionalDependencies",{})==pkg.get("optionalDependencies",{})
        root=ROOT/"node_modules"
        r["package"]["modules_root"]=str(root.resolve(strict=False))
        r["package"]["modules_present"]=root.is_dir()
        r["package"]["modules_is_symlink"]=root.is_symlink()
        installed={}
        for group,label in (("dependencies","required"),("optionalDependencies","optional"),("devDependencies","development")):
            names=pkg.get(group,{})
            if not isinstance(names,dict):names={}
            present=[]; missing=[]; mismatch=[];unreadable=[]
            for name,declared in sorted(names.items()):
                location=root/name/"package.json"
                try:
                    installed_pkg=json.loads(location.read_text(encoding="utf8"))
                    version=installed_pkg.get("version")
                    if not isinstance(version,str):unreadable.append(name);continue
                    present.append(name)
                    if version!=declared:
                        mismatch.append({"name":name,"declared":declared,"installed":version})
                    installed[name]=version
                except (OSError,ValueError,TypeError):
                    if location.exists():unreadable.append(name)
                    else:missing.append(name)
            r["package"][label]={"declared":len(names),"present":len(present),"missing":missing,
                "unreadable":unreadable,"versions_different":mismatch}
        r["package"]["optional_frida_version"]=installed.get("frida")
        # Verify checked-out source is identical to the pinned author's commit
        check=small(["git","-C",str(ROOT),"diff","--exit-code",PIN,"--","package.json","package-lock.json","scripts/rea.mjs"],timeout=10)
        r["package"]["key_source_files_unchanged"]=check["exit"]==0
        deps_check=small([str(NODE),"scripts/check-dependency-install.mjs"],timeout=30)
        r["package"]["official_dependency_check"]=deps_check
    except (OSError,ValueError,KeyError,TypeError) as err:
        r["package"]["error_type"]=type(err).__name__
    ps=shutil.which("ps")
    r["host_prerequisites"]["procps_ps"]={"present":bool(ps),
        "path":ps,"version":small([ps,"--version"],timeout=9) if ps else None}
    if ps:
        test=small([ps,"-o","pid=","-p",str(os.getpid())],timeout=9)
        r["host_prerequisites"]["procps_ps"]["ownership_flag_test_exit"]=test["exit"]
    r["host_prerequisites"]["python3"]={"path":shutil.which("python3"),
        "version":small(["python3","--version"],timeout=9)}
    for name,command in (("npm",["npm","--version"]),("git",["git","--version"]),
                          ("dpkg",["dpkg-query","--version"]),("gcc",["gcc","--version"]),
                          ("cmake",["cmake","--version"]),("xvfb",["Xvfb","-help"])):
        p=shutil.which(command[0])
        r["host_prerequisites"][name]={"present":bool(p),"path":p}
        if p and name!="xvfb":
            r["host_prerequisites"][name]["version"]=small([p,*command[1:]],timeout=9)
    r["host_prerequisites"]["graphics"]={"has_display":bool(os.environ.get("DISPLAY")),
        "has_wayland":bool(os.environ.get("WAYLAND_DISPLAY")),
        "xvfb_run_present":bool(shutil.which("xvfb-run"))}
    # More analysis tools supported by the official source, but not prerequisites for all operations.
    for name,binname in (("ida","ida"),("ida64","ida64"),("jeb","jeb"),
       ("lldb","lldb"),("strace","strace"),("ltrace","ltrace"),
       ("objdump","objdump"),("readelf","readelf"),("file","file"),
       ("gpp","g++"),("clang","clang"),("radare2","r2")):
        location=shutil.which(binname)
        r["host_prerequisites"][name]={"present":bool(location),"path":location}
    # These checks are target-free CLI versions. GUI products are only inspected for presence.
    version_argv={
       "node":["--version"],"java21":["-version"],"unblob":["--version"],
       "binwalk":["--version"],"apktool":["--version"],"gdb":["--version"],
       "rizin":["-v"],"kuna":["--version"],"wakaru":["--version"],
       "mitmdump":["--version"],"dotnet":["--version"],
       "ilspy":["--version"],"adb":["version"],"tshark":["--version"],
       "sigrok":["--version"],"ffmpeg":["-version"],
       "wasm2wat":["--version"],"chromium":["--version"],
       "pwntools":["--version"],"7z":["-version"],
    }
    no_execute={"ghidra","jadx","frida_node_binding","cutter","hopper","pwndbg_gdbinit"}
    for name,path in PROGRAMS.items():
        exists=path.is_file()
        row={"present":exists,"path":str(path),"executable":bool(exists and os.access(path,os.X_OK)),
             "old_tree":str(path).startswith("/opt/rea-reversa/")}
        if exists and name in version_argv and name not in no_execute:
            row["version_probe"]=small([str(path),*version_argv[name]],timeout=12)
        else:row["version_probe"]="NOT_RUN_FILE_OR_GUI"
        r["programs"][name]=row
    if "frida_node_binding" not in r["programs"]:
        binding=ROOT/"node_modules/frida/package.json"
        try:
            f=json.loads(binding.read_text(encoding="utf8"))
            r["programs"]["frida_node_binding"]={"present":True,"package_version":f.get("version"),
                "independent_modules":binding.resolve(strict=False).is_relative_to(Path("/home/ubuntu/rea-final-runtime/node_modules"))}
        except (OSError,ValueError):
            r["programs"]["frida_node_binding"]={"present":False}
    # Official doctor checks deep provider readiness; do not infer readiness from file existence.
    with tempfile.TemporaryDirectory(prefix="rea-original-audit-",dir="/tmp") as temp:
        e=dict(os.environ)
        for k in tuple(e):
            if k.startswith("REA_") or k in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
              "VIRTUAL_ENV","PYTHONPATH","PYTHONHOME","HOPPER_LAUNCHER_PATH"):
                e.pop(k,None)
        vendor="/home/ubuntu/rea-final-runtime/vendors"
        e.update({"HOME":temp,"TMPDIR":temp,"XDG_CONFIG_HOME":temp+"/.config",
            "XDG_CACHE_HOME":temp+"/.cache",
            "JAVA_HOME":vendor+"/tools/jdk-21",
            "GHIDRA_INSTALL_DIR":vendor+"/tools/ghidra_12.1.4_PUBLIC",
            "REA_JADX_MCP_JAR":vendor+"/tools/jadx-headless-mcp-0.7.1-all.jar",
            "REA_UNBLOB_COMMAND":"/home/ubuntu/rea-final-runtime/bin/unblob",
            "REA_BINWALK_COMMAND":vendor+"/providers/binwalk-3.1.0/bin/binwalk",
            "REA_KUNA_COMMAND":vendor+"/providers/kuna-v1.833/bin/kuna",
            "PATH":vendor+"/tools/jdk-21/bin:"+str(NODE.parent)+":"+
                  vendor+"/providers/binwalk-3.1.0/bin:"+e.get("PATH",""),
            "CI":"1"})
        def doctor(name):
            t=execute([str(NODE),"scripts/rea.mjs","doctor","--provider",name,"--json"],
                      env=e,timeout=42)
            result={"exit":t["exit"],"duration_seconds":t["seconds"],
                "cleanup_incomplete":"cleanup_incomplete" in (t["output"]+t["error"]).lower()}
            try:
                obj=json.loads(t["output"])
                norm=obj.get("normalized_result",obj) if isinstance(obj,dict) else obj
                if isinstance(norm,dict):
                    result["healthy"]=norm.get("healthy",obj.get("healthy") if isinstance(obj,dict) else None)
                    result["keys"]=list(norm)[:20]
                    for key in ("status","provider","provider_id","message","code"):
                        if isinstance(norm.get(key),(str,int,bool)):
                            result[key]=norm[key][:240] if isinstance(norm[key],str) else norm[key]
                    for prop in ("checks","providerInspections","provider_inspections"):
                        value=norm.get(prop)
                        if isinstance(value,list):
                            result[prop+"_summary"]=[{k:item[k] for k in ("name","status","healthy","id")
                                if k in item and isinstance(item[k],(str,int,bool))} for item in value[:18] if isinstance(item,dict)]
                else:result["json_type"]=type(obj).__name__
                result["json"]=True
            except ValueError:
                result["json"]=False
                result["error_first_line"]=t["error"].strip().splitlines()[0][:170] if t["error"].strip() else ""
            return result
        for provider in ("ghidra","jadx","kuna","ida","hopper"):
            r["doctor"][provider]=doctor(provider)
        # Detector supports other documented capabilities without requiring a paid provider.
        for operation,args in (("providers",["providers"]),("capabilities",["capabilities"])):
            t=execute([str(NODE),"scripts/rea.mjs",*args,"--json"],env=e,timeout=35)
            summary={"exit":t["exit"],"duration_seconds":t["seconds"],
                "cleanup_incomplete":"cleanup_incomplete" in (t["output"]+t["error"]).lower()}
            try:
                obj=json.loads(t["output"])
                norm=obj.get("normalized_result",obj) if isinstance(obj,dict) else obj
                summary["json"]=True
                if isinstance(norm,dict):
                    summary["fields"]=list(norm)[:22]
                    for key in ("healthy","status","provider_count","capability_count"):
                        if isinstance(norm.get(key),(str,bool,int)):
                            summary[key]=norm[key]
            except ValueError:summary["json"]=False
            r["doctor"][operation]=summary
    r["not_for_linux"]=[
        {"id":"Xcode/macOS-framework-runtime","reason":"macOS-only runtime not on Ubuntu"},
        {"id":"Windows-native-tools","reason":"Windows-only APIs and UI not on Ubuntu"},
        {"id":"iOS live device analysis","reason":"requires device and Apple-specific environment; not needed for server"}
    ]
    r["summary"]={
        "required_total":r["package"].get("required",{}).get("declared"),
        "required_installed":r["package"].get("required",{}).get("present"),
        "required_missing":r["package"].get("required",{}).get("missing",[]),
        "required_version_differences":r["package"].get("required",{}).get("versions_different",[]),
        "optional_missing":r["package"].get("optional",{}).get("missing",[]),
        "frida_version":r["package"].get("optional_frida_version"),
        "programs_present":sum(bool(v.get("present")) for v in r["programs"].values()),
        "programs_total":len(r["programs"]),
        "programs_in_old_tree":[n for n,v in r["programs"].items() if v.get("old_tree")]
    }
    return r


def doctor_detail_audit():
    """Precisely explain scoped official doctor's results, with no env or secrets logged."""
    r={"read_only":True,"engine_commit":PIN,"results":{}}
    root="/home/ubuntu/rea-final-runtime/vendors"
    with tempfile.TemporaryDirectory(prefix="rea-doctor-audit-",dir="/tmp") as temp:
        env=dict(os.environ)
        for k in tuple(env):
            if k.startswith("REA_") or k in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
                "VIRTUAL_ENV","PYTHONPATH","PYTHONHOME","HOPPER_LAUNCHER_PATH"):
                env.pop(k,None)
        env.update({"HOME":temp,"TMPDIR":temp,"XDG_CONFIG_HOME":temp+"/.config",
            "XDG_CACHE_HOME":temp+"/.cache","JAVA_HOME":root+"/tools/jdk-21",
            "GHIDRA_INSTALL_DIR":root+"/tools/ghidra_12.1.4_PUBLIC",
            "REA_JADX_MCP_JAR":root+"/tools/jadx-headless-mcp-0.7.1-all.jar",
            "REA_KUNA_COMMAND":root+"/providers/kuna-v1.833/bin/kuna",
            "PATH":root+"/tools/jdk-21/bin:"+str(NODE.parent)+":"+env.get("PATH",""),
            "CI":"1"})
        def compact_check(v):
            if isinstance(v,str):return v[:135]
            if not isinstance(v,dict):return str(type(v).__name__)
            keys=("name","id","provider","provider_id","status","healthy","passed",
                "ok","severity","code","reason","detail","description","message",
                "summary","available","ready","result")
            row={}
            for key in keys:
                val=v.get(key)
                if isinstance(val,(bool,int,float)):row[key]=val
                elif isinstance(val,str):row[key]=val[:200]
            if len(row)<2:
                row["keys"]=list(v)[:24]
            return row
        for name in ("hopper","ida","ghidra","jadx","kuna"):
            p=execute([str(NODE),"scripts/rea.mjs","doctor","--provider",name,"--json"],
                    env=env,timeout=55)
            row={"exit":p["exit"],"seconds":p["seconds"]}
            try:
                doc=json.loads(p["output"])
                norm=doc.get("normalized_result",doc)
                row["healthy"]=bool(norm.get("healthy",False))
                row["environment_healthy"]=norm.get("environment_healthy")
                for prop in ("scope","scope_checks","informational_checks","checks","providerInspections"):
                    value=norm.get(prop)
                    if isinstance(value,list):
                        row[prop]=[compact_check(item) for item in value[:45]]
                    elif isinstance(value,dict):
                        row[prop]={str(k)[:90]:compact_check(v) for k,v in list(value.items())[:40]}
                for prop in ("reason","message","error","code"):
                    if isinstance(norm.get(prop),str):row[prop]=norm[prop][:200]
                row["json"]=True
            except (ValueError,TypeError,AttributeError) as e:
                row["json"]=False
                row["parse_error"]=type(e).__name__
            r["results"][name]=row
    return r


def strict_separation_audit():
    """Read-only audit of dependencies on OLD and of paths outside final project."""
    import shutil
    final=Path("/home/ubuntu/rea-final-runtime")
    roots={"final_checkout":ROOT,"final_runtime":final}
    report={"read_only":True,"source_commit":PIN,
        "final_root":str(ROOT),"runtime_root":str(final),
        "node_modules_target":str((ROOT/"node_modules").resolve(strict=False)),
        "programs":{}, "file_reference_scan":{},"candidate_copies":{}}
    for name,path in PROGRAMS.items():
        real=path.resolve(strict=False)
        report["programs"][name]={
            "declared":str(path),"realpath":str(real),
            "exists":path.is_file(),
            "points_to_old":str(real).startswith("/opt/rea-reversa/"),
            "project_owned":real==ROOT or ROOT in real.parents or real==final or final in real.parents,
            "host_os_tool":str(real).startswith(("/usr/","/bin/")),
            "user_local_tool":str(real).startswith("/home/ubuntu/.local/"),
            "standalone_external":str(real).startswith("/opt/") and not str(real).startswith("/opt/rea-reversa/")}
    for label,path in roots.items():
        report["file_reference_scan"][label]={
            "present":path.is_dir(), "scanned_entries":0,"symlinks":0,
            "symlinks_to_old":0,"symlinks_to_old_samples":[],
            "old_reference_launchers":0,"old_reference_launcher_samples":[],
            "limit_reached":False}
        x=report["file_reference_scan"][label]
        if not path.is_dir(): continue
        for root,dirs,files in os.walk(path,followlinks=False):
            if label=="final_checkout":
                dirs[:]=[a for a in dirs if a not in (".git","_reference","node_modules")]
            for name in list(dirs)+files:
                p=Path(root)/name
                x["scanned_entries"]+=1
                if x["scanned_entries"]>160000:
                    x["limit_reached"]=True
                    dirs[:]=[]
                    break
                if p.is_symlink():
                    x["symlinks"]+=1
                    target=p.resolve(strict=False)
                    if str(target).startswith("/opt/rea-reversa/"):
                        x["symlinks_to_old"]+=1
                        if len(x["symlinks_to_old_samples"])<20:
                            x["symlinks_to_old_samples"].append(str(p.relative_to(path))[:160])
                if not p.is_file() or p.is_symlink(): continue
                if not (p.suffix.lower() in (".pth",".cfg",".ini",".sh",".py",".toml") or
                        name in ("unblob","binwalk","rizin","kuna","mitmdump","wakaru","java","node")):
                    continue
                try:
                    if p.stat().st_size>48*1024:continue
                    data=p.read_bytes()
                    if b"/opt/rea-reversa/" in data:
                        x["old_reference_launchers"]+=1
                        if len(x["old_reference_launcher_samples"])<24:
                            x["old_reference_launcher_samples"].append(str(p.relative_to(path))[:160])
                except OSError: pass
            if x["limit_reached"]: break
    for alias,pstr in {
        "chromium":"/opt/rea-reversa/providers/chromium-playwright-1.58.2",
        "ilspy":"/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0",
        "pwndbg":"/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15",
        "pwntools":"/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0",
        "hopper":"/opt/hopper",
        }.items():
        p=Path(pstr)
        info={"path":pstr,"exists":p.exists(),"symlink":p.is_symlink()}
        if p.exists() and not p.is_symlink():
            try:
                res=subprocess.run(["sudo","-n","du","-s","-B1",str(p)],
                  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                  stderr=subprocess.DEVNULL,text=True,timeout=95,check=False)
                info["allocated_bytes"]=int(res.stdout.split()[0]) if res.returncode==0 else None
            except (OSError,ValueError,subprocess.TimeoutExpired): pass
        report["candidate_copies"][alias]=info
    report["old_active_provider_refs"]=[k for k,v in report["programs"].items() if v["points_to_old"]]
    report["non_project_installed_providers"]=[k for k,v in report["programs"].items()
      if not v["project_owned"]]
    return report


def optional_source_symlink_audit():
    """Source link inventory, no writes and no arbitrary user paths."""
    paths={
      "chromium":Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2"),
      "ilspy":Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0"),
      "pwndbg":Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15"),
      "pwntools":Path("/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0"),
    }
    out={}
    for alias,src in paths.items():
        row={"count":0,"kinds":{},"examples":[]}
        for root,dirs,files in os.walk(src,followlinks=False):
            for name in dirs+files:
                p=Path(root)/name
                if not p.is_symlink():continue
                row["count"]+=1
                target=os.readlink(p)
                resolved=p.resolve(strict=False)
                kind=("inside_source" if resolved==src or src in resolved.parents
                       else "system" if str(resolved).startswith(("/usr/","/bin/","/lib/"))
                       else "legacy" if str(resolved).startswith("/opt/rea-reversa")
                       else "user_local_other" if str(resolved).startswith("/home/ubuntu/.local")
                       else "other_external")
                row["kinds"][kind]=row["kinds"].get(kind,0)+1
                if len(row["examples"])<25:
                    row["examples"].append({"path":str(p.relative_to(src))[:110],
                        "target":target[:180],"kind":kind,
                        "exists":resolved.exists()})
        out[alias]=row
    return {"read_only":True,"sources":out}

def hygiene_inventory():
    """Read-only inventory of superseded optional supplier copies and their consumers.

    This function never deletes, edits, loads or executes a supplier. Its output
    is bounded and names only these three explicitly project-owned locations.
    """
    import shutil
    import stat
    home = Path("/home/ubuntu/.local/share")
    private = Path("/home/ubuntu/rea-final-runtime")
    candidates = {
        "ilspy": ("rea-optional-ilspycmd-11.2.0", "rea-optional-ilspycmd-11.2.0/ilspycmd"),
        "pwndbg": ("rea-optional-pwndbg-2026.09.15", "rea-optional-pwndbg-2026.09.15/tools/pwndbg/share/pwndbg/gdbinit.py"),
        "pwntools": ("rea-optional-pwntools-4.15.0", "rea-optional-pwntools-4.15.0/bin/python"),
    }
    targets = {k: home/name for k, (name, executable) in candidates.items()}
    mount_points = []
    try:
        for ln in Path("/proc/self/mountinfo").read_text(encoding="utf8").splitlines():
            mount_points.append(ln.split()[4])
    except (OSError, UnicodeError, IndexError):
        mount_points.append("MOUNT_TABLE_UNREADABLE")
    report = {"read_only": True, "disk_before_bytes": shutil.disk_usage(str(ROOT)).free,
              "paths": {}, "private_runtime_references": {"symlinks": [], "small_launchers": []},
              "process_references": [], "unreadable_processes": 0, "other_project_temp_names": []}
    for alias, (name, executable) in candidates.items():
        source = targets[alias]
        final_file = private/"optional"/executable
        final_real = final_file.resolve(strict=False)
        row = {"source": str(source), "source_exists": source.exists(),
               "source_symlink": source.is_symlink(),
               "final_file": str(final_file), "final_file_exists": final_file.is_file(),
               "final_file_private": final_real == private or private in final_real.parents,
               "allocated_bytes": None, "source_owner_uid": None, "source_writeable": False,
               "nested_mounts": []}
        if source.exists() and not source.is_symlink():
            try:
                st = source.lstat()
                row["source_owner_uid"] = st.st_uid
                row["source_writeable"] = os.access(source, os.W_OK)
                row["source_is_directory"] = stat.S_ISDIR(st.st_mode)
                row["nested_mounts"] = [m for m in mount_points
                    if m == str(source) or m.startswith(str(source)+"/")][:12]
                p = subprocess.run(["du", "-s", "-B1", str(source)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, timeout=25, check=False)
                if p.returncode == 0:
                    row["allocated_bytes"] = int(p.stdout.split()[0])
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                row["read_error"] = type(exc).__name__
        report["paths"][alias] = row
    # Check every symlink and small launcher inside the active private runtime.
    # Do not follow symlinked directories; never open binary files.
    source_bytes = {k: str(v).encode() for k, v in targets.items()}
    count = 0
    for root, dirs, files in os.walk(private, followlinks=False):
        for name in dirs+files:
            count += 1
            path = Path(root)/name
            if path.is_symlink():
                link = str(path.resolve(strict=False))
                for alias, source in targets.items():
                    if link == str(source) or link.startswith(str(source)+"/"):
                        report["private_runtime_references"]["symlinks"].append(
                            {"supplier": alias, "path": str(path.relative_to(private))[:180]})
            if len(report["private_runtime_references"]["small_launchers"]) >= 20:
                continue
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix.lower() not in (".pth", ".ini", ".cfg", ".toml", ".sh", ".py") and name not in ("ilspycmd","pwndbg","python","python3"):
                continue
            try:
                if path.stat().st_size > 65536:
                    continue
                data = path.read_bytes()
                for alias, marker in source_bytes.items():
                    if marker in data:
                        report["private_runtime_references"]["small_launchers"].append(
                            {"supplier": alias, "path": str(path.relative_to(private))[:180]})
            except OSError:
                continue
    report["private_runtime_references"]["scanned_entries"] = count
    # Extra read-only sizing of other explicitly REA-named directories.
    report["extra_staging"] = {}
    for alias, p in {
        "uv_staging": Path("/home/ubuntu/.local/share/rea-optional-uv-0.13.6"),
        "runtime_optional": private/"optional",
        "runtime_node_modules": private/"node_modules",
        "runtime_vendors": private/"vendors",
    }.items():
        item = {"present": p.exists(), "symlink": p.is_symlink()}
        if p.exists() and not p.is_symlink():
            try:
                size = subprocess.run(["du","-s","-B1",str(p)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, timeout=35, check=False)
                if size.returncode == 0:
                    item["allocated_bytes"] = int(size.stdout.split()[0])
            except (OSError, ValueError, subprocess.TimeoutExpired):
                item["size_unverified"] = True
        report["extra_staging"][alias] = item
    # Look at process cmdlines/maps/cwd without exposing arguments or secrets.
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            raw = (p/"cmdline").read_bytes() + (p/"maps").read_bytes()[:2097152]
            cwd = str((p/"cwd").resolve(strict=False)).encode()
            raw += cwd
            for alias, marker in source_bytes.items():
                if marker in raw:
                    report["process_references"].append({"pid": int(p.name), "supplier": alias})
        except (OSError, PermissionError):
            report["unreadable_processes"] += 1
    # Discover only names, never content, for additional candidate paths.
    for directory in (home, Path("/tmp"), Path("/var/tmp")):
        try:
            for p in sorted(directory.iterdir(), key=lambda x:x.name):
                if p.name.startswith(("rea-optional-", "rea-skill-probe-", "rea-doctor-audit-")):
                    report["other_project_temp_names"].append(str(p)[:180])
                if len(report["other_project_temp_names"]) >= 75:
                    break
        except OSError:
            pass
    return report


def analyze_project_javascript(req, env):
    """One bounded, read-only source inspection by the installed author's CLI.

    Repository is pinned to a 40-hex main HEAD under the owner's GitHub
    namespace, fetched without credentials, hooks, submodules, or executing
    code from the target. No writes to other projects or the production VPS.
    This is JavaScript static analysis, not a Python/Django security audit.
    """
    import shutil
    out = {"project": req["source_repo"], "revision": req["revision"],
           "analysis": "original_author_cli_static_javascript",
           "provider_used": "REA built-in JavaScript analyzer via private Node",
           "cli_command": "analyze-javascript-application",
           "selected_sources": req["source_paths"], "status": "BLOCKED"}
    if shutil.disk_usage("/tmp").free < 750 * 1024 * 1024:
        out["reason"] = "INSUFFICIENT_TEMP_SPACE"
        return out
    with tempfile.TemporaryDirectory(prefix="rea-skill-project-js-", dir="/tmp") as temp:
        repository = Path(temp)/"repo"
        url = "https://github.com/"+req["source_repo"]+".git"
        fetch = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
             "clone", "--quiet", "--depth", "1", "--filter=blob:none",
             "--single-branch", "--branch", "main", "--no-checkout",
             "--", url, str(repository)],
            cwd=temp, env={**env, "GIT_CONFIG_NOSYSTEM":"1", "GIT_CONFIG_GLOBAL":"/dev/null",
                           "GIT_TERMINAL_PROMPT":"0", "GIT_LFS_SKIP_SMUDGE":"1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=95, check=False)
        if fetch.returncode:
            out["reason"] = "SOURCE_FETCH_FAILED"
            out["git_exit"] = fetch.returncode
            return out
        actual = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=15, check=False)
        if actual.returncode or actual.stdout.strip() != req["revision"]:
            out["reason"] = "SOURCE_REVISION_CHANGED_OR_MISMATCH"
            return out
        checkout = subprocess.run(["git", "-C", str(repository),
            "-c", "core.hooksPath=/dev/null",
            "checkout", "--quiet", "--force", "--detach", req["revision"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=55, check=False)
        if checkout.returncode:
            out["reason"] = "SOURCE_CHECKOUT_FAILED"
            return out
        parent = repository
        for segment in req["javascript_dir"].split("/"):
            parent = parent/segment
            if parent.is_symlink():
                out["reason"] = "SOURCE_SYMLINK_DIR_DENIED"
                return out
        if not parent.is_dir() or not parent.resolve(strict=True).is_relative_to(repository.resolve(strict=True)):
            out["reason"] = "SOURCE_DIRECTORY_NOT_FOUND"
            return out
        files = []
        total_bytes = 0
        for relative in req["source_paths"]:
            selected = parent
            for segment in relative.split("/"):
                selected = selected/segment
                if selected.is_symlink():
                    out["reason"] = "SOURCE_SYMLINK_FILE_DENIED"
                    return out
            if not selected.is_file() or not selected.resolve(strict=True).is_relative_to(parent.resolve(strict=True)):
                out["reason"] = "SOURCE_FILE_NOT_FOUND"
                return out
            size = selected.stat().st_size
            total_bytes += size
            if size > 1024*1024 or total_bytes > 3*1024*1024:
                out["reason"] = "SOURCE_TOO_LARGE"
                return out
            files.append({"path": relative, "size_bytes": size, "sha256": sha256(selected)})
        out["source_files"] = files
        args = [str(NODE), "scripts/rea.mjs", "analyze-javascript-application",
                str(parent), "--detail", "summary", "--evidence_output",
                str(Path(temp)/"full-evidence.json")]
        for relative in req["source_paths"]:
            args += ["--source-path", relative]
        args.append("--json")
        # A source analysis can be larger than a health call, but no code from
        # the target is launched. Captured stdout is never returned verbatim.
        try:
            trial = execute(args, env, timeout=150)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            out["reason"] = "ANALYZER_COULD_NOT_START"
            return out
        out["cli_exit"] = trial["exit"]
        out["seconds"] = trial["seconds"]
        out["cleanup_incomplete"] = "cleanup_incomplete" in (trial["output"]+trial["error"]).lower()
        if len(trial["output"]) > 12 * 1024 * 1024:
            out["reason"] = "ANALYSIS_OUTPUT_TOO_LARGE"
            return out
        try:
            doc = json.loads(trial["output"])
        except (TypeError, ValueError):
            out["reason"] = "ANALYSIS_OUTPUT_NOT_JSON"
            return out
        if not isinstance(doc, dict):
            out["reason"] = "ANALYSIS_OUTPUT_NOT_OBJECT"
            return out
        result = doc.get("result", doc)
        result = result.get("normalized_result", result) if isinstance(result, dict) else result
        out["json"] = True
        out["evidence_id"] = doc.get("evidence_id") if isinstance(doc.get("evidence_id"), str) else None
        out["result_fields"] = list(result)[:28] if isinstance(result, dict) else []
        if isinstance(result, dict) and isinstance(result.get("code"), str):
            out["diagnostic"] = {
                "code": result["code"][:80],
                "category": str(result.get("category", ""))[:60],
                "message": str(result.get("message", ""))[:500],
                "details": json.dumps(result.get("details", {}), ensure_ascii=True)[:1800]
            }
        for key in ("status", "format", "application_type"):
            if isinstance(result, dict) and isinstance(result.get(key), (str, bool, int)):
                out[key] = result[key]
        if isinstance(result, dict):
            for key in ("statistics", "coverage", "summary"):
                data = result.get(key)
                if isinstance(data, dict):
                    out[key] = {k:v for k,v in list(data.items())[:12]
                                if isinstance(v, (str,int,float,bool)) and len(str(v)) < 120}
        if trial["exit"] != 0 or out["cleanup_incomplete"]:
            out["reason"] = "CLI_ANALYSIS_FAILED"
            return out
        out["status"] = "PASS"
        return out

def original_mcp_catalog(env):
    """Read the tool contracts bundled with the pinned original author build."""
    js = ("import {TOOL_CONTRACTS} from './dist/contracts/toolContracts.js';"
          "import {MANAGED_WORKFLOW_TOOL_CONTRACTS} from "
          "'./dist/contracts/managed/managedWorkflowToolContracts.js';"
          "const all=TOOL_CONTRACTS;"
          "process.stdout.write(JSON.stringify(all.map(x=>({name:x.name,kind:x.kind,effects:x.effects}))));")
    trial = execute([str(NODE), "--input-type=module", "-e", js], env, timeout=50)
    if trial["exit"] != 0:
        return {"status":"BLOCKED", "reason":"CATALOG_LOAD_FAILED",
                "exit":trial["exit"],"error":trial["error"][:180]}
    try:
        rows = json.loads(trial["output"])
    except ValueError:
        return {"status":"BLOCKED","reason":"CATALOG_INVALID_JSON"}
    names = [x.get("name") for x in rows if isinstance(x,dict)]
    if not names or len(set(names)) != len(names):
        return {"status":"BLOCKED","reason":"CATALOG_INVALID_NAMES"}
    return {"status":"PASS","catalog_source":"original_build_contracts",
            "total":len(names),"names":sorted(names),
            "note":"Catalog discovery is not proof of execution or provider readiness"}


def run_original_mcp(req, env):
    """Use the already installed author's MCP stdio, one session per request."""
    operation = req["operation"]
    tool_name = req["tool_name"]
    arguments = req.get("arguments", {})
    js = r'''
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { TOOL_CONTRACTS } from "./dist/contracts/toolContracts.js";
const name = process.argv[1];
const mode = process.argv[2];
const args = JSON.parse(process.argv[3] || "{}");
const contract = TOOL_CONTRACTS.find(x => x.name === name);
if (!contract) {
  process.stdout.write(JSON.stringify({status:"BLOCKED",reason:"NOT_IN_ORIGINAL_CATALOG"}));
  process.exit(0);
}
const effects = contract.effects ?? {};
const disallowed = ["mutatesTarget","writesFilesystem","executesForeignCode",
                    "mutatesDevice","mayDiscardData","changesUiState"].filter(x=>effects[x]===true);
if (mode === "mcp_call" && disallowed.length) {
  process.stdout.write(JSON.stringify({status:"BLOCKED",reason:"REQUIRES_SPECIFIC_MUTATION_AUTHORIZATION",tool:name,effects:disallowed}));
  process.exit(0);
}
const transport = new StdioClientTransport({
  command:process.execPath,args:["scripts/rea.mjs","mcp"],
  cwd:process.cwd(),env:process.env,stderr:"pipe"
});
const client = new Client({name:"engenharia-reversa-final-github-bridge",version:"1.0.1"});
try {
  await client.connect(transport);
  let cursor, found;
  for (let page=0;page<10;page++) {
    const list = await client.listTools(cursor ? {cursor} : {});
    found = list.tools?.find(x => x.name === name) ?? found;
    cursor = list.nextCursor;
    if (found || !cursor) break;
  }
  if (!found) throw new Error("MCP_TOOL_NOT_ADVERTISED");
  if (mode === "mcp_describe") {
    process.stdout.write(JSON.stringify({status:"PASS",tool:name,
      description:String(found.description||"").slice(0,1000),
      input_schema:found.inputSchema,effects,kind:contract.kind}));
  } else {
    const out = await client.callTool({name,arguments:args});
    const structured = out.structuredContent;
    let data = structured?.normalized_result ?? structured ?? {};
    if (!data || typeof data !== "object") data={};
    const summary={};
    for (const key of ["scope","status","format","revision","healthy","provider","version","path"]) {
      if (["string","boolean","number"].includes(typeof data[key])) summary[key]=data[key];
    }
    for (const key of ["settings","items","records","providers","entries"]) {
      if (Array.isArray(data[key])) summary[key+"_count"]=data[key].length;
    }
    const text = out.content?.find(x=>x.type==="text")?.text??"";
    process.stdout.write(JSON.stringify({status:out.isError?"FAIL":"PASS",
      tool:name,transport:"original-mcp-stdio",isError:out.isError===true,
      evidence_id:structured?.evidence_id??null,
      result_fields:Object.keys(data).slice(0,24),
      summary,content_digest:await digest(text),
      content_length:text.length}));
  }
} catch (error) {
  process.stdout.write(JSON.stringify({status:"BLOCKED",
    reason:"ORIGINAL_MCP_CALL_FAILED",
    error:String(error?.message||error).slice(0,480),tool:name}));
} finally {
  await client.close().catch(()=>{});
}
async function digest(text) {
  const {createHash}=await import("node:crypto");
  return createHash("sha256").update(text).digest("hex");
}
'''
    trial = execute([str(NODE), "--input-type=module", "-e", js,
                    tool_name, operation, json.dumps(arguments, separators=(",",":"))],
                    env, timeout=120)
    if trial["exit"] != 0:
        return {"status":"BLOCKED","reason":"MCP_CLIENT_PROCESS_FAILED",
                "exit":trial["exit"],"stderr":trial["error"][:350]}
    try:
        doc = json.loads(trial["output"])
    except ValueError:
        return {"status":"BLOCKED","reason":"MCP_CLIENT_INVALID_RESPONSE",
                "stdout_length":len(trial["output"]),
                "stderr":trial["error"][:300]}
    doc["elapsed_seconds"] = trial["seconds"]
    return doc


def perform(req):
    result = {"bridge": "original-final-cli-v1", "request_id": req["request_id"],
              "operation": req["operation"], "engine": engine_state(), "suppliers": supplier_state()}
    if not result["engine"].get("ready"):
        result["status"] = "BLOCKED_ENGINE_INCORRECT"
        return result
    # Fail closed: never execute the FINAL motor using a provider in the old project.
    if any(details.get("shared_with_legacy") for details in result["suppliers"].values()):
        result["status"] = "BLOCKED_LEGACY_PROVIDER_REFERENCE"
        return result
    if any(str(path).startswith("/home/ubuntu/.local/share/rea-optional-")
           for path in PROGRAMS.values()):
        result["status"] = "BLOCKED_NON_PRIVATE_OPTIONAL_PROVIDER"
        return result
    if req["operation"] == "optional_source_symlinks":
        result["optional_source_symlinks"]=optional_source_symlink_audit()
        result["status"]="PASS"
        return result
    if req["operation"] == "hygiene_inventory":
        result["hygiene_inventory"] = hygiene_inventory()
        result["status"] = "PASS"
        return result
    if req["operation"] == "strict_separation_audit":
        result["strict_separation_audit"] = strict_separation_audit()
        result["status"] = "PASS"
        return result
    if req["operation"] == "provider_diagnostics":
        result["provider_diagnostics"] = doctor_detail_audit()
        result["status"] = "PASS"
        return result
    if req["operation"] == "environment_audit":
        result["environment_audit"] = environment_audit()
        result["status"] = "PASS"
        return result
    if req["operation"] == "isolation_audit":
        result["isolation_audit"] = isolation_inventory()
        result["status"] = "PASS" if result["isolation_audit"]["node_modules"]["target_exists"] else "PARTIAL"
        return result
    with tempfile.TemporaryDirectory(prefix="rea-skill-probe-", dir="/tmp") as home:
        env = dict(os.environ)
        for k in tuple(env):
            if k.startswith("REA_") or k in ("JAVA_HOME", "GHIDRA_INSTALL_DIR", "VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "HOPPER_LAUNCHER_PATH"):
                env.pop(k, None)
        env.update({"HOME": home, "TMPDIR": home,
            "XDG_CONFIG_HOME": home+"/.config", "XDG_CACHE_HOME": home+"/.cache",
            "PATH": "/home/ubuntu/rea-final-runtime/vendors/tools/jdk-21/bin:"+str(NODE.parent)+":"+"/home/ubuntu/rea-final-runtime/vendors/providers/binwalk-3.1.0/bin:"+env.get("PATH",""),
            "JAVA_HOME": "/home/ubuntu/rea-final-runtime/vendors/tools/jdk-21",
            "GHIDRA_INSTALL_DIR": "/home/ubuntu/rea-final-runtime/vendors/tools/ghidra_12.1.4_PUBLIC",
            "REA_JADX_MCP_JAR": "/home/ubuntu/rea-final-runtime/vendors/tools/jadx-headless-mcp-0.7.1-all.jar",
            "REA_UNBLOB_COMMAND": "/home/ubuntu/rea-final-runtime/bin/unblob",
            "REA_BINWALK_COMMAND": "/home/ubuntu/rea-final-runtime/vendors/providers/binwalk-3.1.0/bin/binwalk",
            "CI":"1"})
        version = execute([str(NODE), "scripts/rea.mjs", "--version"], env, timeout=25)
        result["cli_version"] = {"exit": version["exit"], "version": version["output"].strip()[:20]}
        if version["exit"] != 0 or version["output"].strip() != "6.8.0":
            result["status"] = "BLOCKED_CLI_VERSION"
            return result
        if req["operation"] == "analyze_project_javascript":
            report = analyze_project_javascript(req, env)
            result["project_analysis"] = report
            result["status"] = "PASS" if report["status"] == "PASS" else "PARTIAL"
            return result
        if req["operation"] == "mcp_catalog":
            catalog = original_mcp_catalog(env)
            result["mcp_catalog"] = catalog
            result["status"] = catalog["status"]
            return result
        tasks = []
        if req["operation"] in ("health", "providers"):
            tasks.extend([("providers", ["providers"]), ("capabilities", ["capabilities"])])
        if req["operation"] in ("health", "inspect_elf"):
            tasks.extend([("inspect_artifact", ["inspect-artifact", "/usr/bin/true"]),
                         ("inspect_elf_notes", ["inspect-elf-notes", "/usr/bin/true"])])
        if req["operation"] == "apk_demo":
            # Only use the already-tested public APK with its pinned digest.
            apk_sha = "a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686"
            candidates = (
                ROOT/"_reference/apk-integration/ApiDemos-debug.apk",
                Path("/home/ubuntu/rea-original-upstream-680-evidence/functional-suppliers-step2-20261029/ApiDemos-debug.apk"),
            )
            fixture = None
            for path in candidates:
                if path.is_file() and sha256(path) == apk_sha:
                    fixture = str(path)
                    break
            if fixture is None:
                result["status"] = "BLOCKED_VERIFIED_APK_FIXTURE_MISSING"
                return result
            result["apk_fixture_sha256_verified"] = True
            tasks.extend([
                ("inspect_android_package", ["inspect-android-package", fixture]),
                ("inspect_android_class", ["inspect-android-class", fixture, "io.appium.android.apis.ApiDemos"]),
                ("inspect_android_method", ["inspect-android-method", fixture, "io.appium.android.apis.ApiDemos", "onCreate"])
            ])
        result["tools"] = [cli_summary(name, args, env) for name,args in tasks]
        result["status"] = "PASS" if all(t["exit"] == 0 and t["json"] and not t["cleanup_incomplete"] for t in result["tools"]) else "PARTIAL"
    return result

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("--validate-request", "--base64"):
        print("REA_SKILL_BRIDGE=INVALID_USAGE")
        return 2
    try:
        if sys.argv[1] == "--validate-request":
            req = validate(Path(sys.argv[2]).read_bytes())
            print("REA_SKILL_REQUEST_VALID=PASS;request_id="+req["request_id"])
            return 0
        encoded = sys.argv[2].encode("ascii")
        if len(encoded) > 5000 or re.fullmatch(rb"[A-Za-z0-9+/=]+", encoded) is None:
            raise ValueError("INVALID_ENCODING")
        req = validate(base64.b64decode(encoded, validate=True))
        state = perform(req)
        print("REA_SKILL_BRIDGE_RESULT="+json.dumps(state, separators=(",",":"), sort_keys=True))
        return 0 if state["status"] == "PASS" else 4
    except (OSError, ValueError, RuntimeError) as err:
        print("REA_SKILL_BRIDGE_BLOCKED="+type(err).__name__+":"+str(err)[:85])
        return 3

if __name__ == "__main__":
    sys.exit(main())
