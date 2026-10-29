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
NODE = Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
DIGESTS = {
    "dist/process/ProcessOwnership.js": "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
    "dist/process/ProcessOwnershipObservation.js": "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
PROGRAMS = {
    "node": NODE,
    "java21": Path("/opt/rea-reversa/tools/jdk-21/bin/java"),
    "ghidra": Path("/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"),
    "jadx": Path("/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar"),
    "unblob": Path("/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob"),
    "binwalk": Path("/opt/rea-reversa/providers/binwalk-3.1.0/bin/binwalk"),
    "apktool": Path("/usr/bin/apktool"),
    "gdb": Path("/usr/bin/gdb"),
    "rizin": Path("/opt/rea-reversa/providers/rizin-v0.9.1/bin/rizin"),
    "kuna": Path("/opt/rea-reversa/providers/kuna-v1.833/bin/kuna"),
    "wakaru": Path("/opt/rea-reversa/providers/wakaru-1.14.0/bin/wakaru"),
    "mitmdump": Path("/opt/rea-reversa/providers/mitmproxy-12.2.3/bin/mitmdump"),
    "dotnet": Path("/usr/bin/dotnet"),
    "ilspy": Path("/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0/ilspycmd"),
    "pwndbg_gdbinit": Path("/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15/tools/pwndbg/share/pwndbg/gdbinit.py"),
    "pwntools": Path("/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0/bin/python"),
    "cutter": Path("/opt/rea-reversa/providers/cutter-2.5.0/bin/Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage"),
    "hopper": Path("/opt/hopper/bin/Hopper"),
    "chromium": Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell"),
    "adb": Path("/usr/bin/adb"),
    "tshark": Path("/usr/bin/tshark"),
    "sigrok": Path("/usr/bin/sigrok-cli"),
    "ffmpeg": Path("/usr/bin/ffmpeg"),
    "wasm2wat": Path("/opt/rea-reversa/providers/wabt-1.0.42/bin/wasm2wat"),
    "7z": Path("/usr/bin/7z"),
}

def validate(raw):
    if len(raw) > 2500:
        raise ValueError("TOO_LARGE")
    value = json.loads(raw)
    required = {"schema_version", "project", "engine_commit", "request_id", "operation"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("SCHEMA_DENIED")
    if value["schema_version"] != 1 or value["project"] != "engenharia-reversa-final" or value["engine_commit"] != PIN:
        raise ValueError("PROJECT_DENIED")
    if not isinstance(value["request_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", value["request_id"]):
        raise ValueError("REQUEST_ID_DENIED")
    if value["operation"] not in ("health", "providers", "inspect_elf", "apk_demo"):
        raise ValueError("OPERATION_DENIED")
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
            "output": stdout[:250000], "error": stderr[:1000]}
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
        status["dependencies"] = "SHARED_LEGACY" if modules.resolve(strict=False) == (OLD/"node_modules").resolve(strict=False) else "OTHER_SYMLINK"
    elif modules.is_dir():
        status["dependencies"] = "LOCAL_NOT_VERIFIED"
    else:
        status["dependencies"] = "MISSING"
    status["ready"] = status["commit_correct"] and status["package_correct"] and status["compiled_hashes_correct"]
    return status

def supplier_state():
    values = {}
    for name, path in PROGRAMS.items():
        exists = path.is_file()
        values[name] = {"present": exists, "usable_executable": exists and os.access(path, os.X_OK),
                        "shared_with_legacy": str(path).startswith("/opt/rea-reversa/")}
    values["frida_node_binding"] = {"present": (ROOT/"node_modules"/"frida").exists(),
                                    "shared_with_legacy": True}
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

def perform(req):
    result = {"bridge": "original-final-cli-v1", "request_id": req["request_id"],
              "operation": req["operation"], "engine": engine_state(), "suppliers": supplier_state()}
    if not result["engine"].get("ready"):
        result["status"] = "BLOCKED_ENGINE_INCORRECT"
        return result
    with tempfile.TemporaryDirectory(prefix="rea-skill-probe-", dir="/tmp") as home:
        env = dict(os.environ)
        for k in tuple(env):
            if k.startswith("REA_") or k in ("JAVA_HOME", "GHIDRA_INSTALL_DIR", "VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "HOPPER_LAUNCHER_PATH"):
                env.pop(k, None)
        env.update({"HOME": home, "TMPDIR": home,
            "XDG_CONFIG_HOME": home+"/.config", "XDG_CACHE_HOME": home+"/.cache",
            "PATH": "/opt/rea-reversa/tools/jdk-21/bin:"+str(NODE.parent)+":"+env.get("PATH",""),
            "JAVA_HOME": "/opt/rea-reversa/tools/jdk-21",
            "GHIDRA_INSTALL_DIR": "/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC",
            "REA_JADX_MCP_JAR": "/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar",
            "REA_UNBLOB_COMMAND": "/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob",
            "CI":"1"})
        version = execute([str(NODE), "scripts/rea.mjs", "--version"], env, timeout=25)
        result["cli_version"] = {"exit": version["exit"], "version": version["output"].strip()[:20]}
        if version["exit"] != 0 or version["output"].strip() != "6.8.0":
            result["status"] = "BLOCKED_CLI_VERSION"
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
                OLD/"_reference/apk-integration/ApiDemos-debug.apk",
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
