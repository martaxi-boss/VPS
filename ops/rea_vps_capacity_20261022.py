#!/usr/bin/env python3
"""VPS capacity audit for REA: no file writes, service changes or secret reads."""
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path

PROBE_ID = "REA_VPS_CAPACITY_READ_ONLY_20261022"

def read(path, limit=16000):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except (OSError, UnicodeError):
        return ""

def memory():
    result = {}
    for line in read("/proc/meminfo").splitlines():
        if ":" not in line: continue
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree"):
            try: result[key] = int(value.strip().split()[0]) * 1024
            except (ValueError, IndexError): pass
    return result

def cpu():
    for line in read("/proc/cpuinfo", 50000).splitlines():
        if line.lower().startswith("model name") and ":" in line:
            return line.split(":", 1)[1].strip()[:120]
    return "unknown"

def version(name, params=None):
    path = shutil.which(name)
    result = {"installed": bool(path)}
    if path and params is not None:
        try:
            p = subprocess.run([path] + params, timeout=5, capture_output=True, text=True, check=False)
            rows = (p.stdout or p.stderr).strip().splitlines()
            if rows: result["version"] = rows[0][:130]
            result["command_ok"] = p.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            result["command_ok"] = False
    return result

def tls(host):
    try:
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as layer:
                return bool(layer.version())
    except (OSError, ssl.SSLError):
        return False

def listening():
    result = {"80": None, "443": None, "8765": None}
    if not shutil.which("ss"): return result
    try:
        p = subprocess.run(["ss", "-H", "-ltn"], timeout=5, capture_output=True, text=True, check=False)
        if p.returncode: return result
        found = set()
        for line in p.stdout.splitlines():
            values = line.split()
            if len(values) >= 5:
                try: found.add(int(values[3].rsplit(":", 1)[1]))
                except (ValueError, IndexError): pass
        return {port: int(port) in found for port in result}
    except (OSError, subprocess.TimeoutExpired):
        return result

def unit_state(name):
    if not shutil.which("systemctl"): return "unavailable"
    try:
        p = subprocess.run(["systemctl", "is-active", name], timeout=5, capture_output=True, text=True, check=False)
        value = p.stdout.strip()
        return value if value in ("active","inactive","failed","activating") else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"

def main():
    disk = shutil.disk_usage("/")
    disk_stats = os.statvfs("/")
    release = {}
    for line in read("/etc/os-release", 4096).splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                release[key.lower()] = value.strip().strip('"')[:100]
    limits = {}
    for name, path in (("memory_max","/sys/fs/cgroup/memory.max"), ("cpu_max","/sys/fs/cgroup/cpu.max")):
        if read(path, 80).strip(): limits[name] = read(path,80).strip()
    candidates = {
        "node":["--version"],"npm":["--version"],"python3":["--version"],
        "java":["-version"],"javac":["-version"],"git":["--version"],
        "docker":["--version"],"curl":["--version"],"ps":["--version"],
        "unzip":None,"ghidra":None,"analyzeHeadless":None,"jadx":None,
        "apktool":None,"nginx":None,"caddy":None,
    }
    result = {
        "probe": PROBE_ID, "side_effects": False, "unix_time": int(time.time()),
        "os":release, "architecture":platform.machine(), "kernel":platform.release(),
        "logical_cpus":os.cpu_count(),
        "affinity_cpus":len(os.sched_getaffinity(0)) if hasattr(os,"sched_getaffinity") else None,
        "cpu_model":cpu(), "loadavg":list(os.getloadavg()), "cgroup":limits,
        "memory_bytes":memory(),
        "root_disk_bytes":{"total":disk.total,"used":disk.used,"free":disk.free},
        "root_inodes":{"total":disk_stats.f_files,"available":disk_stats.f_favail},
        "tools":{k:version(k,v) for k,v in candidates.items()},
        "outbound_tls443":{"npm":tls("registry.npmjs.org"),"github":tls("github.com")},
        "ports_listening":listening(),
        "services":{"nginx":unit_state("nginx"),"caddy":unit_state("caddy"),"docker":unit_state("docker")},
    }
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
