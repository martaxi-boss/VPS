#!/usr/bin/env python3
"""REA original 6.8.0: isolated Cutter bridge v2, Chromium policy and Hopper publisher readback.

No source modifications, no new services, no root, no sandbox weakening, no package installs.
Persistent evidence only under the private REA verification directory.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request

ROOT = Path("/home/ubuntu/rea-original-upstream-680")
EVID = Path("/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029/targeted-followup")
NODE = Path("/opt/rea-reversa/providers/node-v24.22.1/bin/node")
CUTTER = Path("/opt/rea-reversa/providers/cutter-2.5.0/bin/Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage")
BROWSER_ROOT = Path("/opt/rea-reversa/providers/chromium-playwright-1.58.2")
HOPPER = Path("/opt/hopper/bin/Hopper")
REV = "160d821ac9a0310afcb8d1fc427862dd6508add5"
FEED = "https://www.hopperapp.com/include/files-api.php?request=releases&public=true"
os.umask(0o077)
summary = {"mode": "original_cli_ssh_no_mcp", "changes_to_security_policy": 0,
           "new_packages_installed": 0, "rea_source_changed": False}

def run(argv, env=None, timeout=22):
    try:
        p = subprocess.run(argv, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           text=True, encoding="utf8", errors="replace", check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        cv = lambda x: x.decode("utf8", errors="replace") if isinstance(x, bytes) else (x or "")
        return 124, cv(e.stdout), cv(e.stderr) + "\nTIMED_OUT"
    except OSError as e:
        return 126, "", type(e).__name__ + ":" + str(e)[:180]

def cli(argv, env, name, timeout=30):
    rc, out, err = run([str(NODE), "scripts/rea.mjs", *argv, "--json"], env, timeout)
    (EVID/(name+".stdout.json")).write_text(out[:2000000])
    (EVID/(name+".stderr.log")).write_text(err[:200000])
    try:
        data=json.loads(out)
        if isinstance(data,dict) and isinstance(data.get("result"),dict):data=data["result"]
    except ValueError:
        data={}
    cleanup=("cleanup_incomplete" in (out+err).lower())
    print("REA_P2_FOLLOWUP_CLI="+name+";rc="+str(rc)+";cleanup_incomplete="+str(cleanup).lower(),flush=True)
    return rc,data if isinstance(data,dict) else {},cleanup

def check_source():
    if pwd.getpwuid(os.geteuid()).pw_name != "ubuntu":raise RuntimeError("SSH_NOT_UBUNTU")
    if ROOT.is_symlink() or not ROOT.is_dir():raise RuntimeError("ORIGINAL_DIRECTORY_CHANGED")
    if not NODE.is_file():raise RuntimeError("PINNED_NODE_MISSING")
    rc,out,_=run(["git","-C",str(ROOT),"rev-parse","HEAD"])
    if rc or out.strip()!=REV:raise RuntimeError("ORIGINAL_COMMIT_CHANGED")
    for name,digest in {
      "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
      "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
    }.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError("ORIGINAL_BINARY_CHANGED")
    if not EVID.parent.is_dir():raise RuntimeError("CANONICAL_EVIDENCE_MISSING")
    EVID.mkdir(mode=0o700,parents=True,exist_ok=True)
    EVID.chmod(0o700)
    print("REA_P2_FOLLOWUP_ORIGINAL_PIN=PASS",flush=True)

def clean_env(home):
    env=dict(os.environ)
    for k in list(env):
        if k.startswith("REA_") or k in ("PYTHONPATH","PYTHONHOME","QT_PLUGIN_PATH","QT_QPA_PLATFORM_PLUGIN_PATH"):
            env.pop(k,None)
    env.update({"HOME":str(home),"XDG_DATA_HOME":str(home/".local/share"),
                "XDG_CONFIG_HOME":str(home/".config"),
                "XDG_CACHE_HOME":str(home/".cache"),
                "PATH":str(NODE.parent)+":"+env.get("PATH",""),
                "CI":"1"})
    return env

def cutter_probe():
    home = EVID/"cutter-owned-home"
    if home.exists():raise RuntimeError("OWNED_CUTTER_HOME_ALREADY_EXISTS")
    home.mkdir(mode=0o700)
    env=clean_env(home)
    bridge=home/"bridge"
    bridge.mkdir(mode=0o700)
    env["REA_CUTTER_BRIDGE_DIR"]=str(bridge)
    plugin=ROOT/"bridge/cutter/rea_bridge.py"
    plugin_dir=home/".local/share/rizin/cutter/plugins/python"
    plugin_dir.mkdir(parents=True,mode=0o700)
    if not plugin.is_file():raise RuntimeError("OFFICIAL_CUTTER_BRIDGE_MISSING")
    (plugin_dir/"rea_bridge.py").symlink_to(plugin)
    result={"program_present":CUTTER.is_file(),"official_original_bridge_used":True,
            "private_home":True,"result":"NOT_STARTED","cli_cutter_analysis":"NOT_TESTED",
            "cleanup":"NOT_STARTED"}
    launcher=shutil.which("xvfb-run")
    if not (CUTTER.is_file() and os.access(CUTTER,os.X_OK) and launcher):
        result["result"]="MISSING_CUTTER_OR_XVFB_RUN"
        shutil.rmtree(home)
        summary["cutter"]=result
        print("REA_P2_CUTTER_BRIDGE=MISSING_PREREQUISITE",flush=True)
        return
    stdout_file=(EVID/"cutter-owned.stdout.log").open("w")
    stderr_file=(EVID/"cutter-owned.stderr.log").open("w")
    process=None
    try:
        process=subprocess.Popen([launcher,"-a","-s","-screen 0 1280x800x24 -nolisten tcp",
                     str(CUTTER),"/usr/bin/true"],
                     cwd=str(EVID),env=env,stdin=subprocess.DEVNULL,
                     stdout=stdout_file,stderr=stderr_file,start_new_session=True)
        result["result"]="PROCESS_LAUNCHED"
        found=[]
        response={}
        for idx in range(11):
            if process.poll() is not None:break
            time.sleep(2)
            rc,response,cleanup=cli(["list-cutter-sessions"],env,"cutter-sessions-"+str(idx),timeout=18)
            normalized=response.get("normalized_result",response)
            if isinstance(normalized,dict):
                found=normalized.get("sessions",[])
                if not isinstance(found,list):found=[]
                if normalized.get("discovery_status")=="sessions_found" and found and rc==0 and not cleanup:
                    break
        result["process_exit_before_cleanup"]=process.poll()
        result["discovery_status"]=normalized.get("discovery_status") if isinstance(normalized,dict) else None
        result["sessions_found"]=len(found)
        print("REA_P2_CUTTER_AUTHENTICATED_SESSIONS="+str(len(found))+";discovery="+str(result["discovery_status"]),flush=True)
        if found:
            ss=found[0]
            sid=ss.get("session_id") if isinstance(ss,dict) else None
            generation=ss.get("document_generation") if isinstance(ss,dict) else None
            result["cutter_version"]=str(ss.get("cutter_version",""))[:80]
            result["current_file_present"]=bool(ss.get("current_file"))
            if isinstance(sid,str) and isinstance(generation,int):
                rc, data, incomplete=cli(["cutter-command",sid,str(generation),"ij","--json-output"],env,"cutter-real-ij",timeout=35)
                norm=data.get("raw_result",data.get("normalized_result",{}))
                result["cli_cutter_analysis"]="PASS" if rc==0 and isinstance(norm,dict) and isinstance(norm.get("bin"),dict) and isinstance(norm["bin"].get("arch"),str) and not incomplete else "NOT_PROVEN"
                result["result"]="PASS_BRIDGE_V2" if rc==0 and not incomplete else "BRIDGE_COMMAND_FAILED"
            else:result["result"]="DISCOVERY_NO_VALID_SESSION_ID"
        else:result["result"]="NO_AUTHENTICATED_BRIDGE_SESSION"
    finally:
        if process is not None:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=5)
        stdout_file.close()
        stderr_file.close()
        if home.is_dir():shutil.rmtree(home)
        result["cleanup"]="PASS" if process is None or process.poll() is not None else "FAIL"
        result["owned_home_removed"]=not home.exists()
        summary["cutter"]=result
        print("REA_P2_CUTTER_BRIDGE="+result["result"]+";analysis="+result["cli_cutter_analysis"]+";cleanup="+result["cleanup"],flush=True)

def chrome_probe():
    binaries=[]
    if BROWSER_ROOT.is_dir():
        for base,dirs,files in os.walk(BROWSER_ROOT,followlinks=False):
            dirs[:]=[n for n in dirs if n not in ("node_modules","locales",".git","resources","swiftshader")]
            if "chrome" in files or "chrome-headless-shell" in files:
                binaries += [str(Path(base)/name) for name in ("chrome","chrome-headless-shell") if name in files]
                if len(binaries)>5:break
    info={"status":"NO_BINARY" if not binaries else "INSTALLED",
          "binary_count":len(binaries),"userns_restriction":None,"sandbox_untouched":True}
    for name in ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns","/proc/sys/kernel/unprivileged_userns_clone"):
        p=Path(name)
        try:info[p.name]=p.read_text().strip()
        except OSError:info[p.name]="UNKNOWN"
    if binaries:
        binary=Path(binaries[0])
        parent=binary.parent
        sandbox=parent/"chrome-sandbox"
        try:
            mode=sandbox.stat().st_mode
            info["setuid_sandbox_present"]=(sandbox.is_file() and bool(mode & stat.S_ISUID) and sandbox.stat().st_uid==0)
        except OSError:info["setuid_sandbox_present"]=False
        info["chromium_path"]=str(binary)
        rc,out,err=run(["/usr/bin/ldd",str(binary)])
        info["shared_libs_missing"]=len([line for line in out.splitlines() if "not found" in line])
        info["ldd_status"]=rc
    info["alternatives"]={name:bool(shutil.which(name)) for name in ("chromium","chromium-browser","google-chrome-stable")}
    info["existing_apparmor_profile"]=Path("/etc/apparmor.d/chrome").is_file()
    summary["chromium"]=info
    print("REA_P2_CHROMIUM_PROFILE_POLICY=UNCHANGED;alternatives="+str(info["alternatives"])+
          ";setuid_sandbox="+str(info.get("setuid_sandbox_present")),flush=True)

def hopper_probe():
    info={"installed":HOPPER.is_file(),"publisher_feed_checked":False,
          "installed_matches_current_feed":False,"license_bypass":False}
    if HOPPER.is_file():
        info["installed_sha256"]=hashlib.sha256(HOPPER.read_bytes()).hexdigest()
        rc,out,err=run(["/usr/bin/dpkg-query","-S",str(HOPPER)])
        info["package_owner"]=out.strip()[:100] if rc==0 else "UNTRACKED_BY_DPKG"
        try:
            req=urllib.request.Request(FEED,headers={"User-Agent":"rea-original-p2-publisher-readonly/1"})
            with urllib.request.urlopen(req,timeout=16) as resp:
                raw=resp.read(1024*1024+1)
            if len(raw)>1024*1024:raise RuntimeError("OFFICIAL_FEED_TOO_LARGE")
            feed=json.loads(raw)
            info["publisher_feed_checked"]=True
            def rows(x):
                if isinstance(x,list):
                    for item in x:yield from rows(item)
                if isinstance(x,dict):
                    if "main_exe_hash" in x and "filename" in x:yield x
                    else:
                        for value in x.values():
                            if isinstance(value,(list,dict)):yield from rows(value)
            releases=[v for v in rows(feed) if isinstance(v.get("filename"),str)
                and v["filename"].startswith(("https://www.hopperapp.com/","https://www.hopperapp.com:443/")) and "Linux-demo" in v["filename"]]
            info["official_linux_demo_entries"]=len(releases)
            matches=[v for v in releases if v.get("main_exe_hash")==info["installed_sha256"]]
            info["installed_matches_current_feed"]=bool(matches)
            info["matched_version"]=str(matches[0].get("version",""))[:35] if matches else None
            info["official_deb_versions"]=list(dict.fromkeys(
                str(v.get("version",""))[:35] for v in releases if v["filename"].endswith(".deb")))[:6]
        except Exception as e:
            info["publisher_error"]=type(e).__name__+":"+str(e)[:120]
    summary["hopper"]=info
    print("REA_P2_HOPPER_OFFICIAL_DEB_VERSIONS="+str(info.get("official_deb_versions",[])),flush=True)
    print("REA_P2_HOPPER_PUBLISHER_FEED="+str(info["publisher_feed_checked"]).lower()+
          ";match="+str(info["installed_matches_current_feed"]).lower()+
          ";owner="+str(info.get("package_owner")),flush=True)

def main():
    check_source()
    for filename in ("cutter-real-ij.stdout.json","cutter-real-ij.stderr.log"):
        f=EVID/filename
        if not f.is_file():continue
        s=f.read_text(encoding="utf8",errors="replace")
        if filename.endswith(".json"):
            try:
                v=json.loads(s)
                def clean(v):
                    if isinstance(v,str):return v[:380]
                    if isinstance(v,(int,float,bool)) or v is None:return v
                    if isinstance(v,dict):
                        return {k:clean(z) for k,z in v.items() if k in ("code","message","error",
                         "reason","boundary","diagnostics","details","predicate_type","execution_state","cleanup")}
                    return type(v).__name__
                safe={"top_keys":list(v)[:22] if isinstance(v,dict) else [],
                      "status":clean(v)}
                print("REA_P2_CUTTER_FAILED_COMMAND="+json.dumps(safe)[:3500],flush=True)
            except ValueError:print("REA_P2_CUTTER_FAILED_COMMAND=UNPARSEABLE",flush=True)
        else:
            print("REA_P2_CUTTER_FAILED_STDERR="+json.dumps(s.splitlines()[-15:])[:2200],flush=True)
    rc,out,err=run(["/usr/bin/dpkg-query","-W","-f=${Version}","hopper"])
    print("REA_P2_HOPPER_INSTALLED_PACKAGE_VERSION="+(out.strip()[:45] if rc==0 else "UNKNOWN"),flush=True)
    print("REA_P2_READBACK_ONLY=PASS",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print("REA_P2_FOLLOWUP_FATAL="+type(e).__name__+":"+str(e)[:180],flush=True)
        sys.exit(46)
