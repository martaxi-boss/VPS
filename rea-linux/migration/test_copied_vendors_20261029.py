#!/usr/bin/env python3
"""Step 2: Real Ghidra, JADX, Unblob CLI tests on untouched official REA.

GitHub Actions -> pinned SSH -> ubuntu -> original upstream CLI. Never starts
or calls the old MCP transport; no installation, ownership bypass, chmod or
service changes. Test inputs are immutable /usr/bin/true, SHA-pinned public APK
and a generated local gzip+USTAR. Evidence remains in original-only directory.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile

ORIGINAL=Path("/home/ubuntu/rea-original-upstream-680")
PREVIOUS=Path("/opt/rea-reversa/rea")
NODE=Path("/home/ubuntu/rea-final-runtime/vendors/providers/node-v24.22.1/bin/node")
EVID=Path("/home/ubuntu/rea-original-upstream-680-evidence/functional-copied-vendors-20261029")
REV="160d821ac9a0310afcb8d1fc427862dd6508add5"
GHIDRA=Path("/home/ubuntu/rea-final-runtime/vendors/tools/ghidra_12.1.4_PUBLIC")
JDK=Path("/home/ubuntu/rea-final-runtime/vendors/tools/jdk-21")
JADX=Path("/home/ubuntu/rea-final-runtime/vendors/tools/jadx-headless-mcp-0.7.1-all.jar")
UNBLOB=Path("/home/ubuntu/rea-final-runtime/vendors/providers/unblob-26.6.4/bin/unblob")
APK_SHA="a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686"
JADX_SHA="6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"
APK_URL="https://github.com/appium/android-apidemos/releases/download/v6.0.18/ApiDemos-debug.apk"
NATIVE=Path("/usr/bin/true")
DIST_SHA={
 "dist/process/ProcessOwnership.js":"2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852",
 "dist/process/ProcessOwnershipObservation.js":"81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655",
}
os.umask(0o077)
RESULTS=[]
STAGES=[]

def require(ok,desc):
    if not ok:raise RuntimeError(desc)

def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def call(args,env=None,timeout=120):
    start=time.monotonic()
    try:
        p=subprocess.run(args,cwd=ORIGINAL,env=env,timeout=timeout,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            encoding="utf-8",errors="replace",check=False)
        return p.returncode,p.stdout,p.stderr,round(time.monotonic()-start,3)
    except subprocess.TimeoutExpired as e:
        def tostr(x):
            return x.decode("utf-8",errors="replace") if isinstance(x,bytes) else (x or "")
        return 124,tostr(e.stdout),tostr(e.stderr)+"\nCLI_TIMEOUT",round(time.monotonic()-start,3)
    except (OSError,PermissionError) as e:
        return 126,"",type(e).__name__+":"+str(e)[:200],round(time.monotonic()-start,3)

def write(name,data):
    (EVID/name).write_text(data,encoding="utf-8",errors="replace")

def original_checks():
    require(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","UNPRIVILEGED_UBUNTU_REQUIRED")
    require(ORIGINAL.is_dir() and not ORIGINAL.is_symlink(),"ORIGINAL_ROOT_CHANGED")
    require(NODE.is_file(),"NODE_24_MISSING")
    require((ORIGINAL/"node_modules").is_symlink(),"ORIGINAL_DEPS_NOT_REUSED")
    require((ORIGINAL/"node_modules").resolve()==Path("/home/ubuntu/rea-final-runtime/node_modules").resolve(),"DEPS_ORIGIN_CHANGED")
    require((ORIGINAL/"package-lock.json").read_bytes()==(PREVIOUS/"package-lock.json").read_bytes(),
            "DEPENDENCY_LOCK_MISMATCH")
    rc,stdout,stderr,_=call(["git","-C",str(ORIGINAL),"rev-parse","HEAD"],timeout=12)
    require(rc==0 and stdout.strip()==REV,"OFFICIAL_ORIGINAL_COMMIT_DRIFT")
    for path,expected in DIST_SHA.items():
        p=ORIGINAL/path
        require(p.is_file() and not p.is_symlink() and sha(p)==expected,
                "COMPILED_ORIGINAL_DIFFERS:"+path)
    require(EVID.parent.is_dir(),"EVIDENCE_PARENT_MISSING")
    EVID.mkdir(parents=True,exist_ok=True,mode=0o700)
    EVID.chmod(0o700)
    require(NATIVE.is_file(),"HOST_ELF_NOT_FOUND")
    require(GHIDRA.is_dir() and (GHIDRA/"support/analyzeHeadless").is_file(),"EXISTING_GHIDRA_MISSING")
    require((JDK/"bin/java").is_file() and (JDK/"bin/javac").is_file(),"EXISTING_JDK21_MISSING")
    require(JADX.is_file() and sha(JADX)==JADX_SHA,"EXISTING_OFFICIAL_JADX_JAR_HASH_MISMATCH")
    require(UNBLOB.is_file() and os.access(UNBLOB,os.X_OK),"EXISTING_UNBLOB_NOT_ACCESSIBLE")
    print("REA_P2_ORIGINAL_OFFICIAL_COMMIT=PASS;value="+REV,flush=True)
    print("REA_P2_ORIGINAL_COMPILED_HASHES=PASS",flush=True)
    print("REA_P2_EXISTING_NODE_AND_JAR_HASHES=PASS",flush=True)
    print("REA_P2_PROVIDER_INSTALLATIONS=ZERO",flush=True)
    print("REA_P2_TRANSPORT=GITHUB_ACTIONS_SSH_ORIGINAL_CLI_NO_MCP",flush=True)

def environ():
    home=EVID/"isolated-home"
    home.mkdir(mode=0o700,exist_ok=True,parents=True)
    env=dict(os.environ)
    for name in tuple(env):
        if name.startswith("REA_") or name in ("JAVA_HOME","GHIDRA_INSTALL_DIR",
             "HOPPER_LAUNCHER_PATH","PLAYWRIGHT_BROWSERS_PATH"):
            env.pop(name,None)
    env.update({
      "PATH":str(JDK/"bin")+":"+str(NODE.parent)+":"+str(Path("/home/ubuntu/rea-final-runtime/vendors/providers/binwalk-3.1.0/bin"))+":"+env.get("PATH",""),
      "HOME":str(home),
      "XDG_CACHE_HOME":str(home/".cache"),
      "XDG_CONFIG_HOME":str(home/".config"),
      "XDG_DATA_HOME":str(home/".local/share"),
      "JAVA_HOME":str(JDK),
      "GHIDRA_INSTALL_DIR":str(GHIDRA),
      "REA_JADX_MCP_JAR":str(JADX),
      "REA_UNBLOB_COMMAND":str(UNBLOB),
      "REA_BINWALK_COMMAND":"/home/ubuntu/rea-final-runtime/vendors/providers/binwalk-3.1.0/bin/binwalk",
      "CI":"1",
    })
    return env

def parse_evidence(text):
    try:
        j=json.loads(text)
    except (ValueError,TypeError):
        return {},{}
    if not isinstance(j,dict):
        return {},{}
    if isinstance(j.get("result"),dict):
        j=j["result"]
    norm=j.get("normalized_result",{})
    return j,(norm if isinstance(norm,dict) else {})

def execute(label,args,env,timeout=120):
    rc,stdout,stderr,secs=call([str(NODE),"scripts/rea.mjs",*args,"--json"],
                               env=env,timeout=timeout)
    write(label+".json",stdout)
    write(label+".stderr",stderr)
    root,norm=parse_evidence(stdout)
    issue="cleanup_incomplete" in (stdout+stderr).lower()
    x={"name":label,"return_code":rc,"duration_sec":secs,
       "json_evidence":bool(root),"normalized_keys":list(norm.keys())[:45],
       "cleanup_incomplete":issue,"stdout_sha256":hashlib.sha256(stdout.encode()).hexdigest(),
       "stderr_digest":hashlib.sha256(stderr.encode()).hexdigest(),
       "error":root.get("error") if isinstance(root.get("error"),dict) else None}
    STAGES.append(x)
    print("REA_P2_RUN="+label+";exit="+str(rc)+";json="+str(bool(root)).lower()+
          ";elapsed="+str(secs)+";cleanup_incomplete="+str(issue).lower()+
          ";norm_keys="+",".join(list(norm.keys())[:15]),flush=True)
    return x,root,norm

def record(name,status,details=None):
    v={"name":name,"status":status}
    if details is not None:v["details"]=details
    RESULTS.append(v)
    print("REA_P2_TEST="+name+";result="+status,flush=True)

def use_public_apk():
    candidates=[
      ORIGINAL/"_reference/apk-integration/ApiDemos-debug.apk",
      PREVIOUS/"_reference/apk-integration/ApiDemos-debug.apk",
      Path("/home/ubuntu/.local/share/rea-chatgpt-trial/_reference/apk-integration/ApiDemos-debug.apk"),
      EVID/"ApiDemos-debug.apk",
    ]
    for p in candidates:
        try:
            if p.is_file() and sha(p)==APK_SHA:
                print("REA_P2_APK_SOURCE=EXISTING_VERIFIED;path="+str(p),flush=True)
                return p
        except (OSError,PermissionError):
            continue
    # The only downloadable item is the official public APK test fixture,
    # not a binary provider, dependency or tool installation. Verify its
    # upstream pinned digest before it can be used for any JADX analysis.
    target=EVID/"ApiDemos-debug.apk"
    temp=EVID/"ApiDemos-debug.apk.download.tmp"
    try:
        request=urllib.request.Request(APK_URL,
              headers={"User-Agent":"rea-original-fixture-validation/1"})
        with urllib.request.urlopen(request,timeout=45) as response, temp.open("wb") as out:
            size=0
            while True:
                chunk=response.read(256*1024)
                if not chunk:break
                size+=len(chunk)
                if size>75*1024*1024:raise RuntimeError("PUBLIC_APK_TOO_LARGE")
                out.write(chunk)
        require(sha(temp)==APK_SHA,"PUBLIC_APK_DIGEST_MISMATCH")
        temp.replace(target)
        print("REA_P2_APK_SOURCE=PUBLIC_OFFICIAL_FIXTURE_SHA_VERIFIED;size="+str(size),flush=True)
        return target
    except Exception as e:
        print("REA_P2_APK_FIXTURE_BLOCKED="+type(e).__name__+
              ":"+str(e)[:160],flush=True)
        if temp.is_file():temp.unlink()
        return None

def positive(label,x,norm,pred,details=None):
    passed=(x["return_code"]==0 and x["json_evidence"]
            and bool(norm) and not x["cleanup_incomplete"] and pred(norm))
    record(label,"PASS" if passed else "FAIL",details or {
      "cli_exit":x["return_code"],"keys":x["normalized_keys"][:14]})
    return passed

def fixture_unblob(env):
    payload=b"REA_ORIGINAL_UNBLOB_STEP2_REAL_EXTRACTION\n"*80
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode="w",format=tarfile.USTAR_FORMAT) as tf:
        info=tarfile.TarInfo("proof.txt")
        info.size=len(payload)
        info.mtime=0
        info.mode=0o644
        tf.addfile(info,io.BytesIO(payload))
    raw=b"\x00"*64+gzip.compress(archive.getvalue(),mtime=0)+b"\x00"*192
    src=EVID/"firmware-step2.bin"
    dst=EVID/("unblob-output-"+str(time.time_ns()))
    src.write_bytes(raw)
    x,root,norm=execute("unblob-real-extraction",[
           "extract-firmware",str(src),str(dst)
       ],env,timeout=170)
    checks=[]
    for o in norm.get("files",[]) if isinstance(norm.get("files"),list) else []:
        if not isinstance(o,dict):continue
        f=o.get("path")
        if not isinstance(f,str):continue
        p=Path(f)
        if p.is_relative_to(dst) and p.is_file() and sha(p)==hashlib.sha256(payload).hexdigest():
            checks.append(str(p))
    chunks=norm.get("chunks",[])
    hasgzip=isinstance(chunks,list) and any(isinstance(c,dict) and c.get("handler")=="gzip" for c in chunks)
    intact=sha(src)==hashlib.sha256(raw).hexdigest()
    positive("Unblob_26.6.4_real_firmware_extraction",x,norm,
             lambda n:bool(checks) and hasgzip and intact,
             {"extracted_digest_verified":bool(checks),
              "real_gzip_chunk":hasgzip,"source_unchanged":intact})
    return bool(checks) and hasgzip and intact

def capture(n,env):
    python=("import subprocess; "
            "p=[subprocess.Popen(['/usr/bin/true']) for _ in range("+str(n)+")]; "
            "r=[x.wait() for x in p]; "
            "print('CHILDREN=%d'%len(r))")
    scenario=EVID/("capture-"+str(n)+".scenario.json")
    scenario.write_text(json.dumps({
        "executable":"/usr/bin/python3","arguments":["-c",python],
        "timeout_ms":24000
    }),encoding="utf-8")
    x,root,norm=execute("cleanup-"+str(n),["capture-process",str(scenario)],env,timeout=60)
    cl=norm.get("cleanup",{})
    ex=norm.get("exit",{})
    ok=(isinstance(cl,dict) and isinstance(ex,dict) and ex.get("code")==0
        and cl.get("owned_process_group") in ("verified","cleaned")
        and cl.get("temporary_root") in ("removed","cleaned"))
    positive("post_vendor_cleanup_"+str(n),x,norm,lambda y:ok,{"cleanup":cl})
    return ok

def main():
    original_checks()
    # Inspect the relocated entrypoint for a stale absolute shebang.
    try:
        first=UNBLOB.open("rb").readline(400).decode("utf-8",errors="replace").strip()
    except OSError:
        first="UNREADABLE"
    print("REA_COPIED_UNBLOB_SHEBANG="+first[:250],flush=True)
    print("REA_COPIED_NODE_PATH="+str(NODE),flush=True)
    print("REA_COPIED_GHIDRA_PATH="+str(GHIDRA),flush=True)
    print("REA_COPIED_JADX_PATH="+str(JADX),flush=True)
    print("REA_COPIED_JAVA_PATH="+str(JDK),flush=True)
    env=environ()
    initial_hash=sha(NATIVE)
    rc,stdout,stderr,_=call([str(UNBLOB),"--version"],env=env,timeout=15)
    unblob_ready=(rc==0 and stdout.strip()=="26.6.4")
    record("Unblob_existing_version", "PASS" if unblob_ready else "FAIL",
           {"cli_exit":rc,"version":stdout.strip()[:30]})
    for name in ["ghidra","jadx"]:
        x,root,norm=execute("doctor-"+name,["doctor","--provider",name],env,timeout=85)
        status="PASS" if x["return_code"]==0 and root.get("healthy") is True else "FAIL"
        record("doctor_"+name,status,{"healthy":root.get("healthy"),"exit":x["return_code"]})
    # The binary is a real system ELF; provider must not execute target code.
    x,root,norm=execute("ghidra-native-overview",[
        "analyze",str(NATIVE),"--provider","ghidra"
    ],env,timeout=510)
    # Require evidence with a native overview and a real Ghidra provider marker.
    normtext=json.dumps(norm,ensure_ascii=False,default=str).lower()
    roottext=json.dumps(root,ensure_ascii=False,default=str).lower()
    provider_marker="ghidra" in roottext
    native_shape=(isinstance(norm.get("segments"),list)
        or isinstance(norm.get("procedures"),list)
        or any(k in norm for k in ("format","architecture","image_base")))
    native_ok=positive("Ghidra_native_elf_overview",x,norm,
        lambda n:provider_marker and native_shape,
        {"real_ghidra_provider":provider_marker,
         "native_structure":native_shape,"keys":x["normalized_keys"][:25]})
    # A separate provider query tests a different real Ghidra capability. If
    # first failed, do not risk starting another expensive session.
    if native_ok:
        y,r,n=execute("ghidra-native-procedure-search",[
            "search",str(NATIVE),".","--kind","procedures","--mode","regex","--provider","ghidra"
        ],env,timeout=510)
        # The official search_procedures contract returns an array of
        # {value, address} entries as normalized_result, not an object with
        # a nested "matches" key. The generic object-only parser above is
        # intentionally retained for the other command families.
        raw_matches=r.get("normalized_result") if isinstance(r,dict) else None
        matches=raw_matches if isinstance(raw_matches,list) else []
        valid=[item for item in matches
               if isinstance(item,dict)
               and isinstance(item.get("value"),str)
               and item["value"].strip()
               and item.get("address") is not None]
        search_pass=(y["return_code"]==0 and y["json_evidence"]
                     and not y["cleanup_incomplete"] and len(valid)>0)
        record("Ghidra_real_procedure_search",
               "PASS" if search_pass else "FAIL",
               {"result_type":type(raw_matches).__name__,
                "total_matches":len(matches),
                "named_address_matches":len(valid)})
    else:
        record("Ghidra_real_procedure_search","SKIPPED_PREREQUISITE")
    # Real JADX on a publicly hash-pinned APK; no Android device required.
    apk=use_public_apk()
    if apk is None:
        record("JADX_public_apk_package","BLOCKED_FIXTURE")
        record("JADX_real_class_lookup","BLOCKED_FIXTURE")
        record("JADX_real_method_decompile","BLOCKED_FIXTURE")
    else:
        initial_apk_sha=sha(apk)
        x,root,norm=execute("jadx-apk-metadata",[
          "inspect-android-package",str(apk)
        ],env,timeout=450)
        apk_ok=positive("JADX_public_apk_package",x,norm,
            lambda n:n.get("package_name")=="io.appium.android.apis"
                     and n.get("version_name")=="6.0.18"
                     and n.get("manifest",{}).get("status")=="complete",
            {"package":norm.get("package_name"),"version":norm.get("version_name"),
             "class_count":norm.get("class_count")})
        if apk_ok:
            y,r,n=execute("jadx-apk-class",[
               "inspect-android-class",str(apk),"io.appium.android.apis.ApiDemos"
            ],env,timeout=450)
            methods=n.get("methods",[])
            found=any(isinstance(m,dict) and m.get("name")=="onCreate" for m in methods) if isinstance(methods,list) else False
            class_ok=positive("JADX_real_class_lookup",y,n,lambda k:found,
                              {"method_onCreate":found,"methods":len(methods) if isinstance(methods,list) else None})
            if class_ok:
                z,rr,nn=execute("jadx-apk-method",[
                    "inspect-android-method",str(apk),
                    "io.appium.android.apis.ApiDemos","onCreate"
                ],env,timeout=450)
                source=nn.get("source",{})
                if not isinstance(source,dict):source={}
                good=(nn.get("representation")=="java" and nn.get("body_status")=="available"
                      and source.get("status")=="complete" and
                      "getIntent()" in str(source.get("text","")))
                positive("JADX_real_method_decompile",z,nn,lambda k:good,
                         {"java_body":nn.get("body_status"),
                          "source_complete":source.get("status"),
                          "contains_getIntent": "getIntent()" in str(source.get("text",""))})
            else:
                record("JADX_real_method_decompile","SKIPPED_PREREQUISITE")
        else:
            record("JADX_real_class_lookup","SKIPPED_PREREQUISITE")
            record("JADX_real_method_decompile","SKIPPED_PREREQUISITE")
        require(sha(apk)==initial_apk_sha and initial_apk_sha==APK_SHA,"PUBLIC_APK_CHANGED")
    if unblob_ready:
        fixture_unblob(env)
    else:
        record("Unblob_26.6.4_real_firmware_extraction","SKIPPED_PREREQUISITE")
    for n in [8,30]:
        capture(n,env)
    require(sha(NATIVE)==initial_hash,"SYSTEM_TEST_ELF_CHANGED")
    summary={
        "source":REV,"transport":"GitHub Actions SSH -> original CLI, old MCP unused",
        "added_provider_installations":0,"service_changes":0,
        "pristine_original_code":True,"checks":RESULTS,"commands":STAGES,
        "passed":sum(x["status"]=="PASS" for x in RESULTS),
        "failed":sum(x["status"]=="FAIL" for x in RESULTS),
        "not_executed":sum(x["status"].startswith("SKIPPED") or x["status"].startswith("BLOCKED") for x in RESULTS),
        "cleanup_incomplete":sum(bool(x["cleanup_incomplete"]) for x in STAGES),
        "hash_of_test_elf":initial_hash,
        "status":"PASS" if all(x["status"]=="PASS" for x in RESULTS) else "PARTIAL_OR_FAIL"
    }
    write("summary.json",json.dumps(summary,indent=2,sort_keys=True))
    print("REA_P2_TESTS_TOTAL="+str(len(RESULTS)),flush=True)
    print("REA_P2_TESTS_PASS="+str(summary["passed"]),flush=True)
    print("REA_P2_TESTS_FAIL="+str(summary["failed"]),flush=True)
    print("REA_P2_TESTS_NOT_EXECUTED="+str(summary["not_executed"]),flush=True)
    print("REA_P2_CLEANUP_INCOMPLETE="+str(summary["cleanup_incomplete"]),flush=True)
    print("REA_P2_STATUS="+summary["status"],flush=True)
    print("REA_P2_EVIDENCE="+str(EVID),flush=True)
    if summary["status"]!="PASS":sys.exit(31)

if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print("REA_P2_FATAL="+type(exc).__name__+":"+str(exc)[:220],flush=True)
        sys.exit(32)
