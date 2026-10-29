#!/usr/bin/env bash
# REA upstream 6.8.0: isolated GitHub Actions -> pinned SSH -> CLI test.
# No MCP bridge, new server, shared node_modules, sudo or service modification.
set -euo pipefail
umask 077
test "$(id -un)" = "ubuntu"
EXPECTED="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT="$HOME/rea-original-upstream-680"
EVIDENCE="$HOME/rea-original-upstream-680-evidence"
NODE_BIN="/opt/rea-reversa/providers/node-v24.22.1/bin"
test -x "$NODE_BIN/node"
export PATH="$NODE_BIN:$PATH"
export CI=1
test "$(node --version)" = "v24.22.1"
command -v npm >/dev/null
command -v git >/dev/null
mkdir -p "$EVIDENCE"
test ! -L "$ROOT"
if [ ! -e "$ROOT" ]; then
  git clone --depth 1 --branch rea-agents-6.8.0 --single-branch \
    https://github.com/morluto/rea.git "$ROOT"
  echo "REA_ORIGINAL_CLONE=PASS"
else
  test -d "$ROOT/.git"
  test "$(git -C "$ROOT" remote get-url origin)" = "https://github.com/morluto/rea.git"
  echo "REA_ORIGINAL_EXISTING_CLONE=REUSED"
fi
test "$(git -C "$ROOT" rev-parse HEAD)" = "$EXPECTED"
test "$(git -C "$ROOT" describe --tags --exact-match HEAD)" = "rea-agents-6.8.0"
echo "REA_ORIGINAL_SOURCE_COMMIT=$EXPECTED"
cd "$ROOT"
test "$(node -p "require('./package.json').version")" = "6.8.0"
# Fresh original source and build; reuse only verified installed dependencies.
# No reuse of compiled REA modules, local patches, services, credentials or MCP.
INSTALLED="/opt/rea-reversa/rea"
# Read-only stress run: the original installation must already have passed
# the first-install build. Do not invoke npm ci or install a new provider.
test -f "$EVIDENCE/build-pass-for-$EXPECTED" || {
  echo "REA_ORIGINAL_STRESS=BLOCKED_FIRST_INSTALL_NOT_VERIFIED"
  exit 36
}
test -f "$ROOT/node_modules/.package-lock.json"
cmp -s package-lock.json "$INSTALLED/package-lock.json"
node scripts/check-dependency-install.mjs > "$EVIDENCE/dependency-recheck.log" 2>&1
echo "REA_ORIGINAL_STRESS_DEPENDENCIES=VERIFIED_NO_INSTALL"
if [ ! -f "$EVIDENCE/build-pass-for-$EXPECTED" ]; then
  if [ ! -e node_modules ]; then
    if [ -f "$INSTALLED/package-lock.json" ] &&
       [ -d "$INSTALLED/node_modules" ] &&
       [ -f "$INSTALLED/node_modules/.package-lock.json" ] &&
       cmp -s package-lock.json "$INSTALLED/package-lock.json"; then
      ln -s "$INSTALLED/node_modules" node_modules
      if node scripts/check-dependency-install.mjs > "$EVIDENCE/dependency-check.log" 2>&1; then
        echo "REA_ORIGINAL_DEPENDENCIES=REUSED_VERIFIED_LOCK"
      else
        unlink node_modules
        echo "REA_ORIGINAL_DEPENDENCIES=INCOMPATIBLE_LOCK_INSTALL_OWN"
      fi
    fi
  fi
  if [ ! -e node_modules ]; then
    npm ci --no-audit --no-fund > "$EVIDENCE/npm-ci.log" 2>&1 || {
      echo "REA_ORIGINAL_NPM_CI=FAIL"
      tail -n 20 "$EVIDENCE/npm-ci.log" | sed -E 's#(https?://)[^ ]+#\1[URL_REDACTED]#g'
      exit 31
    }
    echo "REA_ORIGINAL_DEPENDENCIES=INSTALLED_OWN_LOCK"
  fi
  node scripts/check-dependency-install.mjs > "$EVIDENCE/dependency-check.log" 2>&1 || {
    echo "REA_ORIGINAL_DEPENDENCIES=FAIL_VERIFICATION"
    exit 34
  }
  echo "REA_ORIGINAL_DEPENDENCY_CHECK=PASS"
  npm run build:cached > "$EVIDENCE/build.log" 2>&1 || {
    echo "REA_ORIGINAL_BUILD=FAIL"
    tail -n 25 "$EVIDENCE/build.log"
    exit 32
  }
  touch "$EVIDENCE/build-pass-for-$EXPECTED"
fi
test -f dist/process/ProcessOwnership.js
test -f dist/process/ProcessOwnershipObservation.js
test -f dist/cli-runtime/cli.js
echo "REA_ORIGINAL_BUILD=PASS"
echo "REA_ORIGINAL_ENGINE_VERSION=$(node scripts/rea.mjs --version)"
sha256sum dist/process/ProcessOwnership.js dist/process/ProcessOwnershipObservation.js |
  awk '{print "REA_ORIGINAL_COMPILED_SHA256=" $1 " " $2}'
# Do not configure or start any MCP endpoint.
python3 - "$EVIDENCE" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
for size in (8,30):
    for attempt in (1,2,3):
        script = (
            "import subprocess; "
            "p=[subprocess.Popen(['/usr/bin/true']) for _ in range(" + str(size) + ")]; "
            "r=[x.wait() for x in p]; "
            "print('ORIGINAL_CHILDREN=" + str(size) + " EXIT='+str(max(r)))"
        )
        case = {"executable":"/usr/bin/python3",
                "arguments":["-c",script],
                "timeout_ms":20000, "settle_ms":400, "finalization_ms":1200}
        (out / ("scenario-" + str(size) + "-" + str(attempt) + ".json")).write_text(
            json.dumps(case),encoding="utf8")
PY
failures=0
for size in 8 30; do
  for attempt in 1 2 3; do
    file="$EVIDENCE/scenario-$size-$attempt.json"
    output="$EVIDENCE/capture-$size-$attempt.json"
    errors="$EVIDENCE/capture-$size-$attempt.stderr"
    if node scripts/rea.mjs capture-process "$file" --json > "$output" 2> "$errors"; then
      result_code=0
    else
      result_code=$?
    fi
    if python3 - "$output" "$errors" "$size" "$attempt" "$result_code" <<'PY'
import json, pathlib, re, sys
output, error, size, attempt, exit_code = sys.argv[1:]
raw = pathlib.Path(output).read_text(errors="replace")
err = pathlib.Path(error).read_text(errors="replace")
try:
    obj = json.loads(raw)
except (ValueError, TypeError):
    obj = {}
inner = obj.get("result") if isinstance(obj, dict) else None
if not isinstance(inner, dict): inner = obj
norm = inner.get("normalized_result", {}) if isinstance(inner, dict) else {}
if not isinstance(norm, dict): norm = {}
cleanup = norm.get("cleanup", {})
settlement = norm.get("settlement", {})
exit_result = norm.get("exit", {})
combined = raw + "\n" + err
code = "cleanup_incomplete" if "cleanup_incomplete" in combined else "none"
status = "PASS" if int(exit_code) == 0 and code == "none" and (
    isinstance(cleanup, dict) and
    cleanup.get("owned_process_group") in ("verified","cleaned") and
    cleanup.get("temporary_root") in ("removed","cleaned")
) else "FAIL"
print("REA_ORIGINAL_CAPTURE_" + size + "_" + attempt + "=" + status +
      ";cli_rc=" + exit_code + ";error=" + code +
      ";cleanup=" + json.dumps(cleanup, separators=(",",":"))[:240] +
      ";settlement=" + json.dumps(settlement, separators=(",",":"))[:120] +
      ";exit=" + json.dumps(exit_result, separators=(",",":"))[:120])
sys.exit(0 if status == "PASS" else 1)
PY
    then :; else failures=$((failures+1)); fi
  done
done
echo "REA_ORIGINAL_FAILED_CAPTURES=$failures"
echo "REA_ORIGINAL_EVIDENCE_DIRECTORY=$EVIDENCE"
if [ "$failures" -gt 0 ]; then
  echo "REA_ORIGINAL_ACCEPTANCE=FAIL"
  exit 33
fi
echo "REA_ORIGINAL_ACCEPTANCE=PASS"

# REA_ORIGINAL_STRESS_SUITE_VERSION=20261029-v2
# This is a CLI-only experiment. Do not start/register MCP, install vendors, or
# import locally patched REA modules. The HOME below isolates agent config.
echo "REA_ORIGINAL_STRESS_SUITE_VERSION=20261029-v2"
echo "REA_ORIGINAL_EXTERNAL_INSTALLS=NONE"
echo "REA_ORIGINAL_CALL_PATH=GITHUB_ACTIONS_TO_SSH_TO_ORIGINAL_CLI"
test "$(git -C "$ROOT" rev-parse HEAD)" = "$EXPECTED"
git -C "$ROOT" diff --quiet
printf '%s\n' \
  "2171c79dfa0e49c8836cef350c966746ceb90b246a2d678b2e98578167aff852  dist/process/ProcessOwnership.js" \
  "81b1aaeded14556d884adaffa570cef41909deb01f76fc25a2d7bd0f9a775655  dist/process/ProcessOwnershipObservation.js" \
  | sha256sum -c -
echo "REA_ORIGINAL_SOURCE_AND_COMPILED_HASHES=PASS"
mkdir -p "$EVIDENCE/stress" "$EVIDENCE/isolated-home"
chmod 700 "$EVIDENCE/isolated-home"
python3 - "$ROOT" "$EVIDENCE/stress" <<'PY'
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
ev = pathlib.Path(sys.argv[2])
node = "/opt/rea-reversa/providers/node-v24.22.1/bin/node"
env = dict(os.environ)
env["HOME"] = str(ev.parent / "isolated-home")
env["XDG_CACHE_HOME"] = str(ev.parent / "isolated-home" / ".cache")
env["XDG_CONFIG_HOME"] = str(ev.parent / "isolated-home" / ".config")
env["XDG_DATA_HOME"] = str(ev.parent / "isolated-home" / ".local" / "share")
env["CI"] = "1"
env.pop("REA_ANALYSIS_PROVIDER", None)
env.pop("REA_MCP_CONFIG", None)
env.pop("REA_MCP_URL", None)

def save(name, kind, text):
    (ev / (name + "." + kind)).write_text(text, encoding="utf-8")

def proc(args, seconds=120):
    return subprocess.run([node, "scripts/rea.mjs", *args],
                          cwd=root, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=seconds,
                          check=False)

def read_doc(raw):
    try:
        d = json.loads(raw)
        if isinstance(d, dict) and isinstance(d.get("result"),dict):
            return d["result"]
        return d if isinstance(d,dict) else {}
    except (ValueError,TypeError):
        return {}

diagnostics = {}
for name, args, secs in [
    ("providers",["providers","--json"],90),
    ("capabilities",["capabilities","--json"],90),
    ("doctor",["doctor","--json"],180),
    ("elf_notes",["inspect-elf-notes","/usr/bin/true","--json"],90),
    ("artifact",["inspect-artifact","/usr/bin/true","--json"],90)
]:
    try:
        p = proc(args,secs)
        save(name,"json",p.stdout)
        save(name,"stderr",p.stderr)
        obj = read_doc(p.stdout)
        diagnostics[name] = {"exit_code":p.returncode,
                             "has_json":bool(obj),
                             "healthy":obj.get("healthy",None)}
        print("REA_ORIGINAL_DIAG_" + name.upper() + "=" +
              ("PASS" if p.returncode==0 and obj else
               "INFORMATIONAL" if name=="doctor" else "FAIL") +
              ";exit=" + str(p.returncode) +
              ";json=" + str(bool(obj)).lower(),flush=True)
    except subprocess.TimeoutExpired:
        diagnostics[name]={"timeout":True}
        print("REA_ORIGINAL_DIAG_"+name.upper()+"=TIMEOUT",flush=True)

def run_scenario(label, count, kind="normal"):
    if kind=="normal":
        py=("import subprocess; "
            "p=[subprocess.Popen(['/usr/bin/true']) for _ in range("+str(count)+")];"
            "results=[x.wait() for x in p];"
            "print('FINISHED='+str(len(results))+' FAILS='+str(sum(bool(x) for x in results)))")
        timeout_ms=25000
    elif kind=="nonzero":
        py="import sys; print('INTENTIONAL_EXIT_7'); sys.exit(7)"
        timeout_ms=15000
    elif kind=="nested":
        py=("import subprocess; "
            "x=subprocess.run(['/usr/bin/python3','-c',"
            "'import subprocess; p=[subprocess.Popen([\"/usr/bin/true\"]) for _ in range(20)]; [q.wait() for q in p]'],check=True);"
            "print('NESTED_EXIT='+str(x.returncode))")
        timeout_ms=25000
    elif kind=="timeout":
        py="import time; print('INTENTIONAL_TIMEOUT',flush=True); time.sleep(8)"
        timeout_ms=1600
    else:
        raise RuntimeError("unknown stress scenario")
    scenario={"executable":"/usr/bin/python3","arguments":["-c",py],
              "timeout_ms":timeout_ms,"settle_ms":450,
              "finalization_ms":1800,
              "terminal":{"columns":80,"rows":24,"scrollback":120}}
    save(label,"scenario.json",json.dumps(scenario,sort_keys=True))
    try:
        p=proc(["capture-process",str(ev/(label+".scenario.json")),"--json"],65)
        save(label,"evidence.json",p.stdout)
        save(label,"stderr",p.stderr)
        obj=read_doc(p.stdout)
        normalized=obj.get("normalized_result",{})
        if not isinstance(normalized,dict): normalized={}
        cleanup=normalized.get("cleanup",{})
        if not isinstance(cleanup,dict): cleanup={}
        exit_obj=normalized.get("exit",{})
        if not isinstance(exit_obj,dict): exit_obj={}
        disposition=normalized.get("settlement",{})
        if not isinstance(disposition,dict): disposition={}
        has_cleanup_error=("cleanup_incomplete" in p.stderr or
                           "cleanup_incomplete" in p.stdout)
        group_ok=cleanup.get("owned_process_group") in ("verified","cleaned")
        temp_ok=cleanup.get("temporary_root") in ("removed","cleaned")
        if kind=="normal" or kind=="nested":
            expected_exit=exit_obj.get("code")==0
        elif kind=="nonzero":
            expected_exit=exit_obj.get("code")==7
        else:
            expected_exit=exit_obj.get("reason") in ("timeout","cancelled")
        ok=(p.returncode==0 and expected_exit and group_ok and temp_ok
            and not has_cleanup_error)
        result={"id":label,"kind":kind,"children":count,
                "status":"PASS" if ok else "FAIL",
                "cli_exit":p.returncode,
                "capture_exit":exit_obj.get("code"),
                "exit_reason":exit_obj.get("reason"),
                "cleanup":cleanup,
                "settlement":disposition.get("state"),
                "cleanup_incomplete":has_cleanup_error}
    except subprocess.TimeoutExpired as exc:
        result={"id":label,"kind":kind,"children":count,"status":"FAIL",
                "reason":"external-test-timeout",
                "cleanup_incomplete":False}
        save(label,"timeout.txt",str(exc))
    return result

cases=[]
cases.extend(("small-%02d"%i,8,"normal") for i in range(1,9))
cases.extend(("regression-%02d"%i,30,"normal") for i in range(1,17))
cases.extend(("large-%02d"%i,60,"normal") for i in range(1,7))
cases.extend(("xlarge-%02d"%i,100,"normal") for i in range(1,5))
cases.extend(("nonzero-%02d"%i,1,"nonzero") for i in range(1,3))
cases.extend(("nested-%02d"%i,20,"nested") for i in range(1,3))
cases.extend(("timeout-%02d"%i,1,"timeout") for i in range(1,3))
results=[]
started=time.monotonic()
for label,count,kind in cases:
    record=run_scenario(label,count,kind)
    results.append(record)
    print("REA_ORIGINAL_STRESS_CASE="+label+";status="+record["status"]+
          ";cleanup_incomplete="+str(record.get("cleanup_incomplete",False)).lower()+
          ";cleanup="+json.dumps(record.get("cleanup",{}),separators=(",",":"))[:150],
          flush=True)
# Controlled two-way concurrency to exercise independent capture roots.
for index in range(1,3):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures=[
            ex.submit(run_scenario,"parallel-%02d-a"%index,30,"normal"),
            ex.submit(run_scenario,"parallel-%02d-b"%index,30,"normal")
        ]
        for f in concurrent.futures.as_completed(futures):
            record=f.result()
            results.append(record)
            print("REA_ORIGINAL_STRESS_CASE="+record["id"]+
                  ";status="+record["status"]+
                  ";cleanup_incomplete="+str(record.get("cleanup_incomplete",False)).lower(),
                  flush=True)

failures=[r for r in results if r["status"]!="PASS"]
cleanup_failures=[r for r in results if r.get("cleanup_incomplete")]
diag_failures=[k for k in ("providers","capabilities","elf_notes","artifact")
               if diagnostics.get(k,{}).get("exit_code")!=0 or not
               diagnostics.get(k,{}).get("has_json",False)]
summary={"source_tag":"rea-agents-6.8.0",
         "source_commit":"160d821ac9a0310afcb8d1fc427862dd6508add5",
         "tests_total":len(results),"tests_pass":len(results)-len(failures),
         "tests_failed":len(failures),"cleanup_incomplete":len(cleanup_failures),
         "diagnostics":diagnostics,
         "diagnostic_failures":diag_failures,
         "elapsed_seconds":round(time.monotonic()-started,2),
         "cases":results}
save("summary","json",json.dumps(summary,indent=2,sort_keys=True))
print("REA_ORIGINAL_STRESS_TOTAL="+str(len(results)),flush=True)
print("REA_ORIGINAL_STRESS_PASS="+str(len(results)-len(failures)),flush=True)
print("REA_ORIGINAL_STRESS_FAIL="+str(len(failures)),flush=True)
print("REA_ORIGINAL_CLEANUP_INCOMPLETE_COUNT="+str(len(cleanup_failures)),flush=True)
print("REA_ORIGINAL_DIAGNOSTIC_FAILURES="+",".join(diag_failures or ["none"]),flush=True)
print("REA_ORIGINAL_STRESS_EVIDENCE="+str(ev),flush=True)
if cleanup_failures or failures or diag_failures:
    print("REA_ORIGINAL_STRESS_ACCEPTANCE=FAIL",flush=True)
    sys.exit(37)
print("REA_ORIGINAL_STRESS_ACCEPTANCE=PASS",flush=True)
PY
