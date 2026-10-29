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
# Install dependencies from the official lockfile, never link the other REA's modules.
if [ ! -f "$EVIDENCE/build-pass-for-$EXPECTED" ]; then
  npm ci --no-audit --no-fund > "$EVIDENCE/npm-ci.log" 2>&1 || {
    echo "REA_ORIGINAL_NPM_CI=FAIL"
    tail -n 35 "$EVIDENCE/npm-ci.log" | sed -E 's#(https?://)[^ ]+#\1[URL_REDACTED]#g'
    exit 31
  }
  echo "REA_ORIGINAL_NPM_CI=PASS"
  npm run build:cached > "$EVIDENCE/build.log" 2>&1 || {
    echo "REA_ORIGINAL_BUILD=FAIL"
    tail -n 35 "$EVIDENCE/build.log"
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
