#!/usr/bin/env bash
# Isolated trial. No sudo, OS package changes, ports or changes to services.
set -Eeuo pipefail
umask 077
export NODE_OPTIONS="--max-old-space-size=1800"
export npm_config_audit=false
export npm_config_fund=false
export npm_config_jobs=2
BASE="$HOME/.local/share/rea-chatgpt-trial"
GIT_REPO="https://github.com/martaxi-boss/Engenheira-reversa.git"
ENG="$BASE/repository/rea"
printf 'REA_VPS_TRIAL_V1=STARTED\n'

python3 - <<'PY'
from pathlib import Path
import shutil, sys
mem = {}
for l in Path("/proc/meminfo").read_text().splitlines():
    if ":" in l:
        k,v=l.split(":",1)
        if k in {"MemAvailable","MemTotal"}: mem[k]=int(v.split()[0])
available=mem.get("MemAvailable",0)
free=shutil.disk_usage(str(Path.home())).free
print("REA_PREFLIGHT_MEMORY_AVAILABLE_GIB=%.2f" % (available/1024/1024))
print("REA_PREFLIGHT_DISK_FREE_GIB=%.2f" % (free/1024**3))
if available < 4*1024*1024 or free < 24*1024**3:
    print("REA_PREFLIGHT=REFUSED_LOW_RESOURCES")
    sys.exit(8)
print("REA_PREFLIGHT=PASS")
PY

test "$(id -un)" = "ubuntu" || { echo 'REA_USER=UNEXPECTED'; exit 9; }
command -v node >/dev/null && command -v npm >/dev/null && command -v git >/dev/null
node -e 'const v=process.versions.node.split(".").map(Number); if (!((v[0]===22 && v[1]>=19) || (v[0]===24 && v[1]>=11) || v[0]>=26)) process.exit(2)'
printf 'REA_NODE=%s\n' "$(node --version)"

if [ -f "$ENG/dist/cli-runtime/cli.js" ]; then
  echo 'REA_TRIAL=EXISTING_SOURCE_VERIFICATION'
  timeout 45s node "$ENG/scripts/rea.mjs" providers --json > /dev/null
  echo 'REA_REAL_CLI=PASS'
  exit 0
fi

mkdir -p "$BASE"
if [ -e "$BASE/repository" ]; then
  echo 'REA_TRIAL=PREEXISTING_INCOMPLETE_DIR_REFUSED'
  exit 10
fi
TMP="$(mktemp -d "$BASE/.building.XXXXXXXX")"
cleanup() { if [ -n "$TMP" ] && [ -d "$TMP" ]; then rm -rf -- "$TMP"; fi; }
trap cleanup EXIT
printf 'REA_CLONE=STARTED\n'
timeout 180s git clone --depth 1 --single-branch "$GIT_REPO" "$TMP/repository" > "$TMP/clone.log" 2>&1 || { echo 'REA_CLONE=FAILED'; tail -n 16 "$TMP/clone.log"; exit 12; }
printf 'REA_CLONE=PASS\n'
test -f "$TMP/repository/rea/package.json" || { echo 'REA_SOURCE=INVALID'; exit 13; }
REV="$(git -C "$TMP/repository" rev-parse --short=12 HEAD)"
cd "$TMP/repository/rea"
printf 'REA_NPM_INSTALL=STARTED\n'
if ! timeout --signal=TERM --kill-after=25s 480s npm ci --no-audit --no-fund > "$TMP/npm.log" 2>&1; then
  echo 'REA_NPM_INSTALL=FAILED'
  tail -n 24 "$TMP/npm.log"
  exit 14
fi
printf 'REA_NPM_INSTALL=PASS\n'
printf 'REA_BUILD=STARTED\n'
if ! timeout --signal=TERM --kill-after=25s 600s npm run build:cached -- --concurrency=1 > "$TMP/build.log" 2>&1; then
  echo 'REA_BUILD=FAILED'
  tail -n 28 "$TMP/build.log"
  exit 15
fi
printf 'REA_BUILD=PASS\n'
timeout 45s node "$TMP/repository/rea/scripts/rea.mjs" providers --json > "$TMP/providers.json"
python3 - "$TMP/providers.json" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1],encoding="utf-8"))
assert isinstance(obj,dict), "providers output should be JSON object"
print("REA_REAL_CLI=PASS")
PY
cd "$HOME"
mv -- "$TMP/repository" "$BASE/repository"
printf 'REA_INSTALLED_LOCATION=%s\n' "$BASE/repository/rea"
printf 'REA_INSTALLED_REPO_COMMIT=%s\n' "$REV"
echo 'REA_TRIAL_V1=BUILT_AND_VERIFIED_NO_SERVICE_EXPOSED'
