#!/usr/bin/env bash
# Free REA Android/native engines, installed only under the ubuntu user's trial directory.
set -Eeuo pipefail
umask 077
BASE="$HOME/.local/share/rea-chatgpt-trial"
TOOLS="$BASE/tools"
REA="$BASE/repository/rea"
GHIDRA_RELEASE="ghidra_12.1.4_PUBLIC_20260921.zip"
GHIDRA_SHA="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
JADX_SHA="6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"
test -f "$REA/scripts/rea.mjs" && test -f "$REA/dist/cli-runtime/cli.js"
test "$(id -un)" = "ubuntu"
python3 - <<'PY'
import shutil,sys
from pathlib import Path
m=0
for line in Path("/proc/meminfo").read_text().splitlines():
    if line.startswith("MemAvailable:"): m=int(line.split()[1])
d=shutil.disk_usage(str(Path.home())).free
print("REA_TOOLS_MEMORY_AVAILABLE_GIB=%.2f" % (m/1024/1024))
print("REA_TOOLS_DISK_FREE_GIB=%.2f" % (d/1024**3))
if m < 3*1024*1024 or d < 18*1024**3:
    print("REA_TOOLS_PREFLIGHT=REFUSED")
    sys.exit(6)
print("REA_TOOLS_PREFLIGHT=PASS")
PY
mkdir -p "$TOOLS"
TMP="$(mktemp -d "$BASE/.tool-stage.XXXXXXXX")"
cleanup() { if [ -d "$TMP" ]; then rm -rf -- "$TMP"; fi; }
trap cleanup EXIT
echo "REA_FREE_TOOLS_V1=STARTED"

if [ ! -f "$TOOLS/jadx-headless-mcp-0.7.1-all.jar" ]; then
  echo "JADX_DOWNLOAD=STARTED"
  curl -fL --connect-timeout 15 --max-time 400 --retry 2 \
    -o "$TMP/jadx.jar" \
    "https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar"
  printf '%s  %s\n' "$JADX_SHA" "$TMP/jadx.jar" | sha256sum -c - >/dev/null
  mv -- "$TMP/jadx.jar" "$TOOLS/jadx-headless-mcp-0.7.1-all.jar"
  echo "JADX_CHECKSUM=PASS"
fi
printf '%s  %s\n' "$JADX_SHA" "$TOOLS/jadx-headless-mcp-0.7.1-all.jar" | sha256sum -c - >/dev/null
export REA_JADX_MCP_JAR="$TOOLS/jadx-headless-mcp-0.7.1-all.jar"
export REA_JADX_HEAP_MIB=1024
if timeout 90s node "$REA/scripts/rea.mjs" doctor --provider jadx --json > "$TMP/jadx-doctor.json" 2> "$TMP/jadx-error.log"; then
  python3 - "$TMP/jadx-doctor.json" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1],encoding="utf-8"))
print("JADX_REA_DOCTOR_JSON=PASS",type(obj).__name__)
PY
else
  echo "JADX_REA_DOCTOR=FAILED"
  tail -n 12 "$TMP/jadx-error.log"
fi

if [ ! -x "$TOOLS/jdk-21/bin/java" ]; then
  echo "JDK21_DOWNLOAD_METADATA=STARTED"
  curl -fLsS --connect-timeout 15 --max-time 90 \
    "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse" \
    -o "$TMP/jdk-meta.json"
  python3 - "$TMP/jdk-meta.json" "$TMP/jdk-url.txt" "$TMP/jdk-sha.txt" <<'PY'
import json,sys,re
from pathlib import Path
doc=json.load(open(sys.argv[1],encoding="utf-8"))
assert isinstance(doc,list) and doc
pkg=doc[0]["binary"]["package"]
url=pkg["link"]
sha=pkg["checksum"]
assert url.startswith("https://github.com/adoptium/temurin21-binaries/releases/download/")
assert re.fullmatch(r"[0-9a-fA-F]{64}",sha)
Path(sys.argv[2]).write_text(url)
Path(sys.argv[3]).write_text(sha)
PY
  echo "JDK21_DOWNLOAD=STARTED"
  curl -fL --connect-timeout 15 --max-time 600 --retry 2 \
    -o "$TMP/jdk.tar.gz" "$(cat "$TMP/jdk-url.txt")"
  printf '%s  %s\n' "$(cat "$TMP/jdk-sha.txt")" "$TMP/jdk.tar.gz" | sha256sum -c - >/dev/null
  mkdir -p "$TMP/jdk21"
  tar -xzf "$TMP/jdk.tar.gz" -C "$TMP/jdk21" --strip-components=1
  test -x "$TMP/jdk21/bin/java" && test -x "$TMP/jdk21/bin/javac"
  "$TMP/jdk21/bin/java" -version 2>&1 | head -n 1
  mv -- "$TMP/jdk21" "$TOOLS/jdk-21"
  echo "JDK21_CHECKSUM_AND_INSTALL=PASS"
fi
export JAVA_HOME="$TOOLS/jdk-21"
"$JAVA_HOME/bin/java" -version 2>&1 | head -n 1

if [ ! -x "$TOOLS/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" ]; then
  echo "GHIDRA_DOWNLOAD=STARTED"
  curl -fL --connect-timeout 15 --max-time 800 --retry 2 \
    -o "$TMP/$GHIDRA_RELEASE" \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/$GHIDRA_RELEASE"
  printf '%s  %s\n' "$GHIDRA_SHA" "$TMP/$GHIDRA_RELEASE" | sha256sum -c - >/dev/null
  mkdir -p "$TMP/extracted"
  unzip -q "$TMP/$GHIDRA_RELEASE" -d "$TMP/extracted"
  test -x "$TMP/extracted/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
  mv -- "$TMP/extracted/ghidra_12.1.4_PUBLIC" "$TOOLS/ghidra_12.1.4_PUBLIC"
  echo "GHIDRA_CHECKSUM_AND_INSTALL=PASS"
fi
export GHIDRA_INSTALL_DIR="$TOOLS/ghidra_12.1.4_PUBLIC"
export GHIDRA_HEADLESS_MAXMEM=1024M
if timeout 120s node "$REA/scripts/rea.mjs" doctor --provider ghidra --json > "$TMP/ghidra-doctor.json" 2> "$TMP/ghidra-error.log"; then
  python3 - "$TMP/ghidra-doctor.json" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1],encoding="utf-8"))
print("GHIDRA_REA_DOCTOR_JSON=PASS",type(obj).__name__)
PY
else
  echo "GHIDRA_REA_DOCTOR=FAILED"
  tail -n 12 "$TMP/ghidra-error.log"
fi

echo "REA_FREE_TOOLS_V1=STAGED_NO_PUBLIC_SERVICE"
