#!/usr/bin/env bash
set -euo pipefail
umask 077
cleanup() {
  result=$?
  trap - EXIT
  adb shell am force-stop com.pinkiptv.extreme >/dev/null 2>&1 || true
  adb shell pm clear com.pinkiptv.extreme >/dev/null 2>&1 || true
  rm -f "$RUNNER_TEMP/pink060-fixed-dns.txt" "$RUNNER_TEMP/pink060-startup.txt"
  exit "$result"
}
trap cleanup EXIT
# Fixed public control hostname only; no account fixture or VPS host access.
adb shell ping -c 1 -W 3 pink-iptv.duckdns.org > "$RUNNER_TEMP/pink060-fixed-dns.txt" 2>&1 || true
python - <<'PY'
import os,re
from pathlib import Path
output=Path(os.environ['RUNNER_TEMP'],'pink060-fixed-dns.txt').read_text()
assert re.search(r'^PING [^\n]*\(146\.59\.145\.3\)',output,re.M)
print('ANDROID13_FIXED_CONTROL_DNS_EXPECTED_TARGET=PASS')
PY
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-1.9.0-debug.apk"
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-instrumentation.apk"
adb shell am instrument -w -r -e class com.pinkiptv.extreme.PinkVpnStartupTest com.pinkiptv.extreme.test/androidx.test.runner.AndroidJUnitRunner > "$RUNNER_TEMP/pink060-startup.txt"
cat "$RUNNER_TEMP/pink060-startup.txt"
grep -q 'OK (1 test)' "$RUNNER_TEMP/pink060-startup.txt"
echo ANDROID13_DNS_PROFILE_AND_UNCHANGED_STRICT_STARTUP=PASS
