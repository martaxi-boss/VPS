#!/usr/bin/env bash
set -euo pipefail
umask 077
cleanup() {
  result=$?
  trap - EXIT
  adb shell am force-stop com.pinkiptv.extreme >/dev/null 2>&1 || true
  adb shell pm clear com.pinkiptv.extreme >/dev/null 2>&1 || true
  rm -f "$RUNNER_TEMP/pink060-startup.txt"
  exit "$result"
}
trap cleanup EXIT
# Fixed public control hostname only; no account fixture or VPS host access.
python ops/pink_ui_060_dns_ready.py
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-1.9.0-debug.apk"
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-instrumentation.apk"
adb shell am instrument -w -r -e class com.pinkiptv.extreme.PinkVpnStartupTest com.pinkiptv.extreme.test/androidx.test.runner.AndroidJUnitRunner > "$RUNNER_TEMP/pink060-startup.txt"
cat "$RUNNER_TEMP/pink060-startup.txt"
grep -q 'OK (1 test)' "$RUNNER_TEMP/pink060-startup.txt"
echo ANDROID13_DNS_PROFILE_AND_UNCHANGED_STRICT_STARTUP=PASS
