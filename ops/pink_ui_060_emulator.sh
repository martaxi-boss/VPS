#!/usr/bin/env bash
set -euo pipefail
umask 077
ssh_args=(-T -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
fixture="$RUNNER_TEMP/pink056-account.json"
native_crash_diagnostics() {
  # Wait only for debuggerd's asynchronous trace publication, never publish raw data.
  sleep 3
  if test -f "$RUNNER_TEMP/pink056-current-pid.txt"; then
    pink_crash_pid=$(cat "$RUNNER_TEMP/pink056-current-pid.txt")
  else
    pink_crash_pid=$(adb shell run-as com.pinkiptv.extreme cat files/pink055-process-public.txt 2>/dev/null | tr -d '\r\n')
  fi
  case "$pink_crash_pid" in
    ''|*[!0-9]*) echo PUBLIC_CRASH_DIAGNOSTIC=NO_TARGET_PID ;;
    *) adb logcat -b all -d -v threadtime 2>/dev/null | python ops/pink_vpn_056_crash.py --pid "$pink_crash_pid" ;;
  esac
  if [[ "$pink_crash_pid" =~ ^[0-9]+$ ]]; then
    adb shell dumpsys activity exit-info com.pinkiptv.extreme 2>/dev/null | python ops/pink_vpn_056_crash.py --exit-pid "$pink_crash_pid"
    adb logcat -b all -d -v threadtime 2>/dev/null | python ops/pink_vpn_056_crash.py --system-pid "$pink_crash_pid"
  fi
}
cleanup() {
  result=$?
  trap - EXIT
  set +e
  # Only the disposable emulator's network is changed by the outage proof.
  adb shell svc wifi enable >/dev/null 2>&1
  if ! adb shell run-as com.pinkiptv.extreme cat files/pink055-peer-public.txt > "$RUNNER_TEMP/pink056-public.txt" 2>/dev/null; then
    : > "$RUNNER_TEMP/pink056-public.txt"
  fi
  if test -s "$RUNNER_TEMP/pink056-public.txt"; then
    python - <<'PY'
import base64,os
from pathlib import Path
root=Path(os.environ['RUNNER_TEMP'])
key=(root/'pink056-public.txt').read_text().strip()
assert len(base64.b64decode(key,validate=True))==32 and len(key)==44
source='MODE="cleanup"\nPUBLIC_KEY='+repr(key)+'\n'+Path('ops/pink_vpn_056_runtime.py').read_text()
(root/'pink056-clean.py').write_text(source)
PY
    generated=$?
    if test "$generated" = 0; then
      sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-clean.py"
      cleaned=$?
      if test "$cleaned" != 0; then result=1; fi
    else result=1; fi
  fi
  if test -f "$RUNNER_TEMP/pink056-observe.py"; then
    sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-observe.py"
    observed=$?
    if test "$observed" != 0; then result=1; fi
  fi
  adb shell pm clear com.pinkiptv.extreme >/dev/null 2>&1
  python - <<'PY'
import os
from pathlib import Path
for name in ('pink060-fixed-dns.txt','pink056-account.json','pink056-public.txt','pink056-clean.py','pink056-observe.py','pink056-fetch.py','pink056-current-pid.txt','pink056-live-phase.txt','pink056-exit-boundary.txt','pink056-network-phase.txt'):
    Path(os.environ['RUNNER_TEMP'],name).unlink(missing_ok=True)
PY
  if test "$result" = 0; then echo REAL_ANDROID_PROOF_AND_BOUNDED_PEER_CLEANUP=PASS; fi
  exit "$result"
}
trap cleanup EXIT
# Establish only the fixed public control DNS baseline before host effects.
adb shell ping -c 1 -W 3 pink-iptv.duckdns.org > "$RUNNER_TEMP/pink060-fixed-dns.txt" 2>&1 || true
python - <<'PY'
import os,re
from pathlib import Path
output=Path(os.environ['RUNNER_TEMP'],'pink060-fixed-dns.txt').read_text()
assert re.search(r'^PING [^\n]*\(146\.59\.145\.3\)',output,re.M)
print('ANDROID13_FIXED_CONTROL_DNS_EXPECTED_TARGET=PASS')
Path(os.environ['RUNNER_TEMP'],'pink060-fixed-dns.txt').unlink()
PY
python - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['RUNNER_TEMP'])
expected=json.loads(Path('ops/pink_vpn_054_manifest.json').read_text())
(root/'pink056-observe.py').write_text('EXPECTED_PUBLIC_SOURCE='+repr(expected)+'\n'+Path('ops/pink_vpn_054_observe.py').read_text())
(root/'pink056-fetch.py').write_text('MODE="fetch"\nPUBLIC_KEY=None\n'+Path('ops/pink_vpn_056_runtime.py').read_text())
PY
sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-observe.py"
# Never print this reply: its only recipient is the private emulator fixture.
sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-fetch.py" > "$fixture"
test -s "$fixture"
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-1.9.0-debug.apk"
adb install -r "$RUNNER_TEMP/pink056-artifact/PINK-IPTV-Extreme-instrumentation.apk"
adb shell "run-as com.pinkiptv.extreme sh -c 'umask 077; mkdir -p files; cat > files/pink055-test-account.json'" < "$fixture"
python - <<'PY'
import os
from pathlib import Path
Path(os.environ['RUNNER_TEMP'],'pink056-account.json').unlink()
PY
adb shell am instrument -w -r -e pinkRetainGrant true -e class com.pinkiptv.extreme.PinkVpnLiveTest com.pinkiptv.extreme.test/androidx.test.runner.AndroidJUnitRunner > "$RUNNER_TEMP/pink056-live.txt"
# Instrumentation failures contain generic messages only; never dump logcat.
cat "$RUNNER_TEMP/pink056-live.txt"
if ! grep -q 'OK (1 test)' "$RUNNER_TEMP/pink056-live.txt"; then
  # Never print/store raw crash logs: emit only tested allowlisted class/frames.
  native_crash_diagnostics
  adb shell run-as com.pinkiptv.extreme cat files/pink055-live-phase-public.txt > "$RUNNER_TEMP/pink056-live-phase.txt" 2>/dev/null || true
  adb shell run-as com.pinkiptv.extreme cat files/pink055-fail-closure-public.txt > "$RUNNER_TEMP/pink056-exit-boundary.txt" 2>/dev/null || true
  python ops/pink_vpn_056_live.py "$RUNNER_TEMP/pink056-live-phase.txt" "$RUNNER_TEMP/pink056-exit-boundary.txt" "$pink_crash_pid"
  exit 1
fi
# A new application process receives no account fixture or technical input.
# The EXIT trap still owns cleanup of this exact disposable installation.
previous_pid=$(adb shell run-as com.pinkiptv.extreme cat files/pink055-process-public.txt | tr -d '\r\n')
adb shell am force-stop com.pinkiptv.extreme
# This new process cannot inherit the old test's PID diagnostic. Capture it
# concurrently with instrumentation, before launching its root activity.
: > "$RUNNER_TEMP/pink056-current-pid.txt"
run_restore() {
  restore_output="$2"
  : > "$RUNNER_TEMP/pink056-current-pid.txt"
  adb shell am instrument -w -r -e pinkNetworkChange "$1" -e class com.pinkiptv.extreme.PinkVpnRestoreTest com.pinkiptv.extreme.test/androidx.test.runner.AndroidJUnitRunner > "$restore_output" &
restore_command=$!
while kill -0 "$restore_command" 2>/dev/null; do
  current_pid=$(adb shell pidof com.pinkiptv.extreme 2>/dev/null | tr -d '\r\n') || current_pid=''
  if [[ "$current_pid" =~ ^[0-9]+$ && "$current_pid" != "$previous_pid" ]]; then
    printf '%s' "$current_pid" > "$RUNNER_TEMP/pink056-current-pid.txt"
    break
  fi
  sleep 0.05
done
wait "$restore_command" || true
if test -s "$RUNNER_TEMP/pink056-current-pid.txt"; then
  echo COLD_RESTORE_DISTINCT_PROCESS_PID=CAPTURED
else
  echo COLD_RESTORE_DISTINCT_PROCESS_PID=UNAVAILABLE
fi
}
run_restore true "$RUNNER_TEMP/pink056-restore.txt"
cat "$RUNNER_TEMP/pink056-restore.txt"
if ! grep -q 'OK (1 test)' "$RUNNER_TEMP/pink056-restore.txt"; then
  native_crash_diagnostics
  # A lost admitted VPN intentionally kills all app networking. Accept only
  # an exact fixed cause at the owned network phase, with exact PID/SIGKILL.
  # Every other crash remains a failure; no generic retry can certify it.
  adb shell run-as com.pinkiptv.extreme cat files/pink055-fail-closure-public.txt > "$RUNNER_TEMP/pink056-exit-boundary.txt"
  adb shell run-as com.pinkiptv.extreme cat files/pink055-restore-phase-public.txt > "$RUNNER_TEMP/pink056-network-phase.txt"
  adb shell dumpsys activity exit-info com.pinkiptv.extreme | python ops/pink_vpn_056_recovery.py "$RUNNER_TEMP/pink056-exit-boundary.txt" "$RUNNER_TEMP/pink056-network-phase.txt" "$(cat "$RUNNER_TEMP/pink056-current-pid.txt")"
  adb shell svc wifi enable
  run_restore false "$RUNNER_TEMP/pink056-reconnected.txt"
  cat "$RUNNER_TEMP/pink056-reconnected.txt"
  if ! grep -q 'OK (1 test)' "$RUNNER_TEMP/pink056-reconnected.txt" || ! grep -q 'POST_NETWORK_RESTART_SAME_KEY_AUTHORIZED_TUNNEL=PASS' "$RUNNER_TEMP/pink056-reconnected.txt"; then
    native_crash_diagnostics
    exit 1
  fi
  echo FAIL_CLOSED_PROCESS_RESTART_AND_NETWORK_RECOVERY=PASS
fi
sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-observe.py"
