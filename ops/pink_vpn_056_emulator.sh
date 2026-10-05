#!/usr/bin/env bash
set -euo pipefail
umask 077
ssh_args=(-T -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
fixture="$RUNNER_TEMP/pink056-account.json"
native_crash_diagnostics() {
  # Wait only for debuggerd's asynchronous trace publication, never publish raw data.
  sleep 3
  pink_crash_pid=$(adb shell run-as com.pinkiptv.extreme cat files/pink055-process-public.txt 2>/dev/null | tr -d '\r\n')
  case "$pink_crash_pid" in
    ''|*[!0-9]*) echo PUBLIC_CRASH_DIAGNOSTIC=NO_TARGET_PID ;;
    *) adb logcat -b all -d 2>/dev/null | python ops/pink_vpn_056_crash.py --pid "$pink_crash_pid" ;;
  esac
  if [[ "$pink_crash_pid" =~ ^[0-9]+$ ]]; then
    adb shell dumpsys activity exit-info com.pinkiptv.extreme 2>/dev/null | python ops/pink_vpn_056_crash.py --exit-pid "$pink_crash_pid"
    adb logcat -b all -d 2>/dev/null | python ops/pink_vpn_056_crash.py --system-pid "$pink_crash_pid"
  fi
}
cleanup() {
  result=$?
  trap - EXIT
  set +e
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
for name in ('pink056-account.json','pink056-public.txt','pink056-clean.py','pink056-observe.py','pink056-fetch.py'):
    Path(os.environ['RUNNER_TEMP'],name).unlink(missing_ok=True)
PY
  if test "$result" = 0; then echo REAL_ANDROID_PROOF_AND_BOUNDED_PEER_CLEANUP=PASS; fi
  exit "$result"
}
trap cleanup EXIT
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
  exit 1
fi
# A new application process receives no account fixture or technical input.
# The EXIT trap still owns cleanup of this exact disposable installation.
adb shell am force-stop com.pinkiptv.extreme
adb shell am instrument -w -r -e class com.pinkiptv.extreme.PinkVpnRestoreTest com.pinkiptv.extreme.test/androidx.test.runner.AndroidJUnitRunner > "$RUNNER_TEMP/pink056-restore.txt"
cat "$RUNNER_TEMP/pink056-restore.txt"
if ! grep -q 'OK (1 test)' "$RUNNER_TEMP/pink056-restore.txt"; then
  native_crash_diagnostics
  exit 1
fi
sshpass -e ssh "${ssh_args[@]}" ubuntu@146.59.145.3 'sudo -n python3 -' < "$RUNNER_TEMP/pink056-observe.py"
