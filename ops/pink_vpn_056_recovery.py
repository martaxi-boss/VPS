"""Recognize only evidenced PINK fail closure during the owned Wi-Fi proof."""
import re
import sys
from pathlib import Path
from pink_vpn_056_crash import public_exit

def outage_boundary(record, phase, pid, exit_lines):
    match = re.fullmatch(r'([0-9]+):(VPN_LOST|RECOVERY_EXHAUSTED)', record.strip())
    if not match or int(match[1]) != pid:
        return None
    if phase.strip() not in {'WIFI_DISABLING', 'WIFI_DISABLED', 'WIFI_ENABLING'}:
        return None
    if public_exit(exit_lines, pid) != ['EXIT_REASON=SIGNALED', 'EXIT_STATUS=9']:
        return None
    return match[2]

if __name__ == '__main__':
    if len(sys.argv) != 4 or not sys.argv[3].isdigit():
        raise SystemExit('FAIL_CLOSED_NETWORK_PROCESS_BOUNDARY=UNVERIFIED')
    reason = outage_boundary(Path(sys.argv[1]).read_text(), Path(sys.argv[2]).read_text(),
                             int(sys.argv[3]), sys.stdin)
    if reason is None:
        raise SystemExit('FAIL_CLOSED_NETWORK_PROCESS_BOUNDARY=UNVERIFIED')
    print('FAIL_CLOSED_NETWORK_PROCESS_BOUNDARY='+reason)
