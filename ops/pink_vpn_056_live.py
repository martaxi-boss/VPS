"""Fixed PID-bound live instrumentation diagnostics; never emit raw app records."""
import re,sys
from pathlib import Path
PHASES={'fixture','normal-consent','offline-capture','protected-login-enrollment','authoritative-catalog','native-audio-video','activity-recreation'}
REASONS={'VPN_LOST','GRANT_EXPIRED','RECOVERY_EXHAUSTED'}
def fixed_live_diagnostics(phase_record,reason_record,pid):
    result=[]
    match=re.fullmatch(r'([0-9]+):([a-z-]+)',phase_record.strip())
    if match and match[1]==str(pid) and match[2] in PHASES:
        result.append('LIVE_FLOW_PHASE='+match[2])
    else: result.append('LIVE_FLOW_PHASE=UNVERIFIED')
    match=re.fullmatch(r'([0-9]+):([A-Z_]+)',reason_record.strip())
    if match and match[1]==str(pid) and match[2] in REASONS:
        result.append('LIVE_FAIL_CLOSED_CAUSE='+match[2])
    else: result.append('LIVE_FAIL_CLOSED_CAUSE=UNVERIFIED')
    return result
if __name__=='__main__':
    if len(sys.argv)!=4: raise SystemExit('LIVE_FLOW_DIAGNOSTIC=UNVERIFIED')
    def read(path):
        try: return Path(path).read_text()
        except OSError: return ''
    for item in fixed_live_diagnostics(read(sys.argv[1]),read(sys.argv[2]),sys.argv[3]): print(item)
