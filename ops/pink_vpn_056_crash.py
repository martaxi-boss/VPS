"""Allowlisted crash structure only. Never forward Android log messages or URLs."""
import re
import sys

PREFIXES = ('java.', 'android.', 'androidx.', 'com.pinkiptv.extreme.', 'com.wireguard.', 'kotlin.', 'org.json.')
LIBRARIES = {'libc.so', 'libart.so', 'libandroid.so', 'libmonochrome.so', 'libwebviewchromium.so', 'libwg-go.so', 'libapp.so', 'libapp_lib.so', 'libdatastore_shared_counter.so', 'libpink_iptv.so', 'libxtream.so', 'libhwui.so', 'libandroid_runtime.so', 'libgui.so', 'libnativewindow.so', 'libEGL.so', 'libGLESv2.so', 'libcodec2_soft_avcdec.so', 'libmediandk.so', 'libbinder.so', 'libutils.so', 'libc++.so'}

def public_crash(lines, target_pid=None):
    records = []
    native_target = False
    for line in lines:
        match = re.search(r'(?:^|\s)[EF]\s+(?:AndroidRuntime|DEBUG|libc)\s*:\s*(.*)$', line)
        if not match:
            continue
        message = match.group(1).strip()
        if target_pid is not None:
            log_pid = re.match(r'^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+([0-9]+)\s+[0-9]+\s+[EF]\s', line)
            if message.startswith('*** ***'):
                native_target = False
            native_pid = re.match(r'^pid: ([0-9]+),', message)
            if native_pid:
                native_target = int(native_pid[1]) == target_pid
            own = log_pid is not None and int(log_pid[1]) == target_pid
            if not own and not (native_target and re.search(r'(?:^|\s)[EF]\s+DEBUG\s*:', line)):
                continue
        exception = re.match(r'^(?:Caused by: )?([A-Za-z_$][\w.$]*(?:Exception|Error))(?::|$)', message)
        if exception and exception[1].startswith(PREFIXES):
            records.append('EXCEPTION_CLASS=' + exception[1])
        frame = re.fullmatch(r'at ([A-Za-z_$][\w.$]*)\(([\w.$]+):([0-9]+)\)', message)
        if frame and frame[1].startswith(PREFIXES):
            records.append('STACK=' + frame[1] + '(' + frame[2] + ':' + frame[3] + ')')
        if message.startswith('FORTIFY: pthread_mutex_lock called on a destroyed mutex'):
            records.append('NATIVE_DESTROYED_MUTEX')
        signal = re.match(r'^Fatal signal ([0-9]+) \((SIG[A-Z]+)\)', message)
        if signal and signal[2] in {'SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGFPE', 'SIGTRAP'}:
            records.append('NATIVE_SIGNAL=' + signal[1] + ':' + signal[2])
        native = re.match(r'^#([0-9]+) pc [0-9a-f]+\s+(\S+)', message)
        if native and native[2].rsplit('/', 1)[-1] in LIBRARIES:
            records.append('NATIVE_FRAME=' + native[1] + ':' + native[2].rsplit('/', 1)[-1])
    return list(dict.fromkeys(records))[:80]

def public_exit(lines, target_pid=None):
    reasons={1:'EXIT_SELF',2:'SIGNALED',3:'LOW_MEMORY',4:'CRASH',5:'CRASH_NATIVE',6:'ANR',7:'INITIALIZATION_FAILURE',8:'PERMISSION_CHANGE',9:'EXCESSIVE_RESOURCE_USAGE',10:'USER_REQUESTED',11:'USER_STOPPED',12:'DEPENDENCY_DIED',13:'OTHER',14:'FREEZER',15:'PACKAGE_STATE_CHANGE',16:'PACKAGE_UPDATED'}
    records=[]
    selected = target_pid is None
    for line in lines:
        if 'ApplicationExitInfo ' in line:
            selected = target_pid is None
        metadata = re.fullmatch(r'\s*timestamp=[0-9: .-]+ pid=([0-9]+) realUid=[0-9]+ packageUid=[0-9]+ definingUid=[0-9]+ user=[0-9]+\s*', line.rstrip('\n'))
        if metadata and target_pid is not None:
            selected = int(metadata[1]) == target_pid
        if not selected:
            continue
        if target_pid is not None and not re.fullmatch(r'\s*process=com\.pinkiptv\.extreme reason=[0-9]+ \([^)]*\) subreason=[0-9]+ \([^)]*\) status=[0-9]+\s*', line.rstrip('\n')):
            continue
        reason=re.search(r'(?:^|\s)reason=([0-9]+)\s+\(',line)
        if reason and int(reason[1]) in reasons:
            records.append('EXIT_REASON='+reasons[int(reason[1])])
            status=re.search(r'\sstatus=([0-9]+)(?:\s|$)',line)
            if status and 0 <= int(status[1]) <= 255:
                records.append('EXIT_STATUS='+status[1])
    return list(dict.fromkeys(records))[:16]

def public_system(lines, target_pid):
    records=[]
    for line in lines:
        if re.search(r"\b(?:lmkd|lowmemorykiller)\s*:.*Kill 'com\.pinkiptv\.extreme' \("+str(target_pid)+r'\)',line):
            records.append('SYSTEM_KILL=LOW_MEMORY_KILLER')
        killed=re.search(r'\bActivityManager\s*: Killing '+str(target_pid)+r':com\.pinkiptv\.extreme/[^ :]+.*?: (.*)$',line)
        if killed:
            records.append('SYSTEM_KILL=ACTIVITY_MANAGER')
            reason=killed[1].lower()
            for prefix,label in [('too many cached','CACHED_LIMIT'),('empty','EMPTY_PROCESS'),('anr','ANR'),('excessive cpu','EXCESSIVE_CPU'),('low memory','LOW_MEMORY'),('remove task','REMOVE_TASK'),('stop','STOP'),('crash','CRASH')]:
                if reason.startswith(prefix):
                    records.append('SYSTEM_KILL_CATEGORY='+label)
                    break
    return list(dict.fromkeys(records))[:16]

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--exit-pid' and sys.argv[2].isdigit():
        records = public_exit(sys.stdin,int(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == '--system-pid' and sys.argv[2].isdigit():
        records = public_system(sys.stdin,int(sys.argv[2]))
    elif sys.argv[1:] == ['--exit-info']:
        records = public_exit(sys.stdin)
    elif len(sys.argv) == 3 and sys.argv[1] == '--pid' and sys.argv[2].isdigit():
        records = public_crash(sys.stdin, int(sys.argv[2]))
    elif len(sys.argv) == 1:
        records = public_crash(sys.stdin)
    else:
        raise SystemExit('PUBLIC_CRASH_DIAGNOSTIC=INVALID_ARGUMENTS')
    print('PUBLIC_CRASH_DIAGNOSTIC=' + ('STRUCTURE_ONLY' if records else 'NO_ALLOWED_RECORDS'))
    print('\n'.join(records))
