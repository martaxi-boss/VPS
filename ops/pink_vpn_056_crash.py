"""Allowlisted crash structure only. Never forward Android log messages or URLs."""
import re
import sys

PREFIXES = ('java.', 'android.', 'androidx.', 'com.pinkiptv.extreme.', 'com.wireguard.', 'kotlin.', 'org.json.')
LIBRARIES = {'libc.so', 'libart.so', 'libandroid.so', 'libmonochrome.so', 'libwebviewchromium.so', 'libwg-go.so', 'libapp.so', 'libpink_iptv.so'}

def public_crash(lines):
    records = []
    for line in lines:
        match = re.search(r'(?:^|\s)[EF]\s+(?:AndroidRuntime|DEBUG|libc)\s*:\s*(.*)$', line)
        if not match:
            continue
        message = match.group(1).strip()
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

if __name__ == '__main__':
    records = public_crash(sys.stdin)
    print('PUBLIC_CRASH_DIAGNOSTIC=' + ('STRUCTURE_ONLY' if records else 'NO_ALLOWED_RECORDS'))
    print('\n'.join(records))
