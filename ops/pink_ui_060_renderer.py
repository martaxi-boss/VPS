"""Read-only, bounded CPU sampling of this disposable APK's local WebView.

No profile, page text, URLs or exception strings are persisted. Output contains
only fixed status and positions in this APK's own compiled JavaScript assets.
The existing app/UI proof deadlines and assertions are unchanged.
"""
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PACKAGE = 'com.pinkiptv.extreme'
MAX_FRAME = 8 * 1024 * 1024
IPC_FUNCTIONS = {name: label for name, label in (
    ('uid', 'UID'), ('getRandomValues', 'RANDOM'),
    ('registerCallback', 'REGISTER'), ('invoke', 'INVOKE'),
    ('action', 'ACTION'), ('sendIpcMessage', 'SEND'),
    ('processIpcMessage', 'SERIALIZE'), ('stringify', 'JSON'),
    ('postMessage', 'POST_MESSAGE'), ('Promise', 'PROMISE'),
    ('value', 'VALUE'), ('ipc', 'IPC'))}


def owned_frame(frame):
    url = urllib.parse.urlsplit(frame.get('url', ''))
    if url.scheme in ('http', 'https') and url.hostname == 'tauri.localhost' and re.fullmatch(r'/_astro/[A-Za-z0-9_.-]+\.js', url.path):
        # Positions identify static APK code. Never output function names: a
        # dynamically named callback could contain a runtime account value.
        return (url.path.rsplit('/', 1)[1],
                int(frame.get('lineNumber', -1)), int(frame.get('columnNumber', -1)))
    return None


def summarize(profile):
    nodes = {node['id']: node.get('callFrame', {}) for node in profile.get('nodes', [])}
    parents = {child:node['id'] for node in profile.get('nodes', []) for child in node.get('children', [])}
    counts = Counter()
    kinds = Counter()
    ipc_stacks = Counter()
    for sample in profile.get('samples', []):
        frame = nodes.get(sample, {})
        owned = owned_frame(frame)
        kind = 'OWNED_JS'
        if not owned:
            # A native leaf may be busy on behalf of static app JavaScript.
            # Retain its nearest owned callsite, without printing native names.
            parent = parents.get(sample)
            for _ in range(64):
                if parent is None:
                    break
                owned = owned_frame(nodes.get(parent, {}))
                if owned:
                    kind = 'OWNED_ANCESTOR'
                    break
                parent = parents.get(parent)
        if owned:
            counts[owned] += 1
            kinds[kind] += 1
            if owned[0].startswith('core.') and kind == 'OWNED_ANCESTOR':
                # Inspect only descendants of a static core callsite. Empty
                # source URLs identify injected/native IPC frames; fixed names
                # are mapped to enums and every other name is discarded.
                stack, current = [], sample
                for _ in range(12):
                    inner = nodes.get(current, {})
                    if owned_frame(inner):
                        break
                    if not inner.get('url'):
                        line = int(inner.get('lineNumber', -1))
                        column = int(inner.get('columnNumber', -1))
                        stack.append((IPC_FUNCTIONS.get(inner.get('functionName'), 'OTHER'), line, column))
                    current = parents.get(current)
                    if current is None:
                        break
                ipc_stacks[tuple(stack)] += 1
        else:
            name = frame.get('functionName', '')
            kinds[{'(idle)': 'IDLE', '(garbage collector)': 'GC', '(program)': 'PROGRAM'}.get(name, 'OTHER')] += 1
    return {'kind_samples': dict(kinds), 'ipc_stacks': [
        {'frames': [{'kind': kind, 'line': line, 'column': column} for kind,line,column in stack], 'samples': count}
        for stack,count in ipc_stacks.most_common(5)], 'owned_hotspots': [
        {'asset': key[0], 'line': key[1], 'column': key[2], 'samples': count}
        for key, count in counts.most_common(5)]}


class CDP:
    def __init__(self, url, port):
        parsed = urllib.parse.urlsplit(url)
        assert parsed.scheme == 'ws' and parsed.hostname in ('127.0.0.1', 'localhost') and parsed.port == port
        assert re.fullmatch(r'/devtools/page/[A-Za-z0-9_.-]+', parsed.path) and not parsed.query and not parsed.fragment
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=3)
        self.buffer = b''
        self.sequence = 0
        nonce = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f'GET {parsed.path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        response = b''
        deadline = time.monotonic() + 3
        while b'\r\n\r\n' not in response:
            self.sock.settimeout(max(.01, deadline-time.monotonic()))
            block = self.sock.recv(4096)
            if not block or len(response) > 65536:
                raise ValueError('handshake unavailable')
            response += block
        header, self.buffer = response.split(b'\r\n\r\n', 1)
        assert header.split(b'\r\n', 1)[0].split()[1] == b'101'
        headers = {line.split(b':',1)[0].lower():line.split(b':',1)[1].strip() for line in header.split(b'\r\n')[1:] if b':' in line}
        expected = base64.b64encode(hashlib.sha1((nonce+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert headers.get(b'sec-websocket-accept') == expected

    def close(self):
        self.sock.close()

    def send(self, payload, opcode=1):
        mask = os.urandom(4)
        length = len(payload)
        assert length <= MAX_FRAME
        header = bytes([128 | opcode])
        if length < 126:
            header += bytes([128 | length])
        elif length <= 65535:
            header += bytes([128 | 126]) + struct.pack('!H', length)
        else:
            header += bytes([128 | 127]) + struct.pack('!Q', length)
        self.sock.sendall(header + mask + bytes(value ^ mask[i%4] for i,value in enumerate(payload)))

    def read(self, size, deadline):
        while len(self.buffer) < size:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('bounded CDP wait')
            self.sock.settimeout(remaining)
            block = self.sock.recv(min(65536, size-len(self.buffer)))
            if not block:
                raise ValueError('CDP closed')
            self.buffer += block
        value, self.buffer = self.buffer[:size], self.buffer[size:]
        return value

    def message(self, deadline):
        data = bytearray()
        while True:
            first, second = self.read(2, deadline)
            assert not second & 128
            size = second & 127
            if size == 126:
                size = struct.unpack('!H', self.read(2, deadline))[0]
            elif size == 127:
                size = struct.unpack('!Q', self.read(8, deadline))[0]
            if size > MAX_FRAME or len(data)+size > MAX_FRAME:
                raise ValueError('profile bound')
            payload = self.read(size, deadline)
            opcode = first & 15
            if opcode == 9:
                self.send(payload, 10)
                continue
            if opcode == 8:
                raise ValueError('CDP closed')
            assert opcode in (0,1)
            data.extend(payload)
            if first & 128:
                return json.loads(data)

    def call(self, method, params=None):
        self.sequence += 1
        self.send(json.dumps({'id':self.sequence,'method':method,'params':params or {}}).encode())
        deadline = time.monotonic()+3
        while True:
            response = self.message(deadline)
            if response.get('id') == self.sequence:
                if 'error' in response:
                    raise ValueError('CDP command unavailable')
                return response.get('result', {})


def adb(*args):
    result = subprocess.run(['adb', *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
    return result.stdout.decode('utf-8', errors='replace').strip() if result.returncode == 0 else ''


def interrupted(*_):
    raise InterruptedError('observer stopped')


def main():
    stop = Path(sys.argv[1])
    port = None
    cdp = None
    status = 'UNAVAILABLE'
    try:
        signal.signal(signal.SIGTERM, interrupted)
        deadline = time.monotonic()+150
        # Start before the UI navigation, using only its fixed public phase file.
        while time.monotonic() < deadline and not stop.exists():
            phase = adb('shell','run-as',PACKAGE,'cat','files/pink055-live-phase-public.txt')
            match = re.fullmatch(r'([0-9]+):webview-login-catalog', phase)
            if match:
                break
            time.sleep(.25)
        else:
            status = 'NO_UI_PHASE'
            return
        pid = match.group(1)
        forwarded = adb('forward','--no-rebind','tcp:0',f'localabstract:webview_devtools_remote_{pid}')
        assert forwarded.isdigit() and 1024 <= int(forwarded) <= 65535
        port = int(forwarded)
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/json', timeout=3) as reply:
            pages = json.loads(reply.read(1024*1024))
        page = next(page for page in pages if page.get('type') == 'page' and urllib.parse.urlsplit(page.get('url','')).hostname == 'tauri.localhost')
        cdp = CDP(page['webSocketDebuggerUrl'], port)
        cdp.call('Profiler.enable')
        cdp.call('Profiler.setSamplingInterval', {'interval':1000})
        cdp.call('Profiler.start')
        # Cover the failed evaluator interval too; app deadlines are unchanged.
        # The proof stopfile ends sampling immediately when the app test exits.
        sample_end = time.monotonic()+60
        while time.monotonic()<sample_end and not stop.exists():
            time.sleep(.1)
        profile = cdp.call('Profiler.stop').get('profile', {})
        summary = summarize(profile)
        print('ACTUAL_UI_RENDERER_CPU_FIXED_PROFILE='+json.dumps(summary,separators=(',',':')), flush=True)
        status = 'SAMPLED' if profile.get('samples') else 'NO_SAMPLES'
    except (Exception, KeyboardInterrupt):
        # Never emit transport/profile exceptions, targets, command arguments or data.
        pass
    finally:
        if cdp:
            cdp.close()
        if port:
            try:
                adb('forward','--remove',f'tcp:{port}')
            except Exception:
                pass
        print('ACTUAL_UI_RENDERER_CPU_PROFILE_STATUS='+status, flush=True)


if __name__ == '__main__':
    main()
