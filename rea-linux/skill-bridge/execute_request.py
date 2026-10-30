#!/usr/bin/env python3
"""GitHub Actions -> SSH -> original REA MCP over stdio.

Only transport: no tool catalog, vendor selector, shell command execution,
or second analysis engine lives in this file. REA validates MCP tool inputs.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/ubuntu/rea-original-upstream-680')
RUNTIME = Path('/home/ubuntu/rea-final-runtime')
NODE = RUNTIME / 'vendors/providers/node-v24.22.1/bin/node'


def read_request(raw):
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {'request_id', 'mcp_requests'}:
        raise ValueError('Expected request_id and mcp_requests')
    if not isinstance(request['request_id'], str) or not re.fullmatch(r'[A-Za-z0-9._-]{8,80}', request['request_id']):
        raise ValueError('Invalid request_id')
    calls = request['mcp_requests']
    if not isinstance(calls, list) or not calls:
        raise ValueError('mcp_requests must be a nonempty array')
    for call in calls:
        if not isinstance(call, dict) or set(call) - {'method', 'params'}:
            raise ValueError('Each request needs MCP method and optional params')
        if not isinstance(call.get('method'), str) or not call['method']:
            raise ValueError('Invalid MCP method')
        if 'params' in call and not isinstance(call['params'], dict):
            raise ValueError('MCP params must be an object')
    return request


def run_mcp(request):
    with tempfile.TemporaryDirectory(prefix='rea-final-mcp-', dir='/tmp') as home:
        env = dict(os.environ)
        for key in list(env):
            if key.startswith('REA_') or key in ('JAVA_HOME', 'GHIDRA_INSTALL_DIR', 'VIRTUAL_ENV', 'PYTHONPATH', 'PYTHONHOME', 'HOPPER_LAUNCHER_PATH'):
                env.pop(key, None)
        env.update({
            'HOME': home, 'TMPDIR': home,
            'XDG_CONFIG_HOME': home + '/.config',
            'XDG_CACHE_HOME': home + '/.cache',
            'PATH': str(RUNTIME / 'vendors/tools/jdk-21/bin') + ':' + str(NODE.parent)
                    + ':' + str(RUNTIME / 'vendors/providers/binwalk-3.1.0/bin') + ':' + env.get('PATH', ''),
            'JAVA_HOME': str(RUNTIME / 'vendors/tools/jdk-21'),
            'GHIDRA_INSTALL_DIR': str(RUNTIME / 'vendors/tools/ghidra_12.1.4_PUBLIC'),
            'REA_JADX_MCP_JAR': str(RUNTIME / 'vendors/tools/jadx-headless-mcp-0.7.1-all.jar'),
            'REA_UNBLOB_COMMAND': str(RUNTIME / 'bin/unblob'),
            'REA_BINWALK_COMMAND': str(RUNTIME / 'vendors/providers/binwalk-3.1.0/bin/binwalk'),
            'CI': '1',
        })
        with tempfile.TemporaryFile(mode='w+b') as stderr:
            process = subprocess.Popen(
                [str(NODE), 'scripts/rea.mjs', 'mcp'],
                cwd=str(ROOT), env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=stderr,
                start_new_session=True,
            )
            pending = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)

                def send(message):
                    data = json.dumps(message, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
                    process.stdin.write(data)
                    process.stdin.flush()

                def receive(expected_id, seconds):
                    deadline = time.monotonic() + seconds
                    while True:
                        while b'\n' in pending:
                            line, _, tail = pending.partition(b'\n')
                            pending[:] = tail
                            if not line.strip():
                                continue
                            msg = json.loads(line)
                            if isinstance(msg, dict) and msg.get('id') == expected_id:
                                return msg
                            # Progress and other protocol notifications are not tool results.
                        if process.poll() is not None:
                            stderr.seek(0)
                            raise RuntimeError('REA MCP exited: ' + stderr.read()[-800:].decode(errors='replace'))
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('REA MCP response deadline exceeded')
                        if selector.select(timeout=min(remaining, 1)):
                            data = os.read(process.stdout.fileno(), 65536)
                            if not data:
                                raise RuntimeError('REA MCP closed stdout')
                            pending.extend(data)

                try:
                    send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                        'protocolVersion': '2025-03-26', 'capabilities': {},
                        'clientInfo': {'name': 'engenharia-reversa-final', 'version': '1.0'}}})
                    init = receive(1, 90)
                    if 'error' in init:
                        raise RuntimeError('REA MCP initialization failed: ' + str(init['error'])[:300])
                    send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                    responses = []
                    for index, entry in enumerate(request['mcp_requests']):
                        message = {'jsonrpc': '2.0', 'id': index + 2, 'method': entry['method']}
                        if 'params' in entry:
                            message['params'] = entry['params']
                        send(message)
                        reply = receive(index + 2, 800)
                        responses.append({'method': entry['method'], 'response': reply})
                    return responses
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def emit(report):
    document = json.dumps(report, ensure_ascii=True, separators=(',', ':'))
    if len(document) <= 12000:
        print('REA_SKILL_BRIDGE_RESULT=' + document, flush=True)
        return
    chunk_size = 6000
    parts = [document[i:i + chunk_size] for i in range(0, len(document), chunk_size)]
    for index, part in enumerate(parts, 1):
        print('REA_MCP_RESULT_PART=' + str(index) + '/' + str(len(parts)) + ':' + part, flush=True)
    print('REA_SKILL_BRIDGE_RESULT=' + json.dumps({
        'request_id': report['request_id'], 'status': report['status'],
        'methods': [item['method'] for item in report.get('responses', [])],
        'parts': len(parts), 'encoding': 'utf8-json-parts',
        'sha256': hashlib.sha256(document.encode()).hexdigest(),
    }, separators=(',', ':')), flush=True)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('--validate-request', '--base64'):
        print('REA_SKILL_BRIDGE=INVALID_USAGE')
        return 2
    try:
        if sys.argv[1] == '--validate-request':
            request = read_request(Path(sys.argv[2]).read_bytes())
            print('REA_SKILL_REQUEST_VALID=PASS;request_id=' + request['request_id'])
            return 0
        request = read_request(base64.b64decode(sys.argv[2], validate=True))
        responses = run_mcp(request)
        ok = all('error' not in row['response'] and not (isinstance(row['response'].get('result'), dict) and row['response']['result'].get('isError')) for row in responses)
        emit({'request_id': request['request_id'], 'status': 'PASS' if ok else 'FAIL',
              'transport': 'ssh-to-original-rea-mcp-stdio', 'responses': responses})
        return 0 if ok else 4
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        emit({'request_id': request.get('request_id', 'invalid') if 'request' in locals() else 'invalid',
              'status': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)[:600]})
        return 3


if __name__ == '__main__':
    sys.exit(main())
