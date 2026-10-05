"""Root-owned public-key-only peer controller. Server private key stays on this host."""
import base64
import grp
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import threading
import time

ROOT = Path('/etc/pink-vpn')
STATE = Path('/var/lib/pink-vpn')
SOCKET = Path('/run/pink-vpn/control.sock')
IFACE = 'pinkvpn'
LEASE_MAX = 300


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout.strip()


def validate(payload, caller_uid, backend_uid, now):
    if not isinstance(payload, dict) or set(payload) != {'operation','public_key','address','expires_at'}:
        raise ValueError('Unsupported message')
    if caller_uid not in {0, backend_uid}:
        raise ValueError('Unauthorized caller')
    if payload['operation'] not in {'upsert', 'remove'}:
        raise ValueError('Unsupported operation')
    raw = base64.b64decode(payload['public_key'], validate=True)
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != payload['public_key']:
        raise ValueError('Invalid public key')
    address = ipaddress.ip_address(payload['address'])
    subnet = ipaddress.ip_network('10.66.0.0/24')
    if address not in subnet or int(str(address).split('.')[-1]) not in range(3,255):
        if not (caller_uid == 0 and str(address) == '10.66.0.2'):
            raise ValueError('Invalid peer address')
    deadline = payload['expires_at']
    if not isinstance(deadline, (int,float)):
        raise ValueError('Invalid lease')
    if payload['operation'] == 'upsert' and not now < deadline <= now + LEASE_MAX + 5:
        raise ValueError('Invalid lease')
    return str(address)


class Controller:
    def __init__(self, backend_uid):
        self.backend_uid = backend_uid
        self.peers = {}
        self.lock = threading.Lock()

    def persist(self):
        temp = STATE / 'peers.next'
        temp.write_text(json.dumps(self.peers))
        os.chmod(temp, 0o600)
        temp.replace(STATE / 'peers.json')

    def apply(self, payload, uid):
        address = validate(payload, uid, self.backend_uid, time.time())
        public = payload['public_key']
        with self.lock:
            if payload['operation'] == 'upsert':
                for other, value in self.peers.items():
                    if other != public and value['address'] == address:
                        raise ValueError('Address already assigned')
                run('wg','set',IFACE,'peer',public,'allowed-ips',address+'/32')
                self.peers[public] = {'address':address, 'expires_at':payload['expires_at']}
            else:
                run('wg','set',IFACE,'peer',public,'remove')
                self.peers.pop(public, None)
            self.persist()

    def expire(self):
        while True:
            with self.lock:
                expired = [key for key, value in self.peers.items() if value['expires_at'] <= time.time()]
                for key in expired:
                    try:
                        run('wg','set',IFACE,'peer',key,'remove')
                        del self.peers[key]
                    except Exception:
                        # Stop interface rather than keep an expired authorization alive.
                        try:
                            run('ip','link','set',IFACE,'down')
                        finally:
                            # Exit the process so systemd starts from zero authorized peers.
                            os._exit(1)
                if expired:
                    self.persist()
            time.sleep(1)


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        address = ipaddress.ip_address(self.client_address[0])
        if self.path != '/health' or address not in ipaddress.ip_network('10.66.0.0/24'):
            self.send_error(403)
            return
        self.send_response(200)
        self.send_header('Content-Length','14')
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(b'PINK_VPN_READY')

    def log_message(self, *args):
        pass


def serve():
    assert os.geteuid() == 0
    os.umask(0o077)
    backend_uid = pwd.getpwnam('pink-iptv').pw_uid
    controller = Controller(backend_uid)
    # A daemon restart starts from zero live peers: clients refresh explicitly.
    for key in run('wg','show',IFACE,'peers').splitlines():
        run('wg','set',IFACE,'peer',key,'remove')
    controller.persist()
    threading.Thread(target=controller.expire, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(('10.66.0.1',51821),Health).serve_forever,daemon=True).start()
    SOCKET.parent.mkdir(mode=0o750, exist_ok=True)
    os.chown(SOCKET.parent, 0, grp.getgrnam('pink-iptv').gr_gid)
    if SOCKET.exists():
        if not SOCKET.is_socket() or SOCKET.is_symlink():
            raise ValueError('Unexpected socket path')
        SOCKET.unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(SOCKET))
        os.chown(SOCKET,0,grp.getgrnam('pink-iptv').gr_gid)
        os.chmod(SOCKET,0o660)
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                try:
                    _, uid, _ = struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    raw = connection.makefile('rb').readline(2049)
                    if len(raw) > 2048 or not raw.endswith(b'\n'):
                        raise ValueError('Message limit')
                    controller.apply(json.loads(raw),uid)
                    connection.sendall(b'{"ok":true}\n')
                except Exception:
                    connection.sendall(b'{"ok":false}\n')


if __name__ == '__main__':
    serve()
