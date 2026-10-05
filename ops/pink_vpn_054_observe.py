"""Read-only accepted-runtime audit. No peer, key, route or service mutation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import urllib.error
import urllib.request


def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15).stdout.strip()


def observe(expected):
    assert os.geteuid() == 0 and run('hostname') == 'vps-32bea5b6'
    for name,digest in expected.items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest
    print('EXACT_ACCEPTED_GATEWAY_AND_BACKEND_SOURCE=PASS')
    for service in ('ssh','nginx','postgresql','pink-iptv-backend','lowcost-europa','pink-vpn'):
        run('systemctl','is-active','--quiet',service)
    assert Path('/var/backups/pink-iptv/task052/accepted').is_file()
    assert subprocess.run(['systemctl','is-active','--quiet','pink-vpn-052-rollback.timer'],
                          capture_output=True,timeout=5).returncode != 0
    assert run('wg','show','interfaces') == 'pinkvpn'
    private = Path('/etc/pink-vpn/server.key')
    assert stat.S_IMODE(private.stat().st_mode) == 0o600 and private.stat().st_uid == 0
    assert stat.S_IMODE(private.parent.stat().st_mode) == 0o700
    stored_public = subprocess.run(['wg','pubkey'],input=private.read_text(),
        check=True,capture_output=True,text=True,timeout=5).stdout.strip()
    assert stored_public == run('wg','show','pinkvpn','public-key')
    assert len(base64.b64decode(stored_public,validate=True)) == 32
    print('PROTECTED_PERSISTENT_TASK052_IDENTITY=PASS')
    assert Path('/run/pink-vpn/control.sock').is_socket()
    assert stat.S_IMODE(Path('/run/pink-vpn/control.sock').stat().st_mode) == 0o660
    assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1'
    assert Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip() == '0'
    rules = run('iptables','-w','5','-t','filter','-S')
    assert '-P INPUT DROP' in rules and '-P FORWARD DROP' in rules
    for rule in ('-A INPUT -j PINK052_IN','-A FORWARD -j PINK052_FWD',
                 '-A PINK052_IN -i pinkvpn -j DROP','-A PINK052_FWD -i pinkvpn -j DROP',
                 '-A PINK052_FWD -o pinkvpn -j DROP'):
        assert rule in rules
    assert '-A POSTROUTING -j PINK052_NAT' in run('iptables','-w','5','-t','nat','-S')
    print('OWNED_ROUTING_NAT_AND_PROTECTED_SERVICES=PASS')
    assert run('curl','-sS','--max-time','5','-o','/dev/null','-w','%{http_code}',
               'http://127.0.0.1:8010/openapi.json') == '200'
    public = base64.b64encode(os.urandom(32)).decode()
    body = json.dumps({'public_key':public}).encode()
    request = urllib.request.Request('https://pink-iptv.duckdns.org/v1/vpn/enroll',
        data=body,headers={'Content-Type':'application/json'},method='POST')
    try:
        urllib.request.urlopen(request,timeout=10)
        raise AssertionError('Unauthenticated enrollment admitted')
    except urllib.error.HTTPError as error:
        assert error.code == 401 and error.headers.get('Cache-Control') == 'no-store'
    print('REAL_HTTPS_ENROLLMENT_REQUIRES_AUTHORITY=PASS')


if __name__ == '__main__':
    observe(EXPECTED_PUBLIC_SOURCE)  # Injected public manifest by the workflow.
