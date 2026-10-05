"""Read-only gateway preflight; print structural evidence only, never environments/keys."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout.strip()


def audit():
    assert os.geteuid() == 0 and run('hostname') == 'vps-32bea5b6'
    for service in ('ssh', 'nginx', 'postgresql', 'pink-iptv-backend', 'lowcost-europa'):
        run('systemctl', 'is-active', '--quiet', service)
    assert run('curl', '-sS', '--max-time', '8', '-o', '/dev/null', '-w', '%{http_code}',
               'http://127.0.0.1:8010/openapi.json') == '200'
    run('pg_isready', '-h', '127.0.0.1', '-p', '5432', '-t', '3')
    assert not run('wg', 'show', 'interfaces')
    assert not run('ss', '-H', '-lun', 'sport = :51820')
    retained = Path('/etc/pink-vpn').exists()
    if retained:
        backup = Path('/var/backups/pink-iptv/task052')
        assert (backup/'rolled-back').is_file() and not (backup/'accepted').exists()
        assert Path('/etc/pink-vpn/server.key').stat().st_mode & 0o777 == 0o600
        assert Path('/etc/pink-vpn').stat().st_uid == 0
    subnet = ipaddress.ip_network('10.66.0.0/24')
    for row in json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all')):
        dst = row.get('dst', 'default')
        if dst != 'default':
            assert not subnet.overlaps(ipaddress.ip_network(dst, strict=False))
    firewall = '\n'.join(tool + table + run(tool, '-w', '5', '-t', table, '-S')
                         for tool in ('iptables', 'ip6tables') for table in ('filter','nat','mangle','raw'))
    assert '-P INPUT DROP' in firewall and '-P FORWARD DROP' in firewall
    assert not any(name in firewall for name in ('PINK052_IN','PINK052_FWD','PINK052_NAT'))
    if retained:
        baseline = json.loads((backup/'baseline.json').read_text())
        assert hashlib.sha256(firewall.encode()).hexdigest() == baseline['firewall_sha256']
        assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == baseline['forward']
        assert all(Path(p).read_text().strip() == value for p,value in baseline['ipv4_conf'].items())
        print('RETAINED_OWNED_IDENTITY_EXACT_ROLLBACK_VERIFIED=PASS')
    print('PROTECTED_SERVICES_AND_BACKEND=PASS')
    print('UNCONFLICTED_SUBNET_PORT_INTERFACE=PASS')
    print('FIREWALL_BASELINE_SHA256=' + hashlib.sha256(firewall.encode()).hexdigest())
    print('IPV4_FORWARD=' + Path('/proc/sys/net/ipv4/ip_forward').read_text().strip())
    print('IPV6_FORWARD=' + Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip())
    print('BACKEND_USER=' + run('systemctl','show','pink-iptv-backend','-p','User','--value'))
    print('BACKEND_GROUP=' + run('systemctl','show','pink-iptv-backend','-p','Group','--value'))
    print('BACKEND_WORKDIR=' + run('systemctl','show','pink-iptv-backend','-p','WorkingDirectory','--value'))
    # Only filenames, no environment values or customer/peer data.
    print('BACKEND_ENVIRONMENT_FILE=' + run('systemctl','show','pink-iptv-backend','-p','EnvironmentFiles','--value'))
    print('DEFAULT_EGRESS=' + json.loads(run('ip','-j','route','show','default'))[0]['dev'])
    print('AUTOMATION_PREFLIGHT_052=PASS')


if __name__ == '__main__':
    audit()
