"""Isolated staging installation with an exact additive inverse armed first."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

ROOT = Path('/etc/pink-vpn')
BACKUP = Path('/var/backups/pink-iptv/task052')
APP = Path('/srv/pink-iptv/backend')
DROP = Path('/etc/systemd/system/pink-iptv-backend.service.d/052-vpn.conf')
SYSCTL = Path('/etc/sysctl.d/90-pink-vpn.conf')
UNIT = Path('/etc/systemd/system/pink-vpn.service')
IFACE = 'pinkvpn'
SERVICES = ('ssh','nginx','postgresql','pink-iptv-backend','lowcost-europa')


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30).stdout.strip()


def ipt(table, *args):
    return run('iptables','-w','5','-t',table,*args)


def health():
    for service in SERVICES:
        run('systemctl','is-active','--quiet',service)
    assert run('curl','-sS','--max-time','8','-o','/dev/null','-w','%{http_code}',
               'http://127.0.0.1:8010/openapi.json') == '200'
    run('pg_isready','-h','127.0.0.1','-p','5432','-t','3')


def wait_health():
    for _ in range(25):
        try:
            health()
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError('Protected runtime health unavailable')


def firewall():
    return '\n'.join(t + table + run(t,'-w','5','-t',table,'-S')
                     for t in ('iptables','ip6tables') for table in ('filter','nat','mangle','raw'))


def conf4():
    return {str(p):p.read_text().strip() for p in Path('/proc/sys/net/ipv4/conf').glob('*/*') if p.is_file()}


def network_down():
    # ExecStopPost runs this function: never stop the unit recursively here.
    run('ip','link','delete',IFACE,check=False)
    # Remove exact hooks and each owned entry, never flush another chain/table.
    for table, hook, chain in [('filter','INPUT','PINK052_IN'),('filter','FORWARD','PINK052_FWD'),
                                ('nat','POSTROUTING','PINK052_NAT')]:
        run('iptables','-w','5','-t',table,'-D',hook,'-j',chain,check=False)
        lines = run('iptables','-w','5','-t',table,'-S',chain,check=False).splitlines()
        import shlex
        for line in reversed(lines):
            args = shlex.split(line)
            if args[:2] == ['-A',chain]:
                ipt(table,'-D',*args[1:])
        run('iptables','-w','5','-t',table,'-X',chain,check=False)


def rollback():
    assert BACKUP.is_dir()
    run('systemctl','disable','--now','pink-vpn.service',check=False)
    network_down()
    for p in (DROP, SYSCTL, UNIT, Path('/etc/pink-iptv/vpn.env')):
        if p.exists(): p.unlink()
    meta = json.loads((BACKUP / 'baseline.json').read_text())
    run('sysctl','-qw','net.ipv4.ip_forward='+meta['forward'])
    # Kernel forwarding toggles reset other IPv4 defaults; restore captured values.
    for name, value in meta['ipv4_conf'].items():
        path = Path(name)
        if path.exists() and path.read_text().strip() != value:
            path.write_text(value+'\n')
    assert all(conf4()[p] == v for p,v in meta['ipv4_conf'].items())
    for source in (BACKUP/'app').rglob('*.py'):
        target = APP/'app'/source.relative_to(BACKUP/'app')
        shutil.copy2(source,target)
        os.chown(target,pwd.getpwnam('pink-iptv').pw_uid,pwd.getpwnam('pink-iptv').pw_gid)
    for name in meta.get('new_app_files',[]):
        target = APP/'app'/name
        if target.exists(): target.unlink()
    run('systemctl','daemon-reload')
    run('systemctl','restart','pink-iptv-backend')
    assert hashlib.sha256(firewall().encode()).hexdigest() == meta['firewall_sha256']
    wait_health()
    (BACKUP/'rolled-back').write_text('exact additive inverse verified\n')
    print('EXACT_ADDITIVE_ROLLBACK=PASS')


def network_up():
    assert os.geteuid() == 0
    run('ip','link','add',IFACE,'type','wireguard')
    run('wg','set',IFACE,'private-key',str(ROOT/'server.key'),'listen-port','51820')
    run('ip','address','add','10.66.0.1/24','dev',IFACE)
    run('ip','link','set',IFACE,'mtu','1380','up')
    ipt('filter','-N','PINK052_IN')
    ipt('filter','-A','PINK052_IN','-i','ens3','-p','udp','--dport','51820','-j','ACCEPT')
    ipt('filter','-A','PINK052_IN','-i',IFACE,'-s','10.66.0.0/24','-d','10.66.0.1/32',
        '-p','tcp','--dport','51821','-j','ACCEPT')
    ipt('filter','-A','PINK052_IN','-i',IFACE,'-j','DROP')
    ipt('filter','-I','INPUT','1','-j','PINK052_IN')
    ipt('filter','-N','PINK052_FWD')
    for blocked in ('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
                    '172.16.0.0/12','192.168.0.0/16','198.18.0.0/15','224.0.0.0/3','146.59.145.3/32'):
        ipt('filter','-A','PINK052_FWD','-i',IFACE,'-d',blocked,'-j','DROP')
    ipt('filter','-A','PINK052_FWD','-i',IFACE,'-o','ens3','-s','10.66.0.0/24','-j','ACCEPT')
    ipt('filter','-A','PINK052_FWD','-i','ens3','-o',IFACE,'-d','10.66.0.0/24',
        '-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ipt('filter','-A','PINK052_FWD','-i',IFACE,'-j','DROP')
    ipt('filter','-A','PINK052_FWD','-o',IFACE,'-j','DROP')
    ipt('filter','-I','FORWARD','1','-j','PINK052_FWD')
    ipt('nat','-N','PINK052_NAT')
    ipt('nat','-A','PINK052_NAT','-s','10.66.0.0/24','-o','ens3','-j','MASQUERADE')
    ipt('nat','-A','POSTROUTING','-j','PINK052_NAT')
    run('sysctl','-qw','net.ipv4.ip_forward=1')
    print('OWNED_NETWORK_READY=PASS')


def install(source):
    from pink_vpn_052_audit import audit
    audit()
    assert not BACKUP.exists() and not DROP.exists() and not SYSCTL.exists() and not UNIT.exists()
    os.umask(0o077)
    BACKUP.mkdir(mode=0o700,parents=True)
    shutil.copytree(APP/'app',BACKUP/'app')
    source = Path(source)
    new_files = [str(p.relative_to(source/'backend/app')) for p in (source/'backend/app').rglob('*.py')
                 if not (APP/'app'/p.relative_to(source/'backend/app')).exists()]
    (BACKUP/'baseline.json').write_text(json.dumps({'forward':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
        'firewall_sha256':hashlib.sha256(firewall().encode()).hexdigest(),'new_app_files':new_files,
        'ipv4_conf':conf4()}))
    shutil.copy2(__file__,BACKUP/'rollback.py')
    # Independent inverse is armed before the first network mutation.
    run('systemd-run','--unit=pink-vpn-052-rollback','--on-active=15m','/usr/bin/python3',str(BACKUP/'rollback.py'),'rollback')
    assert run('systemctl','is-active','pink-vpn-052-rollback.timer') == 'active'
    print('INDEPENDENT_ROLLBACK_ARMED=PASS')
    try:
        ROOT.mkdir(mode=0o700)
        Path('/var/lib/pink-vpn').mkdir(mode=0o700)
        key = run('wg','genkey')
        (ROOT/'server.key').write_text(key+'\n')
        os.chmod(ROOT/'server.key',0o600)
        del key
        public = subprocess.run(['wg','pubkey'],input=(ROOT/'server.key').read_text(),
                                capture_output=True,text=True,check=True).stdout.strip()
        for filename in ('pink_vpn_052_install.py','pink_vpn_052_gateway.py','pink_vpn_052_peer.py',
                         'pink_vpn_052_enrollment.py'):
            shutil.copy2(source/'ops'/filename,ROOT/filename)
        UNIT.write_text('''[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
Type=simple
ExecStartPre=/usr/bin/python3 /etc/pink-vpn/pink_vpn_052_install.py up
ExecStart=/usr/bin/python3 /etc/pink-vpn/pink_vpn_052_gateway.py
ExecStopPost=/usr/bin/python3 /etc/pink-vpn/pink_vpn_052_install.py down
Restart=on-failure
RestartSec=5
UMask=0077
RuntimeDirectory=pink-vpn
RuntimeDirectoryMode=0750
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
''')
        SYSCTL.write_text('net.ipv4.ip_forward=1\n')
        run('systemctl','daemon-reload')
        run('systemctl','enable','--now','pink-vpn.service')
        for _ in range(15):
            if Path('/run/pink-vpn/control.sock').is_socket():
                break
            time.sleep(1)
        else:
            raise RuntimeError('Gateway control unavailable')
        run('systemctl','is-active','--quiet','pink-vpn.service')
        for p in (source/'backend/app').rglob('*.py'):
            target=APP/'app'/p.relative_to(source/'backend/app')
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(p,target)
            os.chown(target,pwd.getpwnam('pink-iptv').pw_uid,pwd.getpwnam('pink-iptv').pw_gid)
        shutil.copy2(source/'backend/alembic/versions/20261005_0002_vpn_installations.py',
                     APP/'alembic/versions/20261005_0002_vpn_installations.py')
        # Existing secret values are used in-process only; never returned through diagnostics.
        script = '''from dotenv import dotenv_values
import os
from alembic import command
from alembic.config import Config
for p in ("/etc/pink-iptv/backend.env","/etc/pink-iptv/secrets.env"):
    os.environ.update({k:v for k,v in dotenv_values(p).items() if v is not None})
command.upgrade(Config("alembic.ini"),"head")
'''
        subprocess.run([str(APP/'.venv/bin/python'),'-c',script],cwd=APP,capture_output=True,check=True,timeout=30)
        Path('/etc/pink-iptv/vpn.env').write_text('VPN_ENABLED=true\nVPN_ENDPOINT=146.59.145.3:51820\nVPN_SERVER_PUBLIC_KEY='+public+'\n')
        DROP.parent.mkdir(parents=True,exist_ok=True)
        DROP.write_text('[Service]\nEnvironmentFile=/etc/pink-iptv/vpn.env\n')
        run('systemctl','daemon-reload')
        run('systemctl','restart','pink-iptv-backend')
        wait_health()
        assert '-P INPUT DROP' in ipt('filter','-S') and '-P FORWARD DROP' in ipt('filter','-S')
        assert Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip() == '0'
        assert (ROOT/'server.key').stat().st_mode & 0o777 == 0o600
        print('PERSISTENT_STAGING_GATEWAY_READY=PASS')
        print('NEW_SERVER_PUBLIC_KEY='+public)
        print('BACKEND_ENROLLMENT_DEPLOY=PASS')
        print('EXISTING_SERVICES_PRESERVED=PASS')
    except BaseException:
        rollback()
        raise


if __name__ == '__main__':
    assert os.geteuid() == 0
    mode = sys.argv[1]
    if mode == 'install': install(sys.argv[2])
    elif mode == 'up': network_up()
    elif mode == 'down': network_down()
    elif mode == 'rollback': rollback()
    elif mode == 'accept':
        health()
        run('systemctl','is-active','--quiet','pink-vpn')
        run('systemctl','stop','pink-vpn-052-rollback.timer')
        (BACKUP/'accepted').write_text('protected staging gateway accepted after independent proof\n')
        print('STAGING_GATEWAY_ACCEPTED=PASS')
