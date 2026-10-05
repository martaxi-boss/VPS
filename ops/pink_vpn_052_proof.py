"""Independent Linux client proof; generated private identity never leaves runner."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

IFACE = 'pink052ci'
SSH = ['sshpass','-e','ssh','-T','-o','PreferredAuthentications=password',
       '-o','PubkeyAuthentication=no','-o','StrictHostKeyChecking=accept-new',
       '-o','ConnectTimeout=15','ubuntu@146.59.145.3']


def run(*args,check=True,timeout=30):
    return subprocess.run(args,capture_output=True,text=True,check=check,timeout=timeout).stdout.strip()


def peer(public,operation='upsert',seconds=120):
    result = subprocess.run(SSH+['sudo -n python3 /etc/pink-vpn/pink_vpn_052_peer.py'],
        input=json.dumps({'operation':operation,'public_key':public,'seconds':seconds}),
        capture_output=True,text=True,check=True,timeout=20)
    return json.loads(result.stdout)['server_public_key']


def health(ok=True):
    result = subprocess.run(['curl','--noproxy','*','--interface',IFACE,'--max-time','5',
                             '-fsS','http://10.66.0.1:51821/health'],capture_output=True,text=True,timeout=8)
    assert (result.returncode == 0 and result.stdout == 'PINK_VPN_READY') == ok


def proof():
    os.umask(0o077)
    public = None
    target = next(row[4][0] for row in socket.getaddrinfo('api.github.com',443,socket.AF_INET,socket.SOCK_STREAM))
    with tempfile.TemporaryDirectory(prefix='pink052-') as scratch:
        path = Path(scratch)
        private = run('wg','genkey')
        (path/'peer.key').write_text(private+'\n')
        public = subprocess.run(['wg','pubkey'],input=private,capture_output=True,text=True,check=True).stdout.strip()
        del private
        try:
            server = peer(public)
            config = '[Interface]\nPrivateKey = '+(path/'peer.key').read_text()+(
                '\n[Peer]\nPublicKey = '+server+'\nEndpoint = 146.59.145.3:51820\n'
                'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 5\n')
            (path/'client.conf').write_text(config)
            del config
            run('sudo','ip','link','add',IFACE,'type','wireguard')
            run('sudo','wg','setconf',IFACE,str(path/'client.conf'))
            run('sudo','ip','address','add','10.66.0.2/32','dev',IFACE)
            run('sudo','ip','link','set',IFACE,'mtu','1380','up')
            run('sudo','ip','route','add','10.66.0.1/32','dev',IFACE)
            run('sudo','ip','route','add',target+'/32','dev',IFACE)
            health()
            assert int(run('sudo','wg','show',IFACE,'latest-handshakes').split()[1]) > 0
            print('REAL_EXTERNAL_HANDSHAKE=PASS',flush=True)
            run('curl','--noproxy','*','--interface',IFACE,'--resolve','api.github.com:443:'+target,
                '--max-time','20','-fsS','https://api.github.com/','-o','/dev/null')
            print('BOUNDED_HTTPS_NAT_EGRESS=PASS',flush=True)
            peer(public,seconds=3)
            time.sleep(5)
            health(False)
            print('EXPIRED_PEER_NO_EGRESS=PASS',flush=True)
            assert peer(public) == server
            health()
            print('SAME_IDENTITY_REFRESH_RECOVERS=PASS',flush=True)
            run(*SSH,'sudo -n systemctl restart pink-vpn.service',timeout=30)
            time.sleep(3)
            health(False)
            assert peer(public) == server
            health()
            print('GATEWAY_RESTART_FRESH_AUTH_SAME_SERVER_IDENTITY=PASS',flush=True)
        finally:
            run('sudo','ip','link','delete',IFACE,check=False)
            if public:
                peer(public,operation='remove',seconds=0)
            print('TEMPORARY_CLIENT_IDENTITY_AND_PEER_REMOVED=PASS',flush=True)


if __name__ == '__main__':
    proof()
