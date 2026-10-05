"""Known-account transient fixture or bounded own-installation cleanup only."""
import json
import logging
import os
from pathlib import Path
import subprocess
import sys

logging.disable(logging.CRITICAL)

FETCH = r'''
import hashlib,json,logging
from datetime import UTC,datetime
from sqlalchemy import select
from app.config import get_settings
from app.clients.mega import MegaOTTClient
from app.db import build_session_factory
from app.models import SubscriptionMapping
logging.disable(logging.CRITICAL)
settings=get_settings()
with MegaOTTClient(base_url=settings.mega_ott_api_base,token=settings.require_mega_token()) as mega:
    line=mega.get_subscription(9040240)
    assert hashlib.md5(line.username.encode()).hexdigest()=='325a5df019165e41992baaa59133987d'
    assert line.expiring_at is None or line.expiring_at>datetime.now(UTC)
    with build_session_factory(settings.database_url)() as db:
        row=db.scalar(select(SubscriptionMapping).where(SubscriptionMapping.mega_subscription_id==9040240))
        assert row is not None and row.username==line.username and row.dns_link==line.dns_link
    assert line.password is not None
    print(json.dumps({'username':line.username,'password':line.password.get_secret_value(),'expected_origin':line.dns_link}))
'''

CLEAN = r'''
import json,logging,os
from datetime import UTC,datetime
from sqlalchemy import select
from app.config import get_settings
from app.db import build_session_factory
from app.models import SubscriptionMapping,VpnInstallation
from app.vpn import LocalGateway,public_key
logging.disable(logging.CRITICAL)
key=public_key(os.environ['PINK056_PUBLIC_KEY'])
settings=get_settings()
with build_session_factory(settings.database_url)() as db:
    peer=db.scalar(select(VpnInstallation).where(VpnInstallation.public_key==key))
    if peer is not None:
        mapping=db.get(SubscriptionMapping,peer.mapping_id)
        assert mapping is not None and mapping.mega_subscription_id==9040240
        peer.revoked_at=datetime.now(UTC)
        db.commit()
        LocalGateway('/run/pink-vpn/control.sock').apply('remove',peer)
        db.delete(peer)
        db.commit()
print('ONLY_DISPOSABLE_EMULATOR_INSTALLATION_REMOVED=PASS')
'''


def execute(mode, public_key=None):
    assert os.geteuid()==0
    def run(*args):
        return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    assert run('hostname')=='vps-32bea5b6'
    assert run('systemctl','show','pink-iptv-backend','-p','WorkingDirectory','--value')=='/srv/pink-iptv/backend'
    pid=int(run('systemctl','show','pink-iptv-backend','-p','MainPID','--value'))
    assert pid>1
    allowed={'APP_ENV','DATABASE_URL','SESSION_SIGNING_KEY','SESSION_TTL_SECONDS','MEGA_OTT_API_BASE','MEGA_OTT_API_TOKEN'}
    runtime={}
    for item in Path('/proc/'+str(pid)+'/environ').read_bytes().split(b'\0'):
        if b'=' in item:
            key,value=item.split(b'=',1)
            if key.decode() in allowed:
                runtime[key.decode()]=value.decode()
    assert runtime.get('DATABASE_URL') and runtime.get('MEGA_OTT_API_TOKEN')
    assert mode in ('fetch','cleanup')
    env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1',**runtime}
    if mode=='cleanup':
        assert isinstance(public_key,str) and len(public_key)==44
        env['PINK056_PUBLIC_KEY']=public_key
    child=subprocess.run(['/srv/pink-iptv/backend/.venv/bin/python','-c',FETCH if mode=='fetch' else CLEAN],
        cwd='/srv/pink-iptv/backend',env=env,capture_output=True,text=True,timeout=90)
    if child.returncode!=0:
        raise RuntimeError('Protected operational action unavailable')
    if mode=='fetch':
        obj=json.loads(child.stdout)
        assert set(obj)=={'username','password','expected_origin'}
        # SSH stdout must be redirected to the private ephemeral runner fixture.
        sys.stdout.write(json.dumps(obj)+'\n')
    else:
        assert child.stdout.strip()=='ONLY_DISPOSABLE_EMULATOR_INSTALLATION_REMOVED=PASS'
        print(child.stdout.strip())


if __name__=='__main__':
    try:
        execute(MODE, PUBLIC_KEY)  # Injected exact public mode/key by workflow.
    except BaseException:
        sys.stderr.write('PROTECTED_OPERATIONAL_ACTION=FAIL\n')
        raise SystemExit(1)
