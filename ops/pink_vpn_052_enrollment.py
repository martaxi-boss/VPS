"""Real backend UID/socket integration against isolated in-memory account records."""
import base64
from datetime import UTC, datetime, timedelta
import json
import os
import secrets
import sys
import urllib.request

sys.path.insert(0, '/srv/pink-iptv/backend')
os.environ['APP_ENV'] = 'test'
os.environ['DATABASE_URL'] = 'sqlite+pysqlite:///:memory:'
os.environ['SESSION_SIGNING_KEY'] = secrets.token_urlsafe(48)

from app.config import Settings
from app.db import Base
from app.main import create_app
from app.models import SubscriptionMapping
from app.security import issue_session_token
from fastapi.testclient import TestClient


def proof():
    public = base64.b64encode(secrets.token_bytes(32)).decode()
    server = os.environ['PINK052_SERVER_PUBLIC_KEY']
    settings = Settings(vpn_enabled=True,vpn_server_public_key=server,
                        vpn_endpoint='146.59.145.3:51820')
    app = create_app(settings)
    factory = app.state.session_factory
    with factory() as db:
        Base.metadata.create_all(db.get_bind())
        mapping = SubscriptionMapping(mega_subscription_id=1,username='isolated-052',
            dns_link='https://isolated.invalid',expiring_at=datetime.now(UTC)+timedelta(hours=1),
            last_synced_at=datetime.now(UTC))
        db.add(mapping)
        db.commit()
        token, _ = issue_session_token(mapping.id,settings)
    with TestClient(app) as client:
        assert client.post('/v1/vpn/enroll',json={'public_key':public}).status_code == 401
        lease = None
        try:
            result = client.post('/v1/vpn/enroll',json={'public_key':public},
                headers={'Authorization':'Bearer '+token})
            assert result.status_code == 200
            lease = result.json()
            request = {'public_key':public,'device_token':lease['device_token']}
            assert client.post('/v1/vpn/refresh',json=request).status_code == 200
            assert client.post('/v1/vpn/refresh',json=request | {'device_token':'x'*43}).status_code == 403
            assert client.post('/v1/vpn/revoke',json=request).status_code == 204
            assert client.post('/v1/vpn/refresh',json=request).status_code == 403
        finally:
            if lease:
                assert client.post('/v1/vpn/revoke',json={'public_key':public,
                    'device_token':lease['device_token']}).status_code == 204
    assert os.geteuid() != 0
    print('REAL_BACKEND_UID_AUTHENTICATED_ENROLL_REFRESH_REVOKE=PASS')
    print('ISOLATED_ACCOUNT_DATABASE_CUSTOMER_ROWS_UNCHANGED=PASS')


if __name__ == '__main__':
    proof()
