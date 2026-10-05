"""Bounded root-only proof control: public key in, sanitized status out."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def request(payload):
    assert os.geteuid() == 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect('/run/pink-vpn/control.sock')
        connection.sendall(json.dumps(payload).encode()+b'\n')
        response = connection.makefile('rb').readline(2049)
        assert json.loads(response) == {'ok':True}


if __name__ == '__main__':
    assert os.geteuid() == 0
    data = json.load(sys.stdin)
    assert set(data) == {'operation','public_key','seconds'}
    assert data['operation'] in {'upsert','remove'}
    assert isinstance(data['seconds'],int) and 0 <= data['seconds'] <= 120
    request({'operation':data['operation'],'public_key':data['public_key'],
             'address':'10.66.0.2','expires_at':time.time()+data['seconds']})
    public = subprocess.run(['wg','show','pinkvpn','public-key'],check=True,
                            capture_output=True,text=True,timeout=5).stdout.strip()
    print(json.dumps({'ok':True,'server_public_key':public}))
