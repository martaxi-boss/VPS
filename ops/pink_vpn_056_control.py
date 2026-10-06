"""Read-only, fixed-category diagnostics of the accepted HTTPS control path."""
import json,logging,os,re,subprocess,sys
from pathlib import Path
logging.disable(logging.CRITICAL)

PATHS={'/v1/session/resolve':'SESSION_RESOLVE','/v1/vpn/enroll':'VPN_ENROLL','/v1/vpn/refresh':'VPN_REFRESH'}
def request_statuses(lines):
    result={}
    for line in lines:
        match=re.search(r'"POST (/v1/session/resolve|/v1/vpn/enroll|/v1/vpn/refresh) HTTP/1\.[01]" ([1-5][0-9]{2})(?:\s|$)',line)
        if match:
            key=PATHS[match[1]]+'_HTTP_'+match[2]
            result[key]=result.get(key,0)+1
    return result

def resolution_category(reply,expected_origin):
    if not isinstance(reply,dict): return 'INVALID_RESPONSE'
    if reply.get('code')=='SUCCESS':
        return 'SUCCESS_ORIGIN_MATCH' if reply.get('xtream_base_url','').rstrip('/')==expected_origin.rstrip('/') else 'ORIGIN_MISMATCH'
    return 'NON_SUCCESS'

PROBE=r'''
import contextlib,io,json,logging,time,urllib.request,urllib.error
logging.disable(logging.CRITICAL)
capture=io.StringIO()
with contextlib.redirect_stdout(capture): exec(EXACT_FIXTURE_CODE)
fixture=json.loads(capture.getvalue())
request=urllib.request.Request('https://pink-iptv.duckdns.org/v1/session/resolve',
    data=json.dumps({'username':fixture['username'],'password':fixture['password']}).encode(),
    headers={'Content-Type':'application/json'},method='POST')
start=time.monotonic()
try:
    with urllib.request.urlopen(request,timeout=25) as response:
        raw=response.read(65537)
        assert len(raw)<=65536
        reply=json.loads(raw)
        category=resolution_category(reply,fixture['expected_origin'])
        result={'http_status':response.status,'category':category,'seconds':round(time.monotonic()-start,3)}
except urllib.error.HTTPError as error:
    result={'http_status':error.code,'category':'HTTP_FAILURE','seconds':round(time.monotonic()-start,3)}
except Exception:
    result={'http_status':0,'category':'REQUEST_UNAVAILABLE','seconds':round(time.monotonic()-start,3)}
print(json.dumps(result))
'''

def diagnose():
    assert os.geteuid()==0
    def run(*args):
        return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15).stdout.strip()
    assert run('hostname')=='vps-32bea5b6'
    assert run('systemctl','show','pink-iptv-backend','-p','WorkingDirectory','--value')=='/srv/pink-iptv/backend'
    pid=int(run('systemctl','show','pink-iptv-backend','-p','MainPID','--value'))
    assert pid>1
    # Only the exact R7 service window; request bodies/messages are never returned.
    lines=run('journalctl','-u','pink-iptv-backend','--since','2026-10-05 23:19:00 UTC',
              '--until','2026-10-05 23:21:00 UTC','--no-pager','-n','200').splitlines()
    for key,count in sorted(request_statuses(lines).items()): print('R7_CONTROL_LOG='+key+';COUNT='+str(count))
    allowed={'APP_ENV','DATABASE_URL','SESSION_SIGNING_KEY','SESSION_TTL_SECONDS','MEGA_OTT_API_BASE','MEGA_OTT_API_TOKEN'}
    runtime={}
    for item in Path('/proc/'+str(pid)+'/environ').read_bytes().split(b'\0'):
        if b'=' in item:
            key,value=item.split(b'=',1)
            if key.decode() in allowed: runtime[key.decode()]=value.decode()
    assert runtime.get('DATABASE_URL') and runtime.get('MEGA_OTT_API_TOKEN')
    # Exact source is injected by the runner because this module runs on stdin.
    child_code='EXACT_FIXTURE_CODE='+repr(EXACT_FIXTURE_CODE)+'\n'+RESOLUTION_SOURCE+PROBE
    child=subprocess.run(['/srv/pink-iptv/backend/.venv/bin/python','-c',child_code],
        cwd='/srv/pink-iptv/backend',env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1',**runtime},
        capture_output=True,text=True,timeout=90)
    assert child.returncode==0
    reply=json.loads(child.stdout)
    assert set(reply)=={'http_status','category','seconds'}
    assert type(reply['http_status']) is int and reply['http_status'] in {0,*range(100,600)}
    assert reply['category'] in {'SUCCESS_ORIGIN_MATCH','ORIGIN_MISMATCH','NON_SUCCESS','INVALID_RESPONSE','HTTP_FAILURE','REQUEST_UNAVAILABLE'}
    assert isinstance(reply['seconds'],(int,float)) and 0<=reply['seconds']<=90
    print('FRESH_SESSION_HTTP='+str(reply['http_status']))
    print('FRESH_SESSION_RESOLUTION='+reply['category'])
    print('FRESH_SESSION_SECONDS='+str(reply['seconds']))
    print('READ_ONLY_CONTROL_DIAGNOSTIC=PASS')

if __name__=='__main__':
    try: diagnose()
    except BaseException:
        sys.stderr.write('READ_ONLY_CONTROL_DIAGNOSTIC=FAIL\n')
        raise SystemExit(1)
