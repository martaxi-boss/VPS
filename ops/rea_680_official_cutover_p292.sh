#!/usr/bin/env bash
set -Eeuo pipefail
mode="${1:---preflight}"
if [[ "$mode" != "--preflight" && "$mode" != "--activate" ]]; then
  echo "Usage: sudo bash SCRIPT [--preflight|--activate]" >&2
  exit 2
fi
svc='rea-reversa-mcp.service'
root='/opt/rea-reversa'
active="$root/rea"
stage="$root/upgrades/rea-6.8.0-160d821ac9a0"
rollback="$root/rollbacks/rea-6.7.0-20261026"
backup='/home/ubuntu/.local/share/rea-chatgpt-trial/upgrade-backups/rea-6.7.0-retained-evidence-before-6.8.0-20261026.json'
restore="$stage/.rea-migration/evidence-restore.json"
service_touched=0
old_moved=0
new_moved=0
on_exit() {
  rc=$?
  trap - EXIT
  if (( rc != 0 && service_touched == 1 )); then
    echo 'REA680: activation failed; attempting rollback'
    systemctl stop "$svc" || true
    if (( new_moved == 1 )) && [[ -d "$active" ]]; then
      mv -T "$active" "$stage" || true
    fi
    if [[ -d "$rollback" && ! -e "$active" ]]; then
      mv -T "$rollback" "$active" || true
    fi
    if [[ -d "$active" ]]; then
      systemctl start "$svc" || true
    fi
    if systemctl is-active --quiet "$svc"; then
      echo 'REA680_ROLLBACK_SERVICE_ACTIVE=YES'
    else
      echo 'REA680_ROLLBACK_SERVICE_ACTIVE=NO_MANUAL_RECOVERY_REQUIRED'
    fi
  fi
  exit "$rc"
}
trap on_exit EXIT
[[ $(id -u) == 0 ]] || { echo 'Run as root via sudo bash'; exit 2; }
[[ -d "$active" && ! -L "$active" && -d "$stage" && ! -L "$stage" ]] || exit 3
[[ ! -e "$rollback" && ! -L "$rollback" ]] || exit 4
[[ $(stat -c %d "$active") == $(stat -c %d "$stage") ]] || exit 5
[[ $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$active/package.json") == '6.7.0' ]] || exit 6
[[ $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$stage/package.json") == '6.8.0' ]] || exit 7
[[ $(sudo -u ubuntu git -C "$stage" rev-parse HEAD) == '160d821ac9a0310afcb8d1fc427862dd6508add5' ]] || exit 8
[[ $(sudo -u ubuntu git -C "$stage" rev-parse 'HEAD^{tree}') == '15e6fec513dcce08cefdbcf441200986397e2793' ]] || exit 9
sudo -u ubuntu git -C "$stage" diff --quiet --exit-code || exit 10
[[ $(sha256sum "$backup" | cut -d ' ' -f 1) == 'baa448b25c2f1f2a5c76589b0a1eb4f586e20d733335eef76a9f5ed29f76b936' ]] || exit 11
[[ $(sha256sum "$restore" | cut -d ' ' -f 1) == 'f8178b2c3db0d093fa65864d9c12be9a1afe3c6d66fc93603769761bd9400f3b' ]] || exit 12
[[ -r "$restore" ]] || exit 12
systemctl is-active --quiet "$svc" || exit 13
[[ $(systemctl show "$svc" -p User --value) == 'rea-reversa' ]] || exit 14
systemctl show "$svc" -p ExecStart --value | grep -Fq "$active" || exit 15
mcpcheck() {
python3 - "$1" "$backup" <<'PY'
import hashlib,json,sys,urllib.request
mode,backup=sys.argv[1:]
url='http://127.0.0.1:8765/mcp'
def post(payload,session=None,version=None):
    headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
    if session: headers['Mcp-Session-Id']=session
    if version: headers['MCP-Protocol-Version']=version
    req=urllib.request.Request(url,data=json.dumps(payload).encode(),headers=headers,method='POST')
    with urllib.request.urlopen(req,timeout=20) as resp:
        hdr=resp.headers
        text=resp.read(6000000).decode().strip()
    if not text: return hdr,{}
    if text.startswith('{'): return hdr,json.loads(text)
    for line in text.splitlines():
        if line.startswith('data:') and line[5:].strip().startswith('{'):
            return hdr,json.loads(line[5:].strip())
    raise ValueError('Invalid MCP response')
def locate(x,depth=0):
    if depth>10:return None
    if isinstance(x,dict):
        if isinstance(x.get('records'),list) and isinstance(x.get('unknowns'),list):return x
        for v in x.values():
            z=locate(v,depth+1)
            if z is not None:return z
    elif isinstance(x,list):
        for v in x[:35]:
            z=locate(v,depth+1)
            if z is not None:return z
    elif isinstance(x,str) and x.lstrip().startswith('{') and len(x)<4500000:
        try:return locate(json.loads(x),depth+1)
        except ValueError:pass
    return None
h,init=post({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'rea-680-controlled-cutover','version':'1'}}})
assert 'result' in init,'MCP initialize failed'
sid=h.get('Mcp-Session-Id');version=init['result'].get('protocolVersion')
post({'jsonrpc':'2.0','method':'notifications/initialized'},sid,version)
if mode=='before':
    _,reply=post({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'get_evidence_bundle','arguments':{'detail':'complete'}}},sid,version)
    saved=locate(json.load(open(backup)))
    actual=locate(reply)
    assert saved and actual,'Evidence bundle missing'
    assert len(actual['records'])==len(saved['records'])==16
    assert len(actual['unknowns'])==len(saved['unknowns'])==1
    digest=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    assert digest(actual['records'])==digest(saved['records']),'Evidence changed since backup'
    assert digest(actual['unknowns'])==digest(saved['unknowns']),'Unknowns changed since backup'
    print('REA680_LIVE_EVIDENCE_MATCH=PASS_16_1')
    _,reply=post({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_cutter_sessions','arguments':{}}},sid,version)
    assert reply.get('result',{}).get('structuredContent',{}).get('sessions')==[], 'Active Cutter session or unreadable session status'
    _,reply=post({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'list_documents','arguments':{}}},sid,version)
    result=reply.get('result',{})
    assert result.get('isError') is True and any('No app is open' in str(item.get('text','')) for item in result.get('content',[]) if isinstance(item,dict)), 'An analysis application may still be open'
    print('REA680_NO_ACTIVE_ANALYSIS_SESSIONS=PASS')
elif mode=='after':
    _,reply=post({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},sid,version)
    items=reply.get('result',{}).get('tools',[])
    names=[x.get('name') for x in items]
    assert len(items)==229 and len(set(names))==229,'New MCP catalog not 229'
    print('REA680_MCP_CATALOG=229')
else:
    raise ValueError('invalid mode')
PY
}
mcpcheck before
echo 'REA680_PREFLIGHT=PASS'
if [[ "$mode" == '--preflight' ]]; then
  echo 'REA680_NO_SERVICE_CHANGES=PASS'
  exit 0
fi
install -d -m 0755 -o root -g root "$root/rollbacks"
service_touched=1
systemctl stop "$svc"
if systemctl is-active --quiet "$svc"; then echo 'REA680_SERVICE_DID_NOT_STOP'; exit 21; fi
mv -T "$active" "$rollback"
old_moved=1
mv -T "$stage" "$active"
new_moved=1
systemctl start "$svc"
valid=0
for try in 1 2 3 4 5 6; do
  if systemctl is-active --quiet "$svc" && mcpcheck after; then
    valid=1
    break
  fi
  sleep 3
done
(( valid == 1 )) || exit 16
echo 'REA680_ACTIVE=PASS_6_8_0'
echo 'REA680_PREVIOUS_6_7_0=RETAINED_FOR_ROLLBACK'
echo 'REA680_EVIDENCE_IMPORT=WAITING_FOR_SIGNED_GITHUB_MCP_CALL'
