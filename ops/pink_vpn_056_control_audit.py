"""Run exact canonical control validators on current repository evidence."""
import base64,hashlib,json,os,subprocess,sys,urllib.request
from pathlib import Path
CONTROL='8efecaccfb5708d3689f9fcd0ad3bb77ec8e40db'
SOURCE='9e1fc82c9c964a079d876671990a41a73689955e'
ROOT=Path('_canonical_control').resolve()
sys.path.insert(0,str(ROOT))
from control.validate_records import validate_task,validate_pair,validate_scope,validate_recovery_journal,validate_transition_authorization,validate_transition_pair
from control.verify_github_evidence import verify_github_evidence,verify_compare_payload
def get(repo,path):
    req=urllib.request.Request('https://api.github.com/repos/'+repo+'/'+path,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=30) as response: return json.load(response)
def contents(repo,path,ref):
    reply=get(repo,'contents/'+path+'?ref='+ref)
    assert reply['encoding']=='base64'
    return base64.b64decode(reply['content'])
def check(repo,task_id,auth_sha,head,local):
    path='.project-leader/tasks/'+task_id+'.json'
    current=Path(path).read_bytes() if local else contents(repo,path,head)
    original=contents(repo,path,auth_sha)
    assert current==original
    task=json.loads(current);validate_task(task)
    assert task['repository']==repo and task['effect_class']=='E1_RECOVERABLE_PROJECT_LOCAL'
    assert hashlib.sha256((ROOT/'control/generic-project-policy.json').read_bytes()).hexdigest()==task['policy']['sha256']
    ancestry=get(repo,'compare/'+auth_sha+'...'+head);assert ancestry['status']=='ahead'
    scope=get(repo,'compare/'+task['starting_state']['base_sha']+'...'+head)
    assert len(scope['files'])<300;validate_scope(task,[x['filename'] for x in scope['files']])
    directory='.project-leader/recovery-events/'+task_id
    if local: records=[json.loads(p.read_text()) for p in sorted(Path(directory).glob('*.json'))]
    else:
        listing=get(repo,'contents/'+directory+'?ref='+head)
        records=[json.loads(contents(repo,item['path'],head)) for item in listing if item['type']=='file' and item['name'].endswith('.json')]
    validate_recovery_journal(records)
    result_path='.project-leader/results/'+task_id+'.json'
    if os.environ['PINK056_AUDIT_MODE']=='post':
        result=json.loads(Path(result_path).read_text()) if local else json.loads(contents(repo,result_path,head))
        validate_pair(task,result)
        verify_github_evidence(result,repo,os.environ['GH_TOKEN'],head)
        print('CANONICAL_TERMINAL_GITHUB_EVIDENCE_'+('VPS' if local else 'PINK')+'=PASS')
    return task
def main():
    assert os.environ['GITHUB_REPOSITORY']=='martaxi-boss/VPS'
    assert subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()==CONTROL
    assert get('martaxi-boss/Project-leader','git/ref/heads/main')['object']['sha']==CONTROL
    message=os.environ.get('PINK056_COMMIT_MESSAGE','')
    if message in {'Authorize exact real Android flow 056','Record verified real056 recovery'}:
        live=get('martaxi-boss/VPS','git/ref/heads/builder/pink-extreme-real-flow-056')['object']['sha']
        assert live==os.environ['GITHUB_SHA']
    if message=='Authorize exact real Android flow 056':
        commit=get('martaxi-boss/VPS','commits/'+os.environ['GITHUB_SHA'])
        paths=[f['filename'] for f in commit['files'] if f['status']=='added' and f['filename'].startswith('.project-leader/transitions/PINK-IPTV-EXTREME-REAL-FLOW-056-EXECUTE') and f['filename'].endswith('.authorization.json')]
        assert len(paths)==1
        authority=json.loads(Path(paths[0]).read_text());validate_transition_authorization(authority)
        assert authority['action']=='staging_operational_proof' and authority['authority']['source']=='STANDING_OWNER_GRANT'
        assert authority['target']['identifier'].startswith('OVH:vps-32bea5b6;PINK:'+SOURCE+';artifact-run:')
        print('LIVE_EXACT_PRIVILEGED_AUTHORIZATION_SCHEMA_AND_BRANCH_HEAD=PASS')
    if os.environ['PINK056_AUDIT_MODE']=='post':
        for path in Path('.project-leader/transitions').glob('PINK-IPTV-EXTREME-REAL-FLOW-056-*.result.json'):
            result=json.loads(path.read_text())
            if result['terminal_status']=='SUCCESS':
                auth=json.loads(Path(result['authorization_record']).read_text())
                validate_transition_pair(auth,result)
        print('EXACT_SUCCESSFUL_EFFECT_AUTHORIZATION_RESULT_PAIRS=PASS')
    pink=get('martaxi-boss/pink-iptv','git/ref/heads/builder/extreme-live-certification-055')['object']['sha']
    verify_compare_payload(get('martaxi-boss/pink-iptv','compare/'+SOURCE+'...'+pink),SOURCE,pink,'PINK-IPTV-EXTREME-LIVE-CERTIFICATION-055')
    check('martaxi-boss/pink-iptv','PINK-IPTV-EXTREME-LIVE-CERTIFICATION-055','d0d08845751bdc80c0e8dbd73b7f7bab25a3afd2',pink,False)
    check('martaxi-boss/VPS','PINK-IPTV-EXTREME-REAL-FLOW-056','fdfaa4300792227f8baa589a7b747246139cc728',os.environ['GITHUB_SHA'],True)
    print('CANONICAL_CURRENT_TASK_SCOPE_POLICY_AND_HASH_LINKED_JOURNALS=PASS')
if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('CANONICAL_CONTROL_AUDIT=FAIL;CATEGORY='+type(error).__name__)
        raise SystemExit(1)
