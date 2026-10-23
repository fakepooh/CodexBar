"""One authorized CP-01 only. No retries, follow-ups, or other cases."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import uuid

import isolated_auth as auth
import keychain_helper
import offline_preflight
import pilot
import runtime_setup
import review_route

ROOT = Path(__file__).resolve().parent
EVIDENCE = auth.EVIDENCE
GUARD = ROOT / '.cache/CP-01-live-consumed.json'
OUTPUT = ROOT / 'runs/live-CP-01-2026-10-19'
# The supported minimum is 30. This is a soft session ceiling, not a promise
# about the unknown Free allowance or the original 10% threshold.
SOFT_CREDIT_CEILING = 30
USAGE_PATH = '/home/copilot/cp01-final-usage.json'

# Trusted transport and supported usage-file capture, never a model tool.
# Only the CLI child gets the credential environment. The wrapper wipes the
# mutable token and drops its reference to the child environment after spawn.
BOOTSTRAP = r"""
const fs=require('fs'),cp=require('child_process');
function exact(n){const b=Buffer.alloc(n);let at=0;while(at<n){const k=fs.readSync(0,b,at,n-at,null);if(!k)process.exit(70);at+=k}return b}
const h=exact(4),n=h.readUInt32BE();h.fill(0);if(n<12||n>1024)process.exit(71);
const b=exact(n);if(!/^github_pat_[A-Za-z0-9_]+$/.test(b.toString('ascii')))process.exit(72);
const env={...process.env,COPILOT_GITHUB_TOKEN:b.toString('ascii')};b.fill(0);
const child=cp.spawn('/usr/local/bin/copilot',process.argv.slice(1),{env,stdio:['ignore','inherit','inherit'],shell:false});
delete env.COPILOT_GITHUB_TOKEN;
child.on('error',()=>{console.log(JSON.stringify({type:'cp01.transport_error',data:{reason:'CLI could not start'}}));process.exitCode=73});
child.on('exit',(code,signal)=>{
 try{const file='/home/copilot/cp01-final-usage.json';if(fs.existsSync(file)&&fs.statSync(file).size<=1048576){console.log(JSON.stringify({type:'cp01.captured_usage',data:JSON.parse(fs.readFileSync(file,'utf8'))}))}}
 catch{console.log(JSON.stringify({type:'cp01.usage_capture_error',data:{reason:'Usage file could not be parsed'}}))}
 process.exitCode=Number.isInteger(code)?code:1;
});
"""


def live_args():
    case = next(c for c in pilot.cases() if c['id'] == 'CP-01')
    return review_route.validate_args([*pilot.FLAGS, '--agent=' + review_route.AGENT_ID, '--log-level=error',
            '--secret-env-vars=COPILOT_GITHUB_TOKEN',
            '--max-ai-credits='+str(SOFT_CREDIT_CEILING),
            '--usage-output-file='+USAGE_PATH, '-p', pilot.prompt(case)])


def command(image, endpoint, name):
    cmd = offline_preflight.command(image, ROOT/'contexts/CP-01', endpoint,
        ['-e',BOOTSTRAP,'--',*live_args()],entrypoint='node',name=name)
    cmd[cmd.index('--network=none')]='--network=bridge'
    for flag in ('--interactive','--log-driver=none','--ulimit=core=0:0'):
        cmd.insert(cmd.index('run')+1,flag)
    return cmd


def reserve(path, receipt):
    # A crash or failed invocation consumes the guard. It is never removed by
    # this runner, and neither the generic ledger nor other cases are changed.
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(receipt,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())


def baseline():
    billing=pilot.load(EVIDENCE/'billing-immediately-before.json')
    credentials=pilot.load(EVIDENCE/'auth-immediately-before-final.json')
    now=dt.datetime.now(dt.timezone.utc)
    for receipt in (billing,credentials):
        age=(now-dt.datetime.fromisoformat(receipt['checked_at'])).total_seconds()
        if not 0<=age<=180:
            raise ValueError('Fresh immediately-before Billing and auth evidence required')
    if billing.get('plan')!='Copilot Free' or billing.get('additional_usage')!='Not enabled':
        raise ValueError('Copilot Free and disabled paid usage must be confirmed')
    if credentials.get('status')!='passed' or credentials.get('auth',{}).get('isAuthenticated') is not True:
        raise ValueError('CLI authentication must pass before AI')
    return billing,credentials


def parse_output(text):
    events=[];invalid=0
    for line in text.splitlines():
        if not line.strip():continue
        try:events.append(json.loads(line))
        except json.JSONDecodeError:invalid+=1
    usage=[x.get('data') for x in events if isinstance(x,dict) and x.get('type')=='cp01.captured_usage']
    messages=[]
    for event in events:
        if not isinstance(event,dict):continue
        if event.get('type')=='assistant.message':
            content=event.get('data',{}).get('content')
            if isinstance(content,str):messages.append(content)
    stats=usage[-1] if usage else None
    models=[]
    if isinstance(stats,dict):
        models=[name for name,value in stats.get('modelMetrics',{}).items()
                if isinstance(value,dict) and value.get('requests',{}).get('count',0)>0]
    return {'events':events,'invalid_jsonl_lines':invalid,'usage':stats,
            'messages':messages,'observed_models_from_usage':models}


def execute():
    if GUARD.exists() or OUTPUT.exists():
        raise ValueError('CP-01 already reserved or output exists; no retry permitted')
    case=next(c for c in pilot.cases() if c['id']=='CP-01')
    context=pilot.check_context(ROOT/'contexts/CP-01',case)
    state,env=runtime_setup.environment()
    image=pilot.load(EVIDENCE/'runtime-image-with-ca.json')
    review_route.require_proof(image['image'], context['context_sha256'])
    offline=pilot.load(EVIDENCE/'offline-runtime-preflight-with-ca.json')
    vm=pilot.load(EVIDENCE/'vm-isolation-runtime.json')
    endpoint='unix://'+str(Path(state['root'])/'colima/copilot-pilot/docker.sock')
    if endpoint!=image['docker_host'] or offline['image']!=image['image']:
        raise ValueError('Private pinned runtime mismatch')
    if offline['runtime']!='passed' or not all(vm['checks'].values()):
        raise ValueError('Isolation has not passed')
    if offline['context_sha256']!=context['context_sha256']:
        raise ValueError('Snapshot changed after preflight')
    billing,credentials=baseline()
    live_args()  # Validate the route before Keychain access or reservation.
    run_id=uuid.uuid4().hex
    name='cp01-once-'+run_id
    docker=str(ROOT/'.cache/components/bin/docker')
    result={'schema_version':1,'run_id':run_id,'case':case,'mode':'copilot_builtin_review',
        'status':'interrupted','error':'Reserved; never retry automatically',
        'cli_version':'1.0.98','actual_model':None,'duration_seconds':0,
        'credits':{'used':None,'source':'Pending supported session usage and GitHub Billing'},
        'review':None,'started_at':pilot.now(),'context_sha256':context['context_sha256'],
        'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'engine_verified':False,'requested_model':'auto','image':image['image'],
        'authorization_exception':'Exactly one CP-01 using included Free allowance; unknown allowance and unguaranteed 10% threshold accepted',
        'soft_session_credit_ceiling':SOFT_CREDIT_CEILING,'ai_invocations_reserved':1,
        'billing_before':billing,'sessionless_auth_and_quota_before':credentials,
        'additional_paid_usage':'Not enabled','automatic_retry_permitted':False}
    proc=None
    started=None
    try:
        with keychain_helper.pat(user_interaction=True) as secret:
            baseline()  # The native dialog may have taken time; fail before reservation.
            OUTPUT.mkdir(mode=0o700)
            reserve(GUARD,{'case':'CP-01','run_id':run_id,'reserved_at':pilot.now(),
                           'no_retry':True,'authorization_scope':'CP-01 only'})
            pilot.save(OUTPUT/'result.json',result)
            pilot.save(OUTPUT/'launch-plan.json',{'case':case,'args':live_args(),
                'image':image['image'],'context_sha256':context['context_sha256'],
                'credentials_in_argv_or_docker_environment':False})
            started=time.monotonic()
            proc=subprocess.Popen(command(image['image'],endpoint,name),env=env,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            proc.stdin.write(struct.pack('>I',len(secret._buffer)))
            proc.stdin.write(secret._buffer);proc.stdin.flush()
            try:
                stdout,stderr=proc.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                subprocess.run([docker,'--host='+endpoint,'rm','-f',name],env=env,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                stdout,stderr=proc.communicate(timeout=20)
                result['error']='CP-01 timed out; no retry permitted'
            result['duration_seconds']=time.monotonic()-started
            # Exact-value redaction occurs before any serialization. CLI also
            # redacts COPILOT_GITHUB_TOKEN using its supported secret-env option.
            out=pilot.scrub(stdout.replace(secret._buffer,b'[REDACTED]').decode(errors='replace'))
            err=pilot.scrub(stderr.replace(secret._buffer,b'[REDACTED]').decode(errors='replace'))
            parsed=parse_output(out)
            (OUTPUT/'review-events.jsonl').write_text(out)
            (OUTPUT/'review-stderr.txt').write_text(err)
            pilot.save(OUTPUT/'session-usage.json',parsed['usage'])
            result['review']=out or None
            result['actual_model']=parsed['observed_models_from_usage'] or None
            result['cli_exit_code']=proc.returncode
            result['invalid_jsonl_lines']=parsed['invalid_jsonl_lines']
            result['session_usage_available']=parsed['usage'] is not None
            if proc.returncode==0 and out.strip():
                result['status']='completed';result['error']=None
            else:
                result['status']='error'
                result['error']=result['error'] if 'timed out' in str(result['error']) else 'CLI did not complete CP-01; no retry permitted'
            if parsed['messages']:
                (OUTPUT/'findings.md').write_text('\n\n'.join(parsed['messages'])+'\n')
    finally:
        if proc:
            subprocess.run([docker,'--host='+endpoint,'rm','-f',name],env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            absent=subprocess.run([docker,'--host='+endpoint,'ps','-aq','--filter=name=^/'+name+'$'],
                env=env,capture_output=True,timeout=30)
            result['container_removed']=absent.returncode==0 and not absent.stdout.strip()
        if started is not None and result['duration_seconds']==0:
            result['duration_seconds']=time.monotonic()-started
        if GUARD.exists() and OUTPUT.exists():pilot.save(OUTPUT/'result.json',pilot.validate_result(result))
    return {k:result[k] for k in ('status','error','cli_exit_code','duration_seconds','actual_model','container_removed') if k in result}


if __name__=='__main__':
    try:
        print(json.dumps(execute()))
    except Exception:
        # Do not echo credential-handling exceptions, argv, or environments.
        print(json.dumps({'status':'blocked','reason':'One-shot CP-01 runner stopped safely; inspect sanitized receipts; never retry if reserved'}))
        raise SystemExit(2)
