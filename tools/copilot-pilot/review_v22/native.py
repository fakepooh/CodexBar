"""Credential-free pinned CLI -> local mock verification in network=none VM.

Explicit offline entry only. It cannot enable inference. Reuses immutable v2.1
sender and native forward-redaction receiver, independently binds v2.2 payload.
"""
import argparse
import json
from pathlib import Path
import secrets
import struct
import subprocess
import time
import uuid

import pilot as p
import prompt_review as history
import prompt_review_v21_adapter as sender
import delivery_attestation_v21 as att
import offline_preflight as isolation
import runtime_setup
import bounded_process
from . import adapter as a, audit, transport


def validate(bundle, context, events, key, nonce, freeze):
    audit.verify_payload(bundle,context,bundle['case'])
    envelopes=[e.get('data') for e in events if e.get('type')=='attestation.receiver']
    if len(envelopes)!=1:raise ValueError('Exactly one authenticated receiver required')
    wire=att.authenticate(envelopes[0],key,nonce)
    for k,v in dict(freeze_sha256=freeze,request_number=1,method='POST',path='/v1/chat/completions',
                    authenticated_header_present=False,complete=True,
                    prompt_sha256=bundle['prompt_sha256'],prompt_bytes=bundle['prompt_bytes'],
                    pages=bundle['expected_pages'],tools=['view']).items():
        if type(wire.get(k)) is not type(v) or wire[k]!=v:raise ValueError('Native transport payload mismatch')
    if any(e.get('type') not in att.EVENTS for e in events):raise ValueError('Unexpected native event')
    users=[(i,e.get('data',{})) for i,e in enumerate(events) if e.get('type')=='user.message']
    prep=[(i,e.get('data',{})) for i,e in enumerate(events) if e.get('type')=='v2.transport_prepared']
    calls=[i for i,e in enumerate(events) if e.get('type')=='model.call_start']
    ends=[e.get('data',{}) for e in events if e.get('type')=='v2.transport_finished']
    if len(users)!=1 or len(prep)!=1 or len(calls)!=1 or not prep[0][0]<users[0][0]<calls[0]:
        raise ValueError('Unexpected native session/dispatch sequence')
    expected=dict(prompt_sha256=bundle['prompt_sha256'],prompt_bytes=bundle['prompt_bytes'],
                  mock=True,requested_selection='offline-stub-only',settings_model=None,environment_model=None,home_empty=True)
    if any(type(prep[0][1].get(k)) is not type(v) or prep[0][1][k]!=v for k,v in expected.items()):
        raise ValueError('Unexpected offline sender configuration')
    for field,hashfield in [('content','canonical_telemetry_sha256'),('transformedContent','transformed_telemetry_sha256')]:
        if not isinstance(users[0][1].get(field),str) or p.digest(users[0][1][field].encode())!=wire[hashfield]:
            raise ValueError('Unexpected native telemetry mutation')
    if len(ends)!=1 or any(type(ends[0].get(k)) is not type(v) or ends[0][k]!=v for k,v in
        dict(cli_exit_code=0,timed_out=False,mock=True,automatic_retry=False).items()):
        raise ValueError('Incomplete native one-shot')
    results=[e for e in events if e.get('type')=='result']
    endpoints=[e.get('data',{}) for e in events if e.get('type')=='v2.mock_endpoint']
    if len(results)!=1 or results[0].get('exitCode')!=0 or len(endpoints)!=1 or endpoints[0].get('requests')!=1 or endpoints[0].get('real_model_requests')!=0:
        raise ValueError('Incomplete native mock completion')
    return dict(status='PASS',methodology=a.VERSION,freeze_sha256=freeze,
                prompt_sha256=bundle['prompt_sha256'],pages=len(bundle['expected_pages']),
                cli_version='1.0.98',transport='byte-exact authenticated local HTTP receiver',
                native_forward_redaction_verified=True,real_ai_requests=0,
                github_delivery_proven=False,model_consumption_proven=False,authorization_consumed=False)


def probe(bundle, context, output):
    if output.exists():raise ValueError('Preserve previous evidence')
    freeze=a.check_freeze();audit.verify_payload(bundle,context,bundle['case'])
    key=secrets.token_bytes(32);nonce=secrets.token_hex(24)
    config=dict(key=key.hex(),nonce=nonce,freeze_sha256=freeze,prompt=bundle['prompt'],fault=None)
    raw=a.canonical(config).encode();del config
    data=struct.pack('>I',len(raw))+raw+transport.frame(bundle);del raw
    state,env=runtime_setup.environment()
    endpoint='unix://'+state['root']+'/colima/'+state['profile']+'/docker.sock'
    script=(p.ROOT/'delivery_receiver_hook.cjs').read_text()+'\n'+sender.transport_script(mock=True)
    name='v22-offline-'+uuid.uuid4().hex
    command=isolation.command(history.IMAGE,context,endpoint,['-e',script],entrypoint='node',name=name)
    for flag in ('--interactive','--log-driver=none','--ulimit=core=0:0'):command.insert(command.index('run')+1,flag)
    started=time.monotonic();result=None
    try:
        result=bounded_process.run(command,data=data,env=env,timeout=70)
    finally:
        del data
        docker=str(p.ROOT/'.cache/components/bin/docker')
        subprocess.run([docker,'--host='+endpoint,'rm','-f',name],env=env,capture_output=True,timeout=20)
        absent=subprocess.run([docker,'--host='+endpoint,'ps','-aq','--filter=name=^/'+name+'$'],env=env,capture_output=True,timeout=20)
        if absent.returncode or absent.stdout.strip():raise ValueError('Native test cleanup unverified')
        p.save(output/'lifecycle.json',dict(container_removed=True,seconds=time.monotonic()-started,
                                         real_ai_requests=0,automatic_retry=False))
    if result.returncode:raise ValueError('Native offline transport failed; no retry')
    events=[json.loads(line) for line in result.stdout.decode().splitlines()]
    receipt=validate(bundle,context,events,key,nonce,freeze)
    receipt.update(seconds=round(time.monotonic()-started,3),stdout_sha256=p.digest(result.stdout),container_removed=True)
    # Raw source-bearing telemetry and ephemeral receiver key are never persisted.
    p.save(output/'receipt.json',receipt)
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--context',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(probe(p.load(args.bundle),args.context,args.output)))
