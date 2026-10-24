"""Versioned offline attestation sidecar; frozen review inputs are never changed.

Trust: host-owned network=none receiver hook + ephemeral in-memory HMAC key.
A receipt proves local HTTP transport only, never GitHub delivery or cognition.
No credentials, model invocation, admission or budget API in this module.
"""
import base64
import hashlib
import hmac
import json
import re
import prompt_review_v21_adapter as a
import pilot as p

VERSION = 'source-delivery-attestation-v1.0.0'
FIELDS = {'version','nonce','freeze_sha256','request_number','method','path',
          'authenticated_header_present','wire_bytes','wire_sha256','complete',
          'prompt_sha256','prompt_bytes','pages','canonical_telemetry_sha256',
          'transformed_telemetry_sha256','native_filter_sha256','tools'}
EVENTS = {'v2.transport_prepared','attestation.receiver','session.skills_loaded',
          'session.info','session.mcp_servers_loaded','session.tools_updated','user.message',
          'assistant.turn_start','model.call_start','assistant.message_start',
          'assistant.message_delta','model.call_finished','assistant.message',
          'model.call_final_result','assistant.turn_end','assistant.idle','result',
          'v2.captured_usage','v2.mock_endpoint','v2.transport_finished'}


def authenticate(envelope, key, nonce):
    if set(envelope) != {'payload','mac'} or len(key) != 32:
        raise ValueError('Incomplete receiver authentication')
    try:
        raw = base64.b64decode(envelope['payload'], validate=True)
        if len(raw)>65536 or not hmac.compare_digest(hmac.new(key,raw,hashlib.sha256).hexdigest(),envelope['mac']):
            raise ValueError('Receiver authentication failed')
        data = json.loads(raw)
    except (TypeError,ValueError):
        raise ValueError('Receiver authentication failed') from None
    if set(data)!=FIELDS or data['version']!=VERSION or data['nonce']!=nonce:
        raise ValueError('Incomplete or replayed receiver receipt')
    return data


def verify(bundle, context, case, events, envelope, key, nonce):
    a.verify(bundle,context,case)
    freeze=a.check_freeze()
    wire=authenticate(envelope,key,nonce)
    if any(e.get('type') not in EVENTS for e in events):
        raise ValueError('Unexpected CLI event; offline attestation fails closed')
    exact={'freeze_sha256':freeze,'request_number':1,'method':'POST','path':'/v1/chat/completions',
           'authenticated_header_present':False,'complete':True,
           'prompt_sha256':bundle['prompt_sha256'],'prompt_bytes':bundle['prompt_bytes'],
           'pages':bundle['expected_pages'],'tools':['view']}
    if any(type(wire[k]) is not type(v) or wire[k]!=v for k,v in exact.items()):
        raise ValueError('Incorrect or incomplete historical transport')
    for k in ('wire_sha256','canonical_telemetry_sha256','transformed_telemetry_sha256','native_filter_sha256'):
        if not isinstance(wire[k],str) or not re.fullmatch('[0-9a-f]{64}',wire[k]):
            raise ValueError('Invalid receiver hash')
    if type(wire['wire_bytes']) is not int or not bundle['prompt_bytes']<=wire['wire_bytes']<=2097152:
        raise ValueError('Truncated or excessive request')
    users=[(i,e.get('data',{})) for i,e in enumerate(events) if e.get('type')=='user.message']
    prep=[(i,e.get('data',{})) for i,e in enumerate(events) if e.get('type')=='v2.transport_prepared']
    starts=[i for i,e in enumerate(events) if e.get('type')=='model.call_start']
    ends=[e.get('data',{}) for e in events if e.get('type')=='v2.transport_finished']
    if len(users)!=1 or len(prep)!=1 or len(starts)!=1 or not prep[0][0]<users[0][0]<starts[0]:
        raise ValueError('Unexpected preparation, initial turn or dispatch')
    if any(prep[0][1].get(k)!=v for k,v in {'prompt_sha256':bundle['prompt_sha256'],
            'prompt_bytes':bundle['prompt_bytes'],'mock':True,'home_empty':True,
            'settings_model':None,'environment_model':None,'requested_selection':'offline-stub-only'}.items()):
        raise ValueError('Unexpected offline preparation')
    if len(ends)!=1 or any(ends[0].get(k)!=v for k,v in {'cli_exit_code':0,'timed_out':False,'mock':True,'automatic_retry':False}.items()):
        raise ValueError('Incomplete one-shot mock execution')
    user=users[0][1]
    for field,proof in [('content','canonical_telemetry_sha256'),('transformedContent','transformed_telemetry_sha256')]:
        if not isinstance(user.get(field),str) or p.digest(user[field].encode())!=wire[proof]:
            raise ValueError('Unexpected telemetry mutation; native forward redaction mismatch')
    if any(any(w in e.get('type','') for w in ('compact','truncate','subagent','agent_selected'))
           or e.get('type','').startswith('task.') or e.get('type')=='tool.execution_start' for e in events):
        raise ValueError('Context rewriting, delegation or model tools forbidden')
    receivers=[e['data'] for e in events if e.get('type')=='attestation.receiver']
    if receivers!=[envelope]:
        raise ValueError('Missing, duplicated or contradictory receiver')
    endpoints=[e.get('data',{}) for e in events if e.get('type')=='v2.mock_endpoint']
    if (len(endpoints)!=1 or endpoints[0].get('requests')!=1
            or endpoints[0].get('real_model_requests')!=0
            or len(endpoints[0].get('receipts',[]))!=1):
        raise ValueError('Missing or contradictory frozen mock receiver')
    legacy=endpoints[0]['receipts'][0]
    expected={'received_prompt_sha256':wire['prompt_sha256'],'source_pages':wire['pages'],
              'unmodified_prompt_present':True,'authentication_header_present':False,'tools':['view']}
    if any(type(legacy.get(k)) is not type(v) or legacy[k]!=v for k,v in expected.items()):
        raise ValueError('Receiver telemetry contradicts authenticated transport')
    return {'attestation_version':VERSION,'methodology':a.VERSION,'freeze_sha256':freeze,
      'canonical':{'prompt_sha256':bundle['prompt_sha256'],'prompt_bytes':bundle['prompt_bytes'],
                   'context_sha256':bundle['context_sha256'],'case':case,'pages':bundle['expected_pages']},
      'transport':{'status':'verified_local_receiver','authentication':'ephemeral HMAC-SHA256; key not persisted',
                   'nonce':nonce,'wire_sha256':wire['wire_sha256'],'wire_bytes':wire['wire_bytes'],
                   'signed_receiver':envelope},
      'telemetry':{'status':'exact_native_forward_filter_match',
                  'security_redacted':p.digest(user['content'].encode())!=bundle['prompt_sha256'],
                  'native_filter_sha256':wire['native_filter_sha256']},
      'github_backend_delivery_proven':False,'model_consumption_proven':False,
      'real_ai_requests':0,'authorization_consumed':False,'benchmark_observation':False}
