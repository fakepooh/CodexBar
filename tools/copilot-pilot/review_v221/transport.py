"""Exact mock transport oracle and disabled-by-default diagnostic admission.

This module cannot launch a real session, read credentials or reserve budget.
Local transport proof is never proof of GitHub delivery/model consumption.
"""
import hashlib
import hmac
import json
import struct
from review_v22.context import canonical, digest
from .audit import verify_payload


def frame(bundle):
    raw = canonical(dict(prompt=bundle['prompt'], prompt_sha256=bundle['prompt_sha256'])).encode()
    return struct.pack('>I', len(raw))+raw


def receive(raw, bundle, key, nonce):
    if len(key) != 32 or len(raw) < 5:
        raise ValueError('Authenticated receiver required')
    size = struct.unpack('>I', raw[:4])[0]
    if size != len(raw)-4 or size > 1048576:
        raise ValueError('Incomplete or excessive transport')
    value = json.loads(raw[4:])
    if value != dict(prompt=bundle['prompt'], prompt_sha256=bundle['prompt_sha256']):
        raise ValueError('Transport content differs')
    body = json.loads(value['prompt'].split('HISTORICAL_EVIDENCE_JSON\n')[1])
    pages = [{k:v for k,v in p.items() if k != 'content'} for p in body['source_pages']]
    if pages != bundle['expected_pages']:
        raise ValueError('Incorrect page sequence')
    proof = dict(version='v22-local-transport-v1', nonce=nonce,
                 prompt_sha256=digest(value['prompt'].encode()), pages=pages,
                 wire_sha256=digest(raw), complete=True,
                 real_ai_requests=0, model_consumption_proven=False)
    encoded = canonical(proof).encode()
    return dict(proof=proof, mac=hmac.new(key, encoded, hashlib.sha256).hexdigest())


def validate(envelope, bundle, context, case, key, nonce):
    verify_payload(bundle, context, case)
    if set(envelope) != {'proof', 'mac'} or len(key) != 32:
        raise ValueError('Incomplete authenticated transport')
    proof = envelope['proof']
    if not hmac.compare_digest(envelope['mac'], hmac.new(key, canonical(proof).encode(), hashlib.sha256).hexdigest()):
        raise ValueError('Transport MAC mismatch')
    expected = receive(frame(bundle), bundle, key, nonce)
    if envelope != expected:
        raise ValueError('Incomplete, replayed or contradictory transport')
    return dict(status='PASS', channel='local mock receiver',
                prompt_sha256=bundle['prompt_sha256'], page_count=len(proof['pages']),
                model_consumption_proven=False, github_delivery_proven=False,
                real_ai_requests=0, authorization_consumed=False)


def require_new_authorization(record, bundle, freeze):
    # A plan is not a grant. Old consumed authorizations cannot be re-used.
    if (not isinstance(record, dict) or record.get('methodology') != bundle['methodology']
            or record.get('freeze_sha256') != freeze
            or record.get('prompt_sha256') != bundle['prompt_sha256']
            or record.get('explicit_new_human_authorization') is not True
            or record.get('maximum_sessions') != 1 or record.get('automatic_retry') is not False
            or record.get('paid_additional_usage') is not False
            or record.get('authorization_id', '').startswith(('v2-pub-', 'v2-cp'))
            or not record.get('fresh_preflight_verified')
            or not record.get('atomic_one_shot_reserved')):
        raise ValueError('New bounded authorization and mandatory fresh preflight required; live blocked')
    raise ValueError('Live execution disabled in this offline release; production controller integration required')
