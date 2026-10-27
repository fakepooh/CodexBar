"""Pure durable-ledger contract. Transport must authenticate separately.

Only the reservation job may POST; reviewer job has no contents-write grant.
The immutable ref is created, never updated/deleted. A rerun cannot dispatch.
"""
import re
import json


EXPERIMENT = 'repo-wide-readonly-v1-20261026'


def intent(case, run_id, attempt, workflow_sha, methodology_sha, prompt_sha):
    if not re.fullmatch(r'PUB-(0[1-9]|10)', case):
        raise ValueError('Outside authorized ten-case inventory')
    if type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt != 1:
        raise ValueError('First attempt only; no workflow reruns')
    for value, length in ((workflow_sha, 40), (methodology_sha, 64), (prompt_sha, 64)):
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
            raise ValueError('Exact immutable hashes required')
    return {'experiment': EXPERIMENT, 'case': case, 'run_id': run_id, 'run_attempt': 1,
            'workflow_sha': workflow_sha, 'methodology_sha256': methodology_sha,
            'prompt_sha256': prompt_sha, 'automatic_retry': False}


def reserve(store, value):
    validate(value)
    ref = 'refs/tags/' + EXPERIMENT + '-' + value['case']
    # create_ref must be the GitHub atomic POST /git/refs, never GET-then-PUT.
    # False, 409, 422, uncertain network outcome and existing refs fail closed.
    result = store.create_ref(ref, value)
    if not same(result, {'created': True, 'ref': ref, 'intent': value}):
        raise ValueError('Exclusive durable reservation was not proved')
    return result


def verify(receipt, expected, current_attempt):
    validate(expected)
    if current_attempt != 1 or type(current_attempt) is not int:
        raise ValueError('A workflow rerun is not a new authorization')
    if not same(receipt, {'created': True,
                   'ref': 'refs/tags/' + EXPERIMENT + '-' + expected['case'],
                   'intent': expected}):
        raise ValueError('Reservation does not bind exact session identity')
    return True


def same(left, right):
    # JSON type identity matters: True must never stand for run_id=1.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def validate(value):
    if not isinstance(value, dict):
        raise ValueError('Exact reservation object required')
    try:
        expected = intent(value['case'], value['run_id'], value['run_attempt'],
                          value['workflow_sha'], value['methodology_sha256'], value['prompt_sha256'])
    except (KeyError, TypeError):
        raise ValueError('Incomplete reservation identity') from None
    if not same(value, expected):
        raise ValueError('Unexpected or contradictory reservation fields')
    return value
