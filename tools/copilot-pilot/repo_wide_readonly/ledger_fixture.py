"""Hosted no-AI CAS acceptance. Fixture namespace never consumes a PUB guard."""
import concurrent.futures
import os
import threading

from .prepare import hosted
from .ledger import GitHubStore, RefAlreadyExists
from .snapshot import canonical


def probe(token, workflow_sha, run_id, attempt):
    hosted()
    if type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt != 1:
        raise ValueError('Offline CAS probe requires first workflow attempt')
    # Contains no PUB ID, AI authorization or live reservation prefix.
    ref = 'refs/tags/repo-wide-readonly-offline-cas-' + str(run_id)
    value = {'purpose': 'offline-cas-no-ai', 'workflow_sha': workflow_sha, 'run_id': run_id,
             'real_model_requests': 0, 'live_authorization_consumed': False}
    barrier = threading.Barrier(2)
    def once(_):
        store = GitHubStore(token, workflow_sha)
        barrier.wait(timeout=30)
        try:
            store.create_ref(ref, value)
            return 'CREATED'
        except RefAlreadyExists:
            return 'CONFLICT'
        except ValueError:
            return 'UNPROVED'
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(once, range(2)))
    store = GitHubStore(token, workflow_sha)
    if sorted(outcomes) != ['CONFLICT', 'CREATED'] or canonical(store.read(ref)) != canonical(value):
        raise ValueError('Exclusive remote CAS unproved')
    # Never retry a live mutation. This is a second deliberately conflicting fixture claim.
    try:
        store.create_ref(ref, value)
    except RefAlreadyExists:
        pass
    else:
        raise ValueError('Duplicate fixture claim unexpectedly succeeded')
    return {'status': 'PASS', 'purpose': 'offline-cas-no-ai', 'ref': ref,
            'exactly_one_winner': True, 'duplicate_claim_rejected': True,
            'remote_readback_verified': True, 'ref_updated_or_deleted': False,
            'real_model_requests': 0, 'new_live_reservations': 0}


if __name__ == '__main__':
    try:
        result = probe(os.environ['GITHUB_TOKEN'], os.environ['GITHUB_SHA'],
                       int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']))
    except Exception:
        result = {'status': 'BLOCKED', 'purpose': 'offline-cas-no-ai',
                  'reason': 'REMOTE_CREATE_ONLY_EXCLUSION_NOT_PROVED', 'real_model_requests': 0}
    print(canonical(result))
    raise SystemExit(0 if result['status'] == 'PASS' else 2)
