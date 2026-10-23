"""Pinned CLI -> deterministic loopback HTTP stub inside network=none container.

No model, credentials, billing, budget reservation, or live authorization. Never
retry. A failure is evidence about transport, not a benchmark observation.
"""
import argparse
import json
from pathlib import Path
import subprocess
import uuid

import pilot as p
import prompt_review as v1
import prompt_review_v2_adapter as adapter
import offline_preflight
import runtime_setup


def probe(output, denial_probe=False):
    output = Path(output)
    if output.exists():
        raise ValueError('Preserve prior probe; output must be new')
    case = next(c for c in p.cases() if c['id'] == 'CP-02')
    context = p.ROOT/'contexts/CP-02'
    bundle = adapter.build(context, case)
    v1.verify_history(case, context, p.load(p.ROOT/'local-repos.json')[case['repository']])
    state, env = runtime_setup.environment()
    endpoint = 'unix://' + state['root'] + '/colima/' + state['profile'] + '/docker.sock'
    name = 'v2-offline-stub-' + uuid.uuid4().hex
    command = offline_preflight.command(v1.IMAGE, context, endpoint,
        ['-e', adapter.transport_script(mock=True, denial_probe=denial_probe)], entrypoint='node', name=name)
    command.insert(command.index('run') + 1, '--interactive')
    command.insert(command.index('run') + 1, '--log-driver=none')
    output.mkdir(mode=0o700, parents=True)
    result = None
    try:
        result = subprocess.run(command, input=adapter.frame(bundle), env=env,
                                capture_output=True, timeout=70)
    finally:
        docker = str(p.ROOT/'.cache/components/bin/docker')
        subprocess.run([docker, '--host='+endpoint, 'rm', '-f', name], env=env,
                       capture_output=True, timeout=20)
        absent = subprocess.run([docker, '--host='+endpoint, 'ps', '-aq', '--filter=name=^/'+name+'$'],
                                env=env, capture_output=True, timeout=20)
        if absent.returncode or absent.stdout.strip():
            raise ValueError('Probe container removal unverified')
    events = []; invalid = 0
    for line in result.stdout.decode(errors='replace').splitlines():
        try: events.append(json.loads(line))
        except ValueError: invalid += 1
    endpoints = [e['data'] for e in events if e.get('type') == 'v2.mock_endpoint']
    receipt = None; error = None
    try:
        if result.returncode or len(endpoints) != 1 or invalid:
            raise ValueError('Pinned CLI stub transport did not complete cleanly')
        endpoint_result = endpoints[0]
        expected_requests = 2 if denial_probe else 1
        if endpoint_result['requests'] != expected_requests or len(endpoint_result['receipts']) != expected_requests:
            raise ValueError('Exact bounded local stub request count required')
        wire = endpoint_result['receipts'][0]
        if (wire['received_prompt_sha256'] != bundle['prompt_sha256']
                or wire.get('source_pages') != bundle['expected_pages']
                or not wire['unmodified_prompt_present'] or wire['authentication_header_present']):
            raise ValueError('Mock wire delivery or credential isolation failed')
        if wire['tools'] != ['view']:
            raise ValueError('Only the permission-denied view schema is permitted')
        if denial_probe:
            negative = endpoint_result['receipts'][-1]
            if not negative['read_permission_denied'] or negative['private_sentinel_leaked']:
                raise ValueError('Native read permission denial not established')
            receipt = {'negative_permission_probe': True, 'read_denied': True, 'sentinel_leaked': False}
        else:
            receipt = adapter.delivery_receipt(bundle, events)
    except ValueError as exc:
        error = str(exc)
    # No raw request/response bodies, credentials, env dumps or unrelated content.
    summary = {'status': 'passed' if receipt else 'failed', 'error': error,
        'cli_exit_code': result.returncode, 'cli_version': '1.0.98', 'image': v1.IMAGE,
        'network': 'none; loopback stub in same container', 'container_removed': True,
        'real_ai_requests': 0, 'authorization_consumed': False,
        'negative_permission_probe': denial_probe,
        'methodology': adapter.VERSION, 'prompt_sha256': bundle['prompt_sha256'],
        'transport_script_sha256': p.digest(adapter.transport_script(mock=True, denial_probe=denial_probe).encode()),
        'source_sha256': {name:p.digest((p.ROOT/name).read_bytes()) for name in adapter.ARTIFACTS},
        'prompt_bytes': bundle['prompt_bytes'], 'delivered_page_count': len(bundle['expected_pages']),
        'mock_endpoint': endpoints, 'delivery': receipt,
        'event_types': [e.get('type') for e in events], 'invalid_jsonl_lines': invalid,
        'stdout_sha256': p.digest(result.stdout),
        'sanitized_stderr': p.scrub(result.stderr.decode(errors='replace'))[:3000]}
    p.save(output/'receipt.json', summary)
    p.save(output/'bundle-metadata.json', {k:v for k,v in bundle.items() if k != 'prompt'})
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--denial-probe', action='store_true')
    args = parser.parse_args()
    result = probe(args.out, args.denial_probe)
    print(json.dumps({k:result[k] for k in ('status','error','cli_exit_code','real_ai_requests','delivered_page_count')}))
    raise SystemExit(0 if result['status'] == 'passed' else 2)
