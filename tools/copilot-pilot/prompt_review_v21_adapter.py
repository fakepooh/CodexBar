"""Frozen v2 prompt transport. Offline planner/validator; no live CLI entry point.

Live handoff must be called inside the existing mandatory preflight, shared lock,
budget and atomic one-shot reservation. This module never reads credentials.
"""
import json
import argparse
import datetime as dt
import os
from pathlib import Path
import re
import struct

import pilot as p
import prompt_review as v1
import prompt_review_v21_sources as v2
import offline_preflight

VERSION = 'prompt-review-v2.1.0'
TEMPLATE = p.ROOT / 'prompt-review-v2.1/adapter-prompt.txt'
LIMITS = {'page_bytes': 2000, 'max_pages': 40, 'max_prompt_bytes': 262144,
          'max_diff_bytes': 196608}
USAGE = '/home/copilot/v2-usage.json'
ARTIFACTS = ['prompt_review_v21_sources.py', 'prompt_review_v21_adapter.py', 'v21_transport.cjs',
             'v2_offline_transport_probe.py',
             'prompt-review-v2.1/adapter-prompt.txt', 'prompt-review-v2.1/output.schema.json',
             'prompt-review-v2.1/methodology.json', 'pilot.py', 'prompt_review.py',
             'offline_preflight.py', 'live_cp01.py', 'runtime_setup.py']
SECRET = re.compile(r'(?:github_pat_[A-Za-z0-9_]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def assert_clean(text):
    if SECRET.search(text):
        raise ValueError('Credential-shaped material rejected; raw content withheld')


def build(context, case):
    """Only sealed historical inputs; no evaluator, process env, worktree or refs."""
    context = Path(context)
    meta, trees, texts, changed = v2.historical_sources(context, case)
    selection = v2.select(texts, changed)
    diff = (context / 'diff.txt').read_text()
    if not diff.strip() or len(diff.encode()) > LIMITS['max_diff_bytes']:
        raise ValueError('Complete diff exceeds frozen limit; stop, never silently clip')
    all_pages = []
    for row in selection['selected']:
        path = row['path']; oid = trees['head'][path]['oid']
        records = []
        for part, content in enumerate(v2.pages(texts[path], LIMITS['page_bytes'])):
            lines = [json.loads(x) for x in content.splitlines()]
            records.append({'path': path, 'side': 'head', 'commit': case['head'], 'blob_oid': oid,
                            'page': part, 'line_start': lines[0]['line'], 'line_end': lines[-1]['line'],
                            'content_sha256': p.digest(content.encode()), 'content': content})
        all_pages.append(records)
    # Round-robin preserves entry coverage before taking deeper pages. Never
    # truncate a source line, page, diff or JSON record to fit a limit.
    candidates = [rows[i] for i in range(max(map(len, all_pages), default=0))
                  for rows in all_pages if i < len(rows)]
    instruction = TEMPLATE.read_text().replace('BASE_SHA', case['base']).replace('HEAD_SHA', case['head'])
    body = {'methodology': VERSION, 'base_sha': case['base'], 'head_sha': case['head'],
            'diff_sha256': p.digest(diff.encode()), 'complete_diff': diff, 'source_pages': [],
            'coverage_limits': {'discovery': selection['policy'], 'transport': LIMITS,
                                'discovery_omitted_files': len(selection['omissions']),
                                'transport_omitted_pages': len(candidates)}}
    def render():
        return instruction + '\n\nHISTORICAL_EVIDENCE_JSON\n' + canonical(body)
    if len(render().encode()) > LIMITS['max_prompt_bytes']:
        raise ValueError('Complete diff and instructions exceed prompt limit')
    omitted = []
    for page in candidates:
        body['source_pages'].append(page)
        body['coverage_limits']['transport_omitted_pages'] -= 1
        if (len(body['source_pages']) > LIMITS['max_pages']
                or len(render().encode()) > LIMITS['max_prompt_bytes']):
            body['source_pages'].pop()
            body['coverage_limits']['transport_omitted_pages'] += 1
            omitted.append({k: page[k] for k in ('path', 'blob_oid', 'page', 'line_start', 'line_end', 'content_sha256')})
    if not body['source_pages']:
        raise ValueError('No source page fits frozen transport policy')
    prompt = render(); assert_clean(prompt)
    receipts = [{k: page[k] for k in page if k != 'content'} for page in body['source_pages']]
    return {'methodology': VERSION, 'track': 'copilot_cli_prompt_review_v2_1', 'case': case,
            'context_sha256': meta['context_sha256'], 'prompt': prompt,
            'prompt_sha256': p.digest(prompt.encode()), 'prompt_bytes': len(prompt.encode()),
            'expected_pages': receipts, 'omitted_pages': omitted, 'selection': selection,
            'requested_selection': 'auto', 'actual_model': None, 'routing_events': [],
            'live_authorized': False, 'ai_requests': 0, 'delivery_status': 'planned_only'}


def verify(bundle, context, case):
    if bundle != build(context, case):
        raise ValueError('V2 handoff differs from frozen historical reconstruction')
    return bundle


def cli_args(credit_limit):
    # Keep existing read-only tool/OS policy and supported soft session ceiling.
    if type(credit_limit) not in (int, float) or not 30 <= credit_limit < float('inf'):
        raise ValueError('Existing finite supported soft credit ceiling required')
    flags = [x for x in p.FLAGS if x not in ('--available-tools=view', '--allow-tool=read')]
    # All selected source is inline. Deny model tools, including reads: this
    # prevents the model from inspecting process env/credentials via /proc or
    # requesting unselected material. OS read-only isolation remains mandatory.
    # Pinned CLI interprets an empty allowlist as defaults and prioritizes an
    # explicit available-tools entry over excluded-tools. Retain the verified
    # single view schema, but deny its read permission, verified natively below.
    return [*flags, '--available-tools=view', '--deny-tool=read', '--model=auto', '--log-level=error',
            '--secret-env-vars=COPILOT_GITHUB_TOKEN', '--usage-output-file=' + USAGE,
            '--max-ai-credits=' + str(credit_limit)]


def freeze_description():
    return {'methodology': VERSION, 'cli_version': '1.0.98', 'track': 'copilot_cli_prompt_review_v2_1',
            'image': v1.IMAGE,
            'requested_selection': 'auto', 'limits': LIMITS, 'discovery': v2.POLICY,
            'artifacts_sha256': {f: p.digest((p.ROOT/f).read_bytes()) for f in ARTIFACTS}}


def check_freeze():
    value = p.load(p.ROOT/'prompt-review-v2.1/freeze.json')
    if value != freeze_description():
        raise ValueError('V2 methodology changed after freeze; no credential or reservation permitted')
    return p.digest(canonical(value).encode())


def transport_script(mock=False, credit_limit=30, denial_probe=False):
    if denial_probe and not mock:
        raise ValueError('Synthetic permission probe is offline-only')
    script = (p.ROOT/'v21_transport.cjs').read_text()
    args = cli_args(credit_limit)
    if mock:
        # A deterministic local stub is not a model comparison or Auto proof.
        args[args.index('--model=auto')] = '--model=offline-transport-stub'
    return script.replace('/* CLI_ARGS */', canonical(args)).replace('/* MOCK */', 'true' if mock else 'false').replace('/* DENIAL_PROBE */', 'true' if denial_probe else 'false')


def require_admission(admission, bundle, freeze_sha, credit_limit):
    """Require upstream one-shot reservation and fresh mandatory preflight.

    This is evidence validation, not a grant of user authorization. A future
    controller must produce it only after the new explicit human authorization
    and unchanged numeric budget gate or that authorization's bounded exception.
    No existing CP-01/CP-02 guard or authorization can satisfy this new binding.
    """
    if not isinstance(admission, dict):
        raise ValueError('New explicit v2 authorization, preflight and reservation required')
    expected = {'methodology': VERSION, 'freeze_sha256': freeze_sha, 'case': bundle['case'],
                'prompt_sha256': bundle['prompt_sha256'], 'credit_limit': credit_limit,
                'maximum_live_invocations': 1, 'automatic_retry': False,
                'general_budget_policy_changed': False}
    if set(admission) != set(expected) | {'authorization_id', 'preflight'}:
        raise ValueError('Admission contains unapproved fields')
    if any(type(admission.get(k)) is not type(value) or admission[k] != value for k,value in expected.items()):
        raise ValueError('Admission does not bind this exact frozen one-shot run')
    authorization_id = admission.get('authorization_id', '')
    if not re.fullmatch(r'v2-[a-z0-9-]{8,80}', authorization_id):
        raise ValueError('New v2 authorization identity required')
    auth = p.load(p.ROOT/'private/v2-authorizations'/(authorization_id+'.json'))
    for key in ('authorization_id','methodology','case','maximum_live_invocations','automatic_retry'):
        if type(auth.get(key)) is not type(admission.get(key)) or auth.get(key) != admission.get(key):
            raise ValueError('Authorization scope mismatch')
    if auth.get('explicit_human_authorization') is not True or auth.get('additional_paid_usage_permitted') is not False:
        raise ValueError('Explicit single-case authorization with paid usage forbidden required')
    gate = admission.get('preflight', {})
    if (gate.get('account') != 'fakepooh' or gate.get('cli_version') != '1.0.98'
            or not all(gate.get(k) is True for k in ('isolation','historical_integrity','same_pat_identity',
                'sessionless_auth','copilot_free','paid_usage_disabled','billing_baseline_recorded'))):
        raise ValueError('Mandatory live preflight incomplete')
    age = (dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(gate['checked_at'])).total_seconds()
    if not 0 <= age <= 180:
        raise ValueError('Fresh immediately-before preflight required')
    if auth.get('single_case_unknown_allowance_exception') is not True:
        if p.budget_gate(p.load(p.ROOT/'private/budget.json'), bundle['case']['id']) < credit_limit:
            raise ValueError('Unchanged numeric budget gate blocks this session ceiling')
    guard = p.ROOT/'.cache'/(authorization_id+'-consumed.json')
    if guard.is_symlink() or p.load(guard) != admission:
        raise ValueError('Exact already-reserved one-shot guard required')
    return guard


def handoff(bundle, context, case, endpoint, name, credit_limit, admission=None):
    """Reviewable production recipe, not a launcher or authorization grant."""
    verify(bundle, context, case); freeze_sha = check_freeze()
    guard = require_admission(admission, bundle, freeze_sha, credit_limit)
    if case not in p.cases() or Path(context).resolve() != (p.ROOT/'contexts'/case['id']).resolve():
        raise ValueError('Exact manifest case and sealed snapshot required')
    v1.verify_history(case, context, p.load(p.ROOT/'local-repos.json')[case['repository']])
    state = p.load(p.ROOT/'.cache/runtime-state.json')
    expected = 'unix://' + state['root'] + '/colima/' + state['profile'] + '/docker.sock'
    if endpoint != expected:
        raise ValueError('Only existing private VM endpoint allowed')
    command = offline_preflight.command(v1.IMAGE, Path(context), endpoint,
        ['-e', transport_script(credit_limit=credit_limit)], entrypoint='node', name=name)
    command[command.index('--network=none')] = '--network=bridge'
    for flag in ('--interactive', '--log-driver=none', '--ulimit=core=0:0'):
        command.insert(command.index('run') + 1, flag)
    # Atomic single-use handoff. Failure/crash consumes it; never reset or retry.
    marker = guard.with_name(guard.stem+'-handoff-used.json')
    from live_cp01 import reserve
    reserve(marker, {'methodology': VERSION, 'prompt_sha256': bundle['prompt_sha256'],
                     'authorization_id': admission['authorization_id'], 'automatic_retry': False})
    return {'command': command, 'methodology': VERSION, 'freeze_sha256': freeze_sha,
            'prompt_sha256': bundle['prompt_sha256'], 'requested_selection': 'auto',
            'cli_args': cli_args(credit_limit), 'credit_limit': credit_limit,
            'requires_existing_preflight_lock_budget_and_fresh_one_shot_authorization': True}


def frame(bundle):
    # Credential frame, if ever authorized, is separate and added only by the
    # existing Keychain runner. It cannot become part of the prompt frame.
    raw = canonical({'prompt': bundle['prompt'], 'prompt_sha256': bundle['prompt_sha256']}).encode()
    return struct.pack('>I', len(raw)) + raw


def delivery_receipt(bundle, events):
    """Attest accepted initial prompt and subsequent dispatch, not cognition.

    Must be called even after failure; absent/contradictory proof invalidates the
    run and NEVER authorizes retry. GitHub wire payload is not independently seen.
    """
    users = [(i, x) for i, x in enumerate(events) if x.get('type') == 'user.message']
    starts = [i for i, x in enumerate(events) if x.get('type') == 'model.call_start']
    prepared = [(i, x.get('data', {})) for i, x in enumerate(events) if x.get('type') == 'v2.transport_prepared']
    if (len(prepared) != 1 or prepared[0][1].get('prompt_sha256') != bundle['prompt_sha256']
            or prepared[0][1].get('prompt_bytes') != bundle['prompt_bytes']):
        raise ValueError('Missing or contradictory trusted transport receipt')
    if len(users) != 1 or users[0][1].get('data', {}).get('content') != bundle['prompt']:
        raise ValueError('Missing or contradictory exact initial-prompt delivery proof')
    if not starts or starts[0] <= users[0][0]:
        raise ValueError('Dispatch must follow exact accepted initial prompt')
    if prepared[0][0] >= users[0][0]:
        raise ValueError('Preparation must precede acceptance')
    if any(any(word in x.get('type', '') for word in ('compact', 'truncate', 'subagent', 'agent_selected'))
           or x.get('type', '').startswith('task.') for x in events):
        raise ValueError('Unsupported context rewriting or delegation')
    if any(x.get('type') == 'tool.execution_start' for x in events):
        raise ValueError('Inline-only v2 permits no agent tools')
    return {'methodology': VERSION, 'channel': 'initial_user_prompt',
            'prompt_sha256': bundle['prompt_sha256'], 'pages': bundle['expected_pages'],
            'cli_accepted_exact_prompt': True, 'dispatch_followed_acceptance': True,
            'github_wire_payload_observed': False, 'model_attention_or_understanding_proven': False}


def validate_capture(bundle, events, usage, context):
    verify(bundle, context, bundle['case'])
    receipt = delivery_receipt(bundle, events)
    prepared = next(x['data'] for x in events if x.get('type') == 'v2.transport_prepared')
    if (prepared.get('mock') is not False or prepared.get('requested_selection') != 'auto'
            or prepared.get('settings_model') is not None or prepared.get('environment_model') is not None
            or prepared.get('home_empty') is not True):
        raise ValueError('Offline stub cannot qualify as a benchmark observation')
    finished = [x.get('data', {}) for x in events if x.get('type') == 'v2.transport_finished']
    if (len(finished) != 1 or finished[0].get('cli_exit_code') != 0
            or finished[0].get('mock') is not False or finished[0].get('timed_out') is not False):
        raise ValueError('Successful one-shot CLI transport completion required')
    captured_usage = [x.get('data') for x in events if x.get('type') == 'v2.captured_usage']
    if captured_usage != [usage] or set(usage.get('agentMetrics', {})) - {'main'}:
        raise ValueError('Exact single-session usage capture required')
    allowed = set(p.load(Path(context)/'context.json')['files']) | {'context.json'}
    for event in events:
        if event.get('type') == 'tool.execution_start':
            path = event.get('data', {}).get('arguments', {}).get('path', '')
            if not path.startswith('/context/') or path[len('/context/'):] not in allowed:
                raise ValueError('Read outside exact historical snapshot')
    models = v2.provenance(cli_args(30), events, usage)
    if models['mechanism'] != 'AUTO' or len(models['actual_models']) != 1:
        raise ValueError('Explicit Auto requires positive consistent routing and usage evidence')
    finals = [x for x in events if x.get('type') == 'result']
    if len(finals) != 1 or type(finals[0].get('exitCode')) is not int or finals[0]['exitCode'] != 0:
        raise ValueError('Completion proof required; no retry')
    messages = [x['data']['content'] for x in events if x.get('type') == 'assistant.message' and x.get('data', {}).get('content')]
    if not messages:
        raise ValueError('Final structured review missing')
    review = v1.validate_review(messages[-1], context, bundle['case'])
    return {'methodology': VERSION, 'delivery': receipt, 'selection': models, 'review': review,
            'actual_model': models['actual_models'][0], 'session_usage': usage,
            'github_wire_payload_observed': False}


def dry_run(case_id, output):
    output = Path(output)
    if output.exists():
        raise ValueError('Preserve previous evidence; output must be new')
    freeze_sha = check_freeze()
    case = next(c for c in p.cases() if c['id'] == case_id)
    context = p.ROOT/'contexts'/case_id
    v1.verify_history(case, context, p.load(p.ROOT/'local-repos.json')[case['repository']])
    bundle = build(context, case); verify(bundle, context, case)
    output.mkdir(parents=True, mode=0o700)
    p.save(output/'bundle.json', bundle)
    (output/'prompt.txt').write_text(bundle['prompt'])
    p.save(output/'run-config.json', {'methodology': VERSION, 'freeze_sha256': freeze_sha,
        'case': case, 'context_sha256': bundle['context_sha256'], 'prompt_sha256': bundle['prompt_sha256'],
        'cli_version': '1.0.98', 'image': v1.IMAGE, 'cli_args': cli_args(30),
        'requested_selection': 'auto', 'actual_model': None, 'routing_events': [],
        'status': 'offline_dry_run', 'delivery_status': 'planned_only',
        'expected_pages': bundle['expected_pages'], 'omitted_pages': bundle['omitted_pages'],
        'ai_requests': 0, 'authorization_used': False, 'live_admission_present': False})
    return bundle


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=['CP-02'], required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    bundle = dry_run(args.case, args.out)
    print(json.dumps({'status':'offline_dry_run','methodology':VERSION,'ai_requests':0,
                      'expected_pages':len(bundle['expected_pages']),'prompt_bytes':bundle['prompt_bytes']}))
