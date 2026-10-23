"""Separate prompt-review track. CLI entry points are OFFLINE ONLY; never read credentials."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
import uuid

import offline_preflight
import pilot as p

TRACK = 'copilot_cli_prompt_review_v1'
MODE = 'copilot_prompt_review'
TEMPLATE = p.ROOT / 'prompt-review/review-prompt.txt'
IMAGE = 'sha256:a6db151bc33e9e91f688c07b7ce2da52f2b9fa4a9f24e87b0f105ea84c5a5333'
USAGE = '/home/copilot/prompt-review-usage.json'


def rendered_prompt(case):
    return TEMPLATE.read_text().replace('BASE_SHA', case['base']).replace('HEAD_SHA', case['head'])


def args_for(case, credit_limit):
    # A soft CLI ceiling is not a hard budget guarantee. No default budget exception.
    if type(credit_limit) not in (int, float) or not 30 <= credit_limit < float('inf'):
        raise ValueError('Supported finite session ceiling of at least 30 required')
    return [*p.FLAGS, '--log-level=error', '--secret-env-vars=COPILOT_GITHUB_TOKEN',
            '--usage-output-file=' + USAGE, '--max-ai-credits=' + str(credit_limit),
            '-p', rendered_prompt(case)]


def validate_args(args, case, credit_limit):
    # Exact equality also rejects added shell/write, agents, resume and extra prompts.
    if args != args_for(case, credit_limit):
        raise ValueError('Prompt track invocation differs from its frozen protocol')
    return args


def config(case_id='CP-02'):
    if case_id != 'CP-02':
        raise ValueError('Only CP-02 is prepared; no automatic subsequent cases')
    case = next(c for c in p.cases() if c['id'] == case_id)
    context = p.ROOT / 'contexts' / case_id
    meta = p.check_context(context, case)
    state = p.load(p.ROOT / '.cache/runtime-state.json')
    return {'schema_version': 1, 'track': TRACK, 'mode': MODE, 'first_case': case,
            'cli_version': '1.0.98', 'image': IMAGE, 'requested_model': 'auto',
            'docker_host': 'unix://' + state['root'] + '/colima/' + state['profile'] + '/docker.sock',
            'context': str(context), 'context_sha256': meta['context_sha256'],
            'prompt': rendered_prompt(case), 'prompt_sha256': p.digest(rendered_prompt(case).encode()),
            'template_sha256': p.digest(TEMPLATE.read_bytes()),
            'output_schema_sha256': p.digest((TEMPLATE.parent / 'output.schema.json').read_bytes()),
            'flags': list(p.FLAGS), 'agent_args': [], 'slash_command': None,
            'builtin_engine': False, 'case_order': ['CP-02'], 'automatic_retry': False,
            'result_namespace': 'runs/prompt-review-v1/',
            'guard_namespace': '.cache/prompt-review-v1-CP-02-consumed.json',
            'budget_ledger': 'private/budget.json', 'budget_policy': 'existing numeric 10%/30% thresholds; no new exception',
            'credential_transport': 'existing local Keychain helper; length-framed stdin to CLI child only; never env on Docker',
            'usage_file': USAGE, 'live_authorized': False, 'live_execution_enabled': False,
            'pending_live_gates': ['separate explicit CP-02 authorization',
                'fresh VM/container, sessionless authentication and Free/Billing checks',
                'measured numeric shared budget or separately authorized single-case exception',
                'one-shot reservation under shared pilot lock before inference'],
            'cap_is_soft': True, 'model_quality_verified': False}


def validate_config(value):
    if value != config():
        raise ValueError('Configuration differs from sealed CP-02 protocol')
    return value


def candidate_command(value, endpoint, name, credit_limit):
    """Reviewable future launch specification, not an execution entry point.

    The existing credential transport must be used by a separately authorized
    one-shot runner; this offline module never reads Keychain or launches this.
    """
    validate_config(value)
    if endpoint != value['docker_host']:
        raise ValueError('Only the verified private VM endpoint is permitted')
    args = validate_args(args_for(value['first_case'], credit_limit), value['first_case'], credit_limit)
    from live_cp01 import BOOTSTRAP
    bootstrap = BOOTSTRAP.replace('/home/copilot/cp01-final-usage.json', USAGE)
    bootstrap = bootstrap.replace('cp01.', 'prompt_review.')
    cmd = offline_preflight.command(IMAGE, Path(value['context']), endpoint,
        ['-e', bootstrap, '--', *args], entrypoint='node', name=name)
    cmd[cmd.index('--network=none')] = '--network=bridge'
    for flag in ('--interactive', '--log-driver=none', '--ulimit=core=0:0'):
        cmd.insert(cmd.index('run') + 1, flag)
    return cmd


def budget_gate(ledger):
    # Shared spending, freshness and pending-request constraints are unchanged.
    # CP-02 is the first and only prepared case in THIS separate methodology.
    limit = p.budget_capacity(ledger)
    if any(x.get('track') == TRACK or x.get('case_id') == 'CP-02' for x in ledger.get('attempts', [])):
        raise ValueError('Prompt track already attempted or CP-02 already reserved; no retry')
    if len(ledger.get('attempts', [])) >= 2:
        raise ValueError('Shared two-invocation stop remains in force')
    if limit < 30:
        raise ValueError('Supported soft ceiling minimum exceeds remaining numeric budget')
    return limit


def dry_run(output):
    value = config()
    output = Path(output)
    if output.exists():
        raise ValueError('Existing results are immutable; choose a fresh directory')
    output.mkdir(mode=0o700, parents=True)
    p.save(output / 'config.json', value)
    result = {'schema_version': 1, 'run_id': uuid.uuid4().hex, 'case': value['first_case'],
              'mode': MODE, 'track': TRACK, 'status': 'dry_run', 'error': None,
              'cli_version': None, 'actual_model': None, 'duration_seconds': 0,
              'credits': {'used': 0, 'source': 'offline only; no model invocation'},
              'review': None, 'started_at': p.now(), 'context_sha256': value['context_sha256'],
              'prompt_sha256': value['prompt_sha256'], 'engine_verified': False,
              'protocol_verified': False, 'live_authorized': False}
    p.save(output / 'result.json', validate_result(result))
    return result


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def strict_json(text):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate JSON key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('Nonfinite JSON number')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)


def verify_history(case, context, repo):
    """Read Git objects only; bind every model-visible blob to its historical OID."""
    meta = p.check_context(context, case)
    verified = p.verify_case(case, repo)
    index = p.load(Path(context) / 'index.json')
    if any(index['trees'][side] != p.tree(repo, case[side]) for side in ('base', 'head')):
        raise ValueError('Historical tree mismatch')
    for oid in {item['oid'] for rows in index['trees'].values() for item in rows if item['type'] == 'blob'}:
        blob = p.load(Path(context) / 'blobs' / (oid + '.json'))
        data = blob['content'].encode('utf-8') if blob['encoding'] == 'utf-8' else base64.b64decode(blob['content'], validate=True)
        if blob['git_oid'] != oid or hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != oid:
            raise ValueError('Historical blob identity mismatch')
    diff = p.git(repo, '-c', 'diff.renames=false', 'diff', '--no-ext-diff', '--no-textconv',
                 '--no-color', '--no-renames', '--full-index', '--binary', '--src-prefix=a/',
                 '--dst-prefix=b/', case['base'], case['head'], '--').stdout
    if diff != (Path(context) / 'diff.txt').read_bytes() or not diff.strip():
        raise ValueError('Missing or mismatched historical diff')
    return {'case': case, 'objects': verified, 'context_sha256': meta['context_sha256'],
            'full_blob_identity_check': True, 'diff_sha256': p.digest(diff), 'ai_requests': 0}


def validate_review(review, context, case):
    """Strict syntactic + source-location checks; semantic correctness needs adjudication."""
    p.check_context(context, case)
    value = strict_json(review)
    keys = {'schema_version', 'base_sha', 'head_sha', 'summary', 'findings', 'coverage'}
    if not isinstance(value, dict) or set(value) != keys or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('Invalid prompt-review output structure')
    if value['base_sha'] != case['base'] or value['head_sha'] != case['head'] or not nonempty(value['summary']):
        raise ValueError('Review must bind exact historical SHA')
    index = p.load(Path(context) / 'index.json')
    trees = {s: {x['path']: x for x in index['trees'][s] if x['type'] == 'blob'} for s in ('base', 'head')}
    coverage = value['coverage']
    if not isinstance(coverage, dict) or set(coverage) != {'inspected_paths', 'limitations'}:
        raise ValueError('Coverage required')
    paths = coverage['inspected_paths']
    if not isinstance(paths, list) or not paths or any(not isinstance(x, str) for x in paths) or len(set(paths)) != len(paths) or any(x not in trees['base'] and x not in trees['head'] for x in paths):
        raise ValueError('Inspected paths must exist in historical trees')
    if not isinstance(coverage['limitations'], list) or any(not nonempty(x) for x in coverage['limitations']):
        raise ValueError('Invalid coverage limitations')
    if not isinstance(value['findings'], list):
        raise ValueError('Findings must be an array')
    seen = set()
    for f in value['findings']:
        required = {'id', 'priority', 'title', 'path', 'side', 'line_start', 'line_end', 'trigger', 'impact', 'evidence', 'confidence'}
        if not isinstance(f, dict) or set(f) != required or not isinstance(f['id'], str) or not re.fullmatch(r'F[1-9][0-9]*', f['id']) or f['id'] in seen:
            raise ValueError('Invalid/duplicate finding structure')
        seen.add(f['id'])
        if f['priority'] not in ('P1', 'P2') or f['confidence'] != 'high' or f['side'] not in trees:
            raise ValueError('Only evidenced high-confidence P1/P2 findings accepted')
        if not all(nonempty(f[k]) for k in ('title', 'path', 'trigger', 'impact', 'evidence')):
            raise ValueError('Evidence, trigger and impact required')
        if f['path'] not in paths or f['path'] not in trees[f['side']]:
            raise ValueError('Finding path outside inspected historical context')
        start, end = f['line_start'], f['line_end']
        blob = p.load(Path(context) / 'blobs' / (trees[f['side']][f['path']]['oid'] + '.json'))
        if blob['encoding'] != 'utf-8':
            raise ValueError('Text evidence required for a line finding')
        lines = blob['content'].splitlines()
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines) or end - start > 10:
            raise ValueError('Invalid source line range')
        if f['evidence'] not in '\n'.join(lines[start - 1:end]):
            raise ValueError('Evidence must be an exact source excerpt at the cited lines')
    return value


def validate_result(result):
    p.validate_result(result)
    value = config()
    if result.get('mode') != MODE or result.get('track') != TRACK or result.get('engine_verified') is not False:
        raise ValueError('Prompt track must not claim built-in engine identity')
    if result['case'] != value['first_case'] or result['context_sha256'] != value['context_sha256'] or result.get('prompt_sha256') != value['prompt_sha256']:
        raise ValueError('Result differs from frozen prompt/context/track identity')
    if result['status'] == 'completed':
        if result.get('protocol_verified') is not True or result['cli_version'] != '1.0.98':
            raise ValueError('Completed prompt result needs observed protocol and CLI evidence')
        proof = result.get('protocol_evidence', {})
        validate_args(proof.get('cli_args'), value['first_case'], proof.get('credit_limit'))
        if type(proof.get('exit_code')) is not int or proof['exit_code'] != 0 or not isinstance(proof.get('events_sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', proof['events_sha256']):
            raise ValueError('Successful CLI exit and exact captured-event identity required')
        validate_review(result['review'], Path(value['context']), value['first_case'])
    if result['status'] == 'dry_run' and (result['credits']['used'] != 0 or result['review'] is not None or result.get('protocol_verified') is not False):
        raise ValueError('Dry-run cannot attest an AI review')
    return result


def parse_capture(raw, value, cli_args, credit_limit, exit_code):
    """Validate a future capture offline. Never retries malformed model output."""
    validate_config(value)
    validate_args(cli_args, value['first_case'], credit_limit)
    if type(exit_code) is not int or exit_code != 0:
        raise ValueError('Failed CLI invocation; preserve evidence, no retry')
    events = [strict_json(line) for line in raw.splitlines() if line.strip()]
    if not events or any(not isinstance(e, dict) for e in events):
        raise ValueError('Strict JSONL capture required')
    users = [e for e in events if e.get('type') == 'user.message']
    results = [e for e in events if e.get('type') == 'result']
    usages = [e['data'] for e in events if e.get('type') == 'prompt_review.captured_usage']
    if len(users) != 1 or users[0].get('data', {}).get('content') != value['prompt'] or len(results) != 1 or results[0].get('exitCode') != 0 or len(usages) != 1:
        raise ValueError('Exactly one fixed user prompt, successful result and usage capture required')
    context = Path(value['context'])
    meta = p.check_context(context, value['first_case'])
    allowed = {'/context/' + name for name in meta['files']} | {'/context/context.json'}
    for e in events:
        kind, data = e.get('type', ''), e.get('data', {})
        if 'agent_selected' in kind or kind.startswith(('subagent.', 'task.')):
            raise ValueError('Agent/delegation events cannot enter prompt benchmark')
        if kind == 'tool.execution_start' and (data.get('toolName') != 'view' or data.get('arguments', {}).get('path') not in allowed):
            raise ValueError('Unexpected tool or read outside historical snapshot')
    messages = [e.get('data', {}).get('content') for e in events if e.get('type') == 'assistant.message']
    if not messages or not isinstance(messages[-1], str):
        raise ValueError('Final assistant review missing')
    review = messages[-1]
    validate_review(review, context, value['first_case'])
    usage = usages[0]
    models = sorted(name for name, item in usage.get('modelMetrics', {}).items()
                    if item.get('requests', {}).get('count', 0) > 0)
    nano = usage.get('totalNanoAiu')
    # Conversion is verified against the pinned official native runtime.
    complete = usage.get('aiCreditsStatus') == 'complete'
    credits = nano / 1_000_000_000 if type(nano) is int and nano >= 0 and complete else None
    return {'review': review, 'actual_model': models or None, 'session_usage': usage,
            'credits': {'used': credits, 'source': 'supported session usage' if credits is not None else 'usage missing or incomplete; Billing reconciliation pending'},
            'protocol_evidence': {'cli_args': cli_args, 'credit_limit': credit_limit,
                                  'exit_code': exit_code, 'events_sha256': p.digest(raw.encode())}}


def evaluate(truth, judgments, results):
    for result in results:
        validate_result(result)
    value = p.evaluate(truth, judgments, results, expected_mode=MODE)
    value['replacement_decision'] = 'not established; selected historical cases in a separate prompt-based track, not equivalent to builtin review'
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    dry = sub.add_parser('dry-run'); dry.add_argument('--out', type=Path, required=True)
    check = sub.add_parser('validate-output'); check.add_argument('review', type=Path)
    judge = sub.add_parser('evaluate')
    judge.add_argument('--truth', type=Path, default=p.ROOT / 'private/ground-truth.json')
    judge.add_argument('--judgments', type=Path, required=True)
    judge.add_argument('--results', type=Path, nargs='+', required=True)
    judge.add_argument('--out', type=Path, required=True)
    a = parser.parse_args()
    if a.action == 'dry-run':
        result = dry_run(a.out)
        print(json.dumps({'status': result['status'], 'track': TRACK, 'case': 'CP-02', 'ai_requests': 0}))
    elif a.action == 'validate-output':
        c = config(); validate_review(a.review.read_text(), Path(c['context']), c['first_case'])
        print('valid structure and historical evidence; semantic adjudication pending')
    else:
        results = [validate_result(p.load(x)) for x in a.results]
        if not results or any(r['status'] != 'completed' for r in results):
            raise ValueError('Do not open evaluator truth before a completed prompt review')
        if a.out.exists():
            raise ValueError('Existing evidence is immutable')
        p.save(a.out, evaluate(p.load(a.truth), p.load(a.judgments), results))


if __name__ == '__main__':
    main()
