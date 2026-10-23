"""Pinned built-in review route. Metadata proof never authorizes AI execution."""
import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = '1.0.98'
AGENT_ID = 'code-review.agent.yaml'
IMAGE = 'sha256:a6db151bc33e9e91f688c07b7ce2da52f2b9fa4a9f24e87b0f105ea84c5a5333'
PROOF = ROOT / 'evidence/review-routing-offline-2026-10-19/final/validated-routing.json'
PROBE = ROOT / 'review_route_probe.js'
SOURCE_HASHES = {
    'cli-main.js': '151c2e2a37ddb2514fc5cdbd5c473f9aeeb1a74d59e5062f3921a46d12a8f1c2',
    'prebuilds/linux-arm64/runtime.node': 'b65157f124be5e46a1809388296fa1e74a0da1e4126dfe2a68f7581fe42b7579',
    'definitions/code-review.agent.yaml': '1290258ee70b44faca1f0c74be26254f13e8401e825713ff3f5523b848b361f9'}
LIVE_BLOCKER = ('CLI 1.0.98 built-in review is blocked: direct selection lacks the host system-prompt callback; '
                'supported subagent prompt assembly and dispatch have not been verified before inference. '
                'Selection-only evidence cannot authorize a live route.')


def selected(agent):
    if not isinstance(agent, dict) or any(agent.get(k) != v for k, v in
            {'name': 'code-review', 'id': AGENT_ID, 'source': 'builtin'}.items()) or agent.get('path'):
        raise ValueError('Built-in code-review identity not established; no ordinary-prompt fallback')


def validate_probe(data):
    """Require actual RPC selection/readback, not help text or a requested name."""
    if data.get('network_none') is not True or data.get('credentials_absent') is not True:
        raise ValueError('Routing proof must be offline and credential-free')
    if data.get('source_anchors') is not True or data.get('literal_review_parse') is not None:
        raise ValueError('Pinned CLI dispatch contract changed')
    if data.get('source_sha256') != SOURCE_HASHES or data.get('selected_has_system_prompt') is not True or data.get('selected_prompt_nonempty') is not True:
        raise ValueError('Pinned built-in implementation or selected system prompt not established')
    if data.get('autopilot_control_parse', {}).get('name') != 'autopilot':
        raise ValueError('Parser control failed')
    selected(data.get('builtin'))
    calls = data.get('rpc', [])
    expected = [('session.commands.invoke', {'name': 'review', 'input': 'offline-probe; do not execute code'}),
                ('session.agent.getCurrent', {}), ('session.agent.select', {'name': AGENT_ID}),
                ('session.agent.getCurrent', {}), ('session.agent.select', {'name': 'missing-review-agent'}),
                ('session.agent.getCurrent', {})]
    if [(x.get('method'), x.get('params')) for x in calls] != expected:
        raise ValueError('Unexpected RPCs in routing proof')
    def result(index):
        response = calls[index].get('response', {})
        if response.get('ok') is not True:
            raise ValueError('Agent routing metadata RPC failed')
        return response['result']
    command = result(0)
    if command.get('kind') != 'agent-prompt' or 'task tool with agent_type: "code-review"' not in command.get('prompt', ''):
        raise ValueError('Interactive review dispatch contract changed')
    if result(1).get('agent') is not None:
        raise ValueError('Interactive command unexpectedly selected a root agent')
    for index in (2, 3, 5):
        selected(result(index).get('agent'))
    if calls[4].get('response', {}).get('ok') is not False:
        raise ValueError('Unknown-agent negative control did not fail')
    if set(data.get('host_effects', [])) != {'managed_plugin_admission', 'emit_event'}:
        raise ValueError('Unexpected host effects in routing proof')
    events = data.get('events', [])
    if len(events) != 1 or events[0].get('type') != 'subagent.selected' or events[0].get('data', {}).get('agentName') != 'code-review':
        raise ValueError('Actual agent-selection event missing')
    return True


def validate_args(args):
    if args.count('-p') != 1 or args.index('-p') != len(args) - 2 or not args[-1].strip() or args[-1].lstrip().startswith('/'):
        raise ValueError('Review requires one plain prompt after explicit agent selection')
    if [x for x in args[:-2] if x.startswith('--agent')] != ['--agent=' + AGENT_ID]:
        raise ValueError('Explicit verified built-in agent ID required; no fallback')
    prohibited = ('--yolo', '--allow-all', '--allow-all-tools', '--fleet', '--autopilot',
                  '--continue', '--resume', '--interactive', '-i', '--prompt')
    if any(x.split('=', 1)[0] in prohibited for x in args[:-2]):
        raise ValueError('Unsupported review invocation')
    fixed = {'--agent=' + AGENT_ID, '--available-tools=view', '--deny-tool=shell',
             '--deny-tool=write', '--deny-tool=memory', '--deny-tool=url', '--allow-tool=read',
             '--disable-builtin-mcps', '--no-custom-instructions', '--no-ask-user',
             '--no-auto-update', '--no-remote', '--no-remote-export', '--no-bash-env',
             '--disallow-temp-dir', '--output-format=json', '--log-level=error',
             '--secret-env-vars=COPILOT_GITHUB_TOKEN',
             '--usage-output-file=/home/copilot/cp01-final-usage.json'}
    for flag in args[:-2]:
        if flag in fixed:
            continue
        if flag.startswith('--max-ai-credits='):
            value = flag.split('=', 1)[1]
            if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value) and Decimal(value) >= 30:
                continue
        raise ValueError('Unsupported review argument; no ordinary-prompt fallback')
    if len(args[:-2]) != len(set(args[:-2])) or sum(x.startswith('--max-ai-credits=') for x in args[:-2]) != 1:
        raise ValueError('Duplicate or missing review controls')
    required = {'--available-tools=view', '--deny-tool=shell', '--deny-tool=write',
                '--deny-tool=memory', '--deny-tool=url', '--allow-tool=read',
                '--disable-builtin-mcps', '--no-custom-instructions', '--no-ask-user',
                '--no-auto-update', '--no-remote', '--no-remote-export', '--no-bash-env',
                '--disallow-temp-dir', '--output-format=json'}
    if not required.issubset(args):
        raise ValueError('Required isolation/tool controls missing')
    return args


def read_selection_proof(image, context_sha256, proof_path=None):
    """Identity metadata only. Does not prove system-prompt assembly or readiness."""
    try:
        proof = Path(proof_path) if proof_path is not None else PROOF
        receipt = json.loads(proof.read_text())
        raw = proof.parent / 'pinned-route-probe.json'
        data = json.loads(raw.read_text())
        if (image != IMAGE or receipt['image'] != image or receipt['cli_version'] != VERSION or
                receipt['context_sha256'] != context_sha256 or receipt['status'] != 'passed' or
                receipt['probe_sha256'] != hashlib.sha256(PROBE.read_bytes()).hexdigest() or
                receipt['raw_sha256'] != hashlib.sha256(raw.read_bytes()).hexdigest()):
            raise ValueError('Pinned routing evidence does not match runtime/context/probe')
        validate_probe(data)
        return receipt
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('Verified offline built-in routing evidence required before AI') from exc


def require_proof(image, context_sha256, proof_path=None):
    """Fail before credentials/reservation, even for a genuine selection receipt.

    Deliberately no override: re-enable only with a supported production path and
    deterministic pre-inference prompt/dispatch evidence, not more metadata flags.
    """
    raise ValueError(LIVE_BLOCKER)
