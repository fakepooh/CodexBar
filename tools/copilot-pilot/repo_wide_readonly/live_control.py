"""Hosted admission and immutable one-shot handoff. No model or repair APIs."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import ssl
import urllib.request

from .freeze import verify as verify_freeze
from .ledger import GitHubStore, NoRedirect
from .reservations import intent, reserve, verify
from .snapshot import canonical, sha
from .validate import pairs

ROOT = Path(__file__).parent
OS_FIELDS = {'credential_env_absent', 'host_home_hidden', 'no_capabilities', 'no_docker_socket',
             'no_new_privileges', 'nonroot', 'root_readonly', 'snapshot_git_absent', 'snapshot_mount_readonly'}


def require_transport(proof):
    flags = ['exact_tool_results_received', 'host_escape_denied', 'local_receiver_authenticated',
             'exact_tool_result_order_verified', 'pre_dispatch_tool_catalog_verified', 'production_entry_mock_verified']
    if (proof.get('status') != 'PASS' or proof.get('native_cli_version') != '1.0.98'
            or any(proof.get(k) is not True for k in flags)
            or any(type(proof.get(k)) is not int or proof[k] != v
                   for k, v in [('real_model_requests', 0), ('mock_requests', 6), ('callback_count', 5)])
            or proof.get('selected_tools') != ['repo_glob', 'repo_grep', 'repo_view']
            or set(proof.get('os_isolation', {})) != OS_FIELDS
            or any(v is not True for v in proof['os_isolation'].values())):
        raise ValueError('PRODUCTION_OFFLINE_TRANSPORT_UNPROVED')
    return True


def admission(env, raw, now=None, root=ROOT):
    now = now or dt.datetime.now(dt.timezone.utc)
    required = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'fakepooh/CodexBar', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_ACTOR': 'fakepooh',
                'GITHUB_ACTOR_ID': '4489850', 'GITHUB_RUN_ATTEMPT': '1'}
    if any(env.get(k) != v for k, v in required.items()):
        raise ValueError('HOSTED_OWNER_MAIN_FIRST_ATTEMPT_REQUIRED')
    frozen = verify_freeze(root)
    policy = json.loads((root / 'live-policy.json').read_text())
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_ADMISSION')))
    keys = {'version', 'case', 'nonce', 'workflow_sha', 'freeze_sha256', 'observed_at',
            'account', 'owner_id', 'copilot_free', 'additional_paid_usage',
            'included_display', 'unknown_allowance_exception', 'budget_exception_sha256', 'ci_run_id'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('EXACT_ADMISSION_RECEIPT_REQUIRED')
    if (value['version'] != 1 or type(value['version']) is not int
            or value['account'] != 'fakepooh' or type(value['owner_id']) is not int
            or value['owner_id'] != 4489850 or value['copilot_free'] is not True
            or value['additional_paid_usage'] is not False
            or value['unknown_allowance_exception'] is not True
            or policy['unknown_allowance_exception'] is not True
            or policy['max_sessions'] != 10 or policy['max_sessions_per_case'] != 1
            or policy['additional_paid_usage_permitted'] is not False
            or policy['model'] != 'auto' or policy['cli_version'] != '1.0.98'
            or value['budget_exception_sha256'] != policy['budget_exception_sha256']
            or value['workflow_sha'] != env.get('GITHUB_SHA')
            or not re.fullmatch('[0-9a-f]{40}', value['workflow_sha'])
            or value['freeze_sha256'] != frozen['freeze_sha256']
            or not re.fullmatch('[0-9a-f]{64}', value['nonce'])
            or value['nonce'] != env.get('PREFLIGHT_NONCE')
            or value['case'] != env.get('REVIEW_CASE')
            or type(value['ci_run_id']) is not int or value['ci_run_id'] < 1
            or not isinstance(value['included_display'], str) or not value['included_display']):
        raise ValueError('ADMISSION_BINDING_OR_BILLING_FAILED')
    observed = dt.datetime.fromisoformat(value['observed_at'])
    if observed.tzinfo is None or not 0 <= (now - observed).total_seconds() <= 3600:
        raise ValueError('FRESH_BILLING_RECEIPT_REQUIRED')
    if sha((root / 'manifest.json').read_bytes()) != policy['historical_manifest_sha256']:
        raise ValueError('ORIGINAL_HISTORICAL_INVENTORY_REQUIRED')
    cases = json.loads((root / 'manifest.json').read_text())['cases']
    if not any(c['id'] == value['case'] for c in cases):
        raise ValueError('UNAUTHORIZED_CASE')
    binding = intent(value['case'], int(env['GITHUB_RUN_ID']), 1, value['workflow_sha'],
                     frozen['methodology_sha256'], policy['prompt_sha256'])
    return value, binding, frozen


class GitHubReadOnly:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def get(self, path):
        if not re.fullmatch(r'/(git/commits/[0-9a-f]{40}|actions/runs/[0-9]+(/jobs\?per_page=100)?)', path):
            raise ValueError('READ_ONLY_CI_ENDPOINT_REQUIRED')
        req = urllib.request.Request('https://api.github.com/repos/fakepooh/CodexBar' + path,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'User-Agent': 'repo-wide-readonly-preflight'})
        try:
            with self.opener.open(req, timeout=30) as response:
                raw = response.read(2097153)
                if response.status != 200 or len(raw) > 2097152:
                    raise ValueError('CI_READ_RESPONSE_REJECTED')
                return json.loads(raw)
        except Exception:
            raise ValueError('CI_READ_UNAVAILABLE_NO_RETRY') from None


def require_ci(api, value):
    commit = api.get('/git/commits/' + value['workflow_sha'])
    if commit.get('sha') != value['workflow_sha'] or len(commit['parents']) not in (1, 2):
        raise ValueError('RELEASE_IDENTITY_UNPROVED')
    # A merge's first parent is the OLD base; its CI cannot validate the new patch.
    permitted = {value['workflow_sha']}
    if len(commit['parents']) == 2: permitted.add(commit['parents'][1]['sha'])
    run = api.get('/actions/runs/' + str(value['ci_run_id']))
    if (run.get('name') != 'CI' or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or run.get('head_sha') not in permitted):
        raise ValueError('EXACT_RELEASE_OR_PARENT_CI_REQUIRED')
    result = api.get('/actions/runs/' + str(value['ci_run_id']) + '/jobs?per_page=100')
    rows = result['jobs']
    required = {'lint-build-test', 'swift-test-macos (0, 2)', 'swift-test-macos (1, 2)',
                'swift-build-macos-compatibility', 'lint'}
    if result['total_count'] >= 100 or result['total_count'] != len(rows) or any(
            not any(j['name'] == name and j['conclusion'] == 'success' for j in rows) for name in required):
        raise ValueError('FULL_NON_DRAFT_CI_REQUIRED')
    return {'run_id': value['ci_run_id'], 'head_sha': run['head_sha'], 'full_required_jobs': 'PASS'}


def claim(env=os.environ):
    # Validate all public bindings before reading a credential or creating a guard.
    value, binding, frozen = admission(env, env.get('COPILOT_REPO_WIDE_ADMISSION', ''))
    token = env['GITHUB_TOKEN']; ci = require_ci(GitHubReadOnly(token), value)
    result = reserve(GitHubStore(token, binding['workflow_sha']), binding)
    return {'status': 'RESERVED_ONCE', 'case': value['case'], 'ci': ci,
            'reservation_sha256': sha(canonical(result).encode()), 'real_model_requests': 0}


def read_reservation(env, value, binding, token):
    store = GitHubStore(token, binding['workflow_sha'])
    ref = 'refs/tags/' + binding['experiment'] + '-' + binding['case']
    receipt = {'created': True, 'ref': ref, 'intent': store.read(ref)}
    verify(receipt, binding, int(env['GITHUB_RUN_ATTEMPT']))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('operation', choices=['reserve', 'check-offline'])
    parser.add_argument('--proof', type=Path); args = parser.parse_args()
    try:
        if args.operation == 'check-offline':
            require_transport(json.loads(args.proof.read_text()))
            print(canonical({'status': 'OFFLINE_SHARED_PRODUCTION_PATH_PASS', 'real_model_requests': 0}))
        else: print(canonical(claim()))
    except Exception:
        print(canonical({'status': 'BLOCKED', 'reason': 'LIVE_ADMISSION_OR_ATOMIC_RESERVATION_FAILED',
                         'model_requests': 0})); raise SystemExit(2)
