import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import subprocess
import contextlib
import io
import unittest
from unittest.mock import patch, Mock

from repo_wide_readonly import live_control as control
from repo_wide_readonly import live_host as host
from repo_wide_readonly.snapshot import sha


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.now = dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc)
        policy = json.loads((control.ROOT / 'live-policy.json').read_text())
        manifest = (control.ROOT / 'manifest.json').read_bytes()
        (self.root / 'manifest.json').write_bytes(manifest)
        (self.root / 'live-policy.json').write_text(json.dumps(policy))
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                    'GITHUB_REPOSITORY': 'fakepooh/CodexBar', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_ACTOR': 'fakepooh',
                    'GITHUB_ACTOR_ID': '4489850', 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123',
                    'PREFLIGHT_NONCE': 'd' * 64, 'REVIEW_CASE': 'PUB-01'}
        self.value = {'version': 1, 'case': 'PUB-01', 'nonce': 'd' * 64,
                      'workflow_sha': 'a' * 40, 'freeze_sha256': 'f' * 64,
                      'observed_at': self.now.isoformat(), 'account': 'fakepooh', 'owner_id': 4489850,
                      'copilot_free': True, 'additional_paid_usage': False, 'included_display': '7% used',
                      'unknown_allowance_exception': True, 'budget_exception_sha256': policy['budget_exception_sha256'],
                      'ci_run_id': 456}
        self.frozen = {'freeze_sha256': 'f' * 64, 'methodology_sha256': 'e' * 64}
        self.patch = patch.object(control, 'verify_freeze', return_value=self.frozen); self.patch.start()

    def tearDown(self): self.patch.stop(); self.temp.cleanup()

    def call(self, value=None, env=None, now=None):
        return control.admission(env or self.env, json.dumps(value or self.value), now or self.now, self.root)

    def test_exact_identity_exception_and_case(self):
        value, binding, frozen = self.call()
        self.assertEqual(binding['case'], 'PUB-01'); self.assertEqual(binding['run_attempt'], 1)
        self.assertEqual(binding['methodology_sha256'], 'e' * 64)

    def test_billing_actor_retries_branch_case_and_hash_fail_closed(self):
        for key, value in [('additional_paid_usage', True), ('copilot_free', False), ('owner_id', True),
                           ('nonce', 'bad'), ('freeze_sha256', '0' * 64), ('workflow_sha', 'b' * 40),
                           ('case', 'PUB-11'), ('unknown_allowance_exception', False),
                           ('ci_run_id', True), ('budget_exception_sha256', '0' * 64)]:
            d = dict(self.value); d[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.call(d)
        for key, value in [('GITHUB_ACTOR', 'other'), ('GITHUB_REF', 'refs/heads/branch'),
                           ('GITHUB_RUN_ATTEMPT', '2'), ('RUNNER_ENVIRONMENT', 'self-hosted')]:
            env = dict(self.env); env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.call(env=env)

    def test_expiry_future_and_duplicate_json_are_not_accepted(self):
        for seconds in [3601, -1]:
            with self.assertRaises(ValueError): self.call(now=self.now + dt.timedelta(seconds=seconds))
        raw = json.dumps(self.value)[:-1] + ',"additional_paid_usage":false}'
        with self.assertRaises(ValueError): control.admission(self.env, raw, self.now, self.root)

    def test_rounded_display_does_not_admit_exhaustion_or_invent_allowance(self):
        for display in ['0% used', '7% used', '99% used', '99.999% used']:
            value = dict(self.value, included_display=display)
            admitted, _, _ = self.call(value)
            self.assertEqual(admitted['included_display'], display)
            self.assertNotIn('included_ai_credits', admitted)
        for display in ['100% used', '100.0% used', '101% used', '-1% used',
                        'unknown', 'rounded only', '', 'NaN% used', True, 7, '7% used\n']:
            with self.subTest(display=display), self.assertRaises(ValueError):
                self.call(dict(self.value, included_display=display))

    def test_rejected_admission_never_reads_credential_or_reserves(self):
        class Guarded(dict):
            def __getitem__(self, key):
                if key == 'GITHUB_TOKEN': raise AssertionError('credential touched')
                return super().__getitem__(key)
        with patch.object(control, 'admission', side_effect=ValueError('blocked')), patch.object(control, 'reserve') as reserve:
            with self.assertRaises(ValueError): control.claim(Guarded())
            reserve.assert_not_called()


class CIAndContextTests(unittest.TestCase):
    def test_production_transport_gate_rejects_incomplete_or_mock_selection_only(self):
        proof = {'status': 'PASS', 'native_cli_version': '1.0.98', 'real_model_requests': 0,
                 'mock_requests': 6, 'callback_count': 5, 'selected_tools': ['repo_glob', 'repo_grep', 'repo_view'],
                 'os_isolation': {k: True for k in control.OS_FIELDS}}
        for key in ['exact_tool_results_received', 'host_escape_denied', 'local_receiver_authenticated',
                    'exact_tool_result_order_verified', 'pre_dispatch_tool_catalog_verified', 'production_entry_mock_verified']: proof[key] = True
        self.assertTrue(control.require_transport(proof))
        for key in ['pre_dispatch_tool_catalog_verified', 'production_entry_mock_verified', 'os_isolation', 'callback_count']:
            d = dict(proof); d.pop(key)
            with self.assertRaises(ValueError): control.require_transport(d)
        d = dict(proof, real_model_requests=True)
        with self.assertRaises(ValueError): control.require_transport(d)
    def test_old_base_draft_incomplete_failed_or_other_head_cannot_authorize(self):
        required = ['lint-build-test', 'swift-test-macos (0, 2)', 'swift-test-macos (1, 2)',
                    'swift-build-macos-compatibility', 'lint']
        def api(head='b' * 40, skip=False, conclusion='success'):
            rows = [{'name': n, 'conclusion': 'skipped' if skip and n.startswith('swift-test') else 'success'} for n in required]
            objects = [{'sha': 'a' * 40, 'parents': [{'sha': 'c' * 40}, {'sha': 'b' * 40}]},
                       {'name': 'CI', 'status': 'completed', 'conclusion': conclusion, 'head_sha': head},
                       {'total_count': len(rows), 'jobs': rows}]
            return Mock(get=Mock(side_effect=objects))
        value = {'workflow_sha': 'a' * 40, 'ci_run_id': 1}
        self.assertEqual(control.require_ci(api(), value)['full_required_jobs'], 'PASS')
        for instance in [api(head='c' * 40), api(head='d' * 40), api(skip=True), api(conclusion='failure')]:
            with self.assertRaises(ValueError): control.require_ci(instance, value)

    def test_container_controls_and_no_credential_in_arguments(self):
        argv = host.container_args('owned-fixture', 'image-pin', Path('/tmp/case'))
        for flag in ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534']:
            self.assertIn(flag, argv)
        self.assertIn('--network=bridge', argv)
        self.assertFalse(any('TOKEN' in x or 'SECRET' in x for x in argv))
        self.assertEqual(sum(x.startswith('type=bind,src=') and x.endswith(',readonly') for x in argv), 2)

    def test_context_exact_diff_no_truncation_no_evaluator_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); body = 'GENERIC REVIEW TASK'; diff = b'fixed complete historical diff\n'
            (root / 'live-policy.json').write_text(json.dumps({'prompt_sha256': sha(body.encode())}))
            receipt = {'complete': True, 'case': {'id': 'PUB-01', 'repository': 'public/fixture', 'pr': 1,
                       'base': 'a' * 40, 'head': 'b' * 40}, 'snapshot_sha256': 'c' * 64,
                       'diff_sha256': sha(diff), 'diff_bytes': len(diff)}
            with patch.object(host, 'ROOT', root):
                prompt = host.initial_prompt(body, receipt, diff, {})
                self.assertTrue(prompt.endswith(diff.decode()))
                self.assertNotIn('PRIVATE_EVALUATOR_SENTINEL', prompt)
                with self.assertRaises(ValueError): host.initial_prompt(body, receipt, diff[:-1], {})
                d = copy.deepcopy(receipt); d['case']['ground_truth'] = 'PRIVATE_EVALUATOR_SENTINEL'
                with self.assertRaises(ValueError): host.initial_prompt(body, d, diff, {})


class ParentOrchestrationTests(unittest.TestCase):
    def exercise(self, *, malformed=False, invalid_output=False, timeout=False, paid=False):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'owned'; calls = []; captures = []
            env = {'PATH': '/usr/bin', 'HOME': '/fixture-host', 'GITHUB_ACTIONS': 'true',
                   'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_REPOSITORY': 'fakepooh/CodexBar',
                   'GITHUB_RUN_ID': '123', 'GITHUB_SHA': 'a' * 40, 'REVIEW_CASE': 'PUB-01',
                   'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_TOKEN': 'SYNTHETIC_TOKEN_NEVER_REAL',
                   'COPILOT_REPO_WIDE_PROMPT': 'GENERIC_FIXED_FIXTURE',
                   'COPILOT_REPO_WIDE_PUBLIC_RECIPIENT': 'PUBLIC_FIXTURE',
                   'COPILOT_REPO_WIDE_ADMISSION': '{}'}
            binding = {'case': 'PUB-01'}
            case = {'id': 'PUB-01', 'repository': 'public/fixture', 'pr': 1, 'base': 'b' * 40, 'head': 'c' * 40}
            snapshot = {'case': case, 'complete': True, 'snapshot_sha256': 'd' * 64,
                        'diff_sha256': sha(b'diff'), 'diff_bytes': 4}
            child = {'binding': binding, 'prompt_sha256': sha(b'FIXED_PAYLOAD'),
                     'status': 'COMPLETED', 'inference_dispatched': True, 'raw_output': 'FULL_FINDING_SENTINEL',
                     'session_id': '12345678-1234-1234-1234-123456789abc', 'duration_seconds': 1.5,
                     'events': [{'type': 'fixture', 'text': 'SYNTHETIC_TOKEN_NEVER_REAL'}], 'tool_audit': []}
            def run(argv, **options):
                calls.append((argv, options)); self.assertNotIn('GITHUB_TOKEN', options.get('env', {}))
                self.assertFalse(any('SYNTHETIC_TOKEN_NEVER_REAL' in str(x) for x in argv))
                if '-m' in argv and 'repo_wide_readonly.prepare' in argv:
                    p = output / 'historical/PUB-01'; p.mkdir(parents=True); (p / 'snapshot').mkdir()
                    (p / 'snapshot.json').write_text(json.dumps(snapshot)); (p / 'complete.diff').write_bytes(b'diff')
                elif argv[:2] == ['docker', 'run']:
                    if 'python3' in argv:
                        return subprocess.CompletedProcess(argv, 0, json.dumps({'ok': True,
                            'result': {k: True for k in control.OS_FIELDS}}).encode(), b'')
                    control_frame = json.loads(options['input']); self.assertEqual(control_frame['token'], env['GITHUB_TOKEN'])
                    if timeout: raise subprocess.TimeoutExpired(argv, 1290)
                    payload = b'BROKEN FULL RESPONSE SENTINEL' if malformed else json.dumps(child).encode()
                    return subprocess.CompletedProcess(argv, 0, payload, b'never persisted raw stderr')
                elif argv[:2] == ['docker', 'cp']:
                    Path(argv[-1]).write_text(json.dumps(child))
                elif len(argv) > 1 and str(argv[1]).endswith('seal-file.mjs'):
                    source = Path(argv[2]); captures.append(source.read_text())
                    Path(argv[3]).write_text('{"encrypted-fixture":true}')
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            admission = Mock(return_value=({'case': 'PUB-01'}, binding,
                {'freeze_sha256': 'e' * 64, 'methodology_sha256': 'f' * 64}))
            if paid: admission.side_effect = ValueError('paid usage is forbidden')
            validation = Mock(return_value=({'findings': []}, {'finding_count': 0}))
            if invalid_output: validation.side_effect = ValueError('invalid output')
            with patch.object(host, 'admission', admission), patch.object(host, 'require_ci', return_value={'status': 'PASS'}), \
                 patch.object(host, 'read_reservation', return_value={'fixture': True}), \
                 patch.object(host, 'initial_prompt', return_value='FIXED_PAYLOAD'), \
                 patch.object(host, 'base_index', return_value={}), patch.object(host, 'validate', validation), \
                 patch.object(host.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()) as public:
                result = host.review(output, env)
            private = json.loads((output / 'private-review.json').read_text())
            self.assertNotIn(env['GITHUB_TOKEN'], (output / 'private-review.json').read_text())
            self.assertNotIn('FULL_FINDING_SENTINEL', public.getvalue())
            self.assertNotIn('BROKEN FULL RESPONSE SENTINEL', public.getvalue())
            handoffs = [a for a, _ in calls if a[:2] == ['docker', 'run'] and 'python3' not in a]
            return result, private, handoffs, calls

    def test_one_handoff_and_private_output_encrypted_no_secret_in_children(self):
        result, private, handoffs, _ = self.exercise()
        self.assertEqual(result['status'], 'COMPLETED_SCHEMA_VALID'); self.assertEqual(len(handoffs), 1)
        self.assertEqual(private['raw_output'], 'FULL_FINDING_SENTINEL')
        self.assertTrue(result['encrypted_evidence_created']); self.assertTrue(result['owned_containers_absent'])

    def test_invalid_output_or_protocol_preserves_evidence_without_retry(self):
        for options in [{'invalid_output': True}, {'malformed': True}]:
            result, private, handoffs, _ = self.exercise(**options)
            self.assertEqual(result['status'], 'BLOCKED'); self.assertEqual(len(handoffs), 1)
            self.assertTrue(result['encrypted_evidence_created'])
            self.assertTrue('raw_output' in private or 'raw_stdout_base64' in private)

    def test_timeout_recovers_only_owned_redacted_checkpoint_and_cleans_without_retry(self):
        result, private, handoffs, calls = self.exercise(timeout=True)
        self.assertEqual(len(handoffs), 1); self.assertTrue(result['owned_containers_absent'])
        self.assertTrue(private['host_timeout_checkpoint_only'])
        self.assertEqual(private['raw_output'], 'FULL_FINDING_SENTINEL')
        copies = [a for a, _ in calls if a[:2] == ['docker', 'cp']]
        self.assertEqual(len(copies), 1); self.assertTrue(copies[0][2].endswith(':/tmp/review-checkpoint.json'))

    def test_failed_admission_never_starts_docker_or_reads_model_prompt(self):
        result, private, handoffs, calls = self.exercise(paid=True)
        self.assertEqual(result['status'], 'BLOCKED'); self.assertFalse(handoffs)
        self.assertFalse(any(a[0] == 'docker' for a, _ in calls))


if __name__ == '__main__': unittest.main()
