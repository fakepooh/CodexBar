import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from repo_wide_readonly.hosted_offline import run, failure_diagnostic


class HostedOrchestration(unittest.TestCase):
    def execute(self, *, timeout=False, proof=None, cleanup_fails=False, exit_code=0, stderr=b''):
        calls = []
        if proof is None:
            proof = {'status': 'PASS', 'native_cli_version': '1.0.98', 'real_model_requests': 0,
                     'mock_requests': 6, 'exact_tool_results_received': True,
                     'host_escape_denied': True, 'os_isolation': {'nonroot': True}}
            proof.update(local_receiver_authenticated=True, exact_tool_result_order_verified=True)
        def command(argv, **options):
            calls.append((argv, options))
            if argv[:2] == ['docker', 'run']:
                if timeout: raise subprocess.TimeoutExpired(argv, 150)
                return subprocess.CompletedProcess(argv, exit_code, json.dumps(proof).encode(), stderr)
            if argv[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(argv, 1 if cleanup_fails else 0, b'', b'')
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        with tempfile.TemporaryDirectory() as tmp, patch('repo_wide_readonly.hosted_offline.hosted'), \
             patch('repo_wide_readonly.hosted_offline.prepare'), \
             patch('repo_wide_readonly.hosted_offline.subprocess.run', side_effect=command), \
             contextlib.redirect_stdout(io.StringIO()):
            report = run(Path(tmp) / 'owned')
            private = Path(tmp) / 'owned/private-startup.json'
            if private.exists():
                self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        return report, calls

    def test_success_requires_exact_native_proof_and_cleanup(self):
        r, calls = self.execute()
        self.assertEqual(r['status'], 'PASS')
        self.assertTrue(r['owned_container_absent_after_cleanup'])
        argv = next(a for a, _ in calls if a[:2] == ['docker', 'run'])
        for flag in ['--network=none', '--read-only', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges', '--user=65534:65534']:
            self.assertIn(flag, argv)
        self.assertNotIn('-e', argv)
        self.assertEqual(sum(a[:2] == ['docker', 'run'] for a, _ in calls), 1)

    def test_timeout_cleans_up_owned_container_without_retry(self):
        r, calls = self.execute(timeout=True)
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertIn('TIMEOUT', [s['status'] for s in r['stages']])
        self.assertTrue(r['owned_container_absent_after_cleanup'])
        run_args = next(a for a, _ in calls if a[:2] == ['docker', 'run'])
        name = run_args[run_args.index('--name') + 1]
        self.assertIn(['docker', 'rm', '-f', name], [a for a, _ in calls])
        self.assertEqual(sum(a[:2] == ['docker', 'run'] for a, _ in calls), 1)

    def test_failed_inventory_cannot_prove_container_cleanup(self):
        r, _ = self.execute(cleanup_fails=True)
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertFalse(r['owned_container_absent_after_cleanup'])

    def test_failed_child_keeps_only_bounded_safe_diagnostic_and_never_passes(self):
        proof = {'status': 'BLOCKED', 'failed_stage': 'cli_initialization',
                 'failure_code': 'RUNTIME_EXECUTION_DENIED', 'mock_requests': 0,
                 'private_startup_diagnostic': 'PRIVATE_FIXTURE_SENTINEL',
                 'private_error': 'PRIVATE_FIXTURE_SENTINEL'}
        r, calls = self.execute(proof=proof, exit_code=2, stderr=b'EACCES PRIVATE_FIXTURE_SENTINEL')
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertEqual(r['native_process_exit_code'], 2)
        self.assertEqual(r['native_failure']['failure_code'], 'RUNTIME_EXECUTION_DENIED')
        self.assertNotIn('PRIVATE_FIXTURE_SENTINEL', json.dumps(r))
        self.assertRegex(r['private_startup_sha256'], r'^[0-9a-f]{64}$')
        self.assertTrue(r['owned_container_absent_after_cleanup'])
        self.assertEqual(sum(a[:2] == ['docker', 'run'] for a, _ in calls), 1)

    def test_arbitrary_failure_fields_or_non_json_are_not_published(self):
        for raw in [b'PRIVATE_FIXTURE_SENTINEL', json.dumps({'failed_stage': 'PRIVATE_FIXTURE_SENTINEL',
                    'failure_code': 'PRIVATE_FIXTURE_SENTINEL', 'mock_requests': True}).encode()]:
            proof = failure_diagnostic(raw)
            self.assertNotIn('PRIVATE_FIXTURE_SENTINEL', json.dumps(proof))
            self.assertNotIn('mock_requests', proof)

    def test_bad_or_untyped_receipts_rejected(self):
        for proof in [{'status': 'PASS'}, {'status': 'PASS', 'real_model_requests': False},
                      {'status': 'PASS', 'native_cli_version': '1.0.98', 'real_model_requests': 0,
                       'mock_requests': 6, 'exact_tool_results_received': True,
                       'host_escape_denied': True, 'os_isolation': {'nonroot': 'true'}}]:
            with self.subTest(proof=proof):
                r, _ = self.execute(proof=proof)
                self.assertEqual(r['status'], 'BLOCKED')


if __name__ == '__main__': unittest.main()
