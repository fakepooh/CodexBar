import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from repo_wide_readonly.hosted_offline import run


class HostedOrchestration(unittest.TestCase):
    def execute(self, *, timeout=False, proof=None, cleanup_fails=False):
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
                return subprocess.CompletedProcess(argv, 0, json.dumps(proof).encode(), b'')
            if argv[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(argv, 1 if cleanup_fails else 0, b'', b'')
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        with tempfile.TemporaryDirectory() as tmp, patch('repo_wide_readonly.hosted_offline.hosted'), \
             patch('repo_wide_readonly.hosted_offline.prepare'), \
             patch('repo_wide_readonly.hosted_offline.subprocess.run', side_effect=command), \
             contextlib.redirect_stdout(io.StringIO()):
            report = run(Path(tmp) / 'owned')
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

    def test_bad_or_untyped_receipts_rejected(self):
        for proof in [{'status': 'PASS'}, {'status': 'PASS', 'real_model_requests': False},
                      {'status': 'PASS', 'native_cli_version': '1.0.98', 'real_model_requests': 0,
                       'mock_requests': 6, 'exact_tool_results_received': True,
                       'host_escape_denied': True, 'os_isolation': {'nonroot': 'true'}}]:
            with self.subTest(proof=proof):
                r, _ = self.execute(proof=proof)
                self.assertEqual(r['status'], 'BLOCKED')


if __name__ == '__main__': unittest.main()
