import copy
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import keychain_helper
import pilot as p
import public_report as report
import public_series as series
import public_actions_repos as objects
import prompt_review_v2_adapter as original
import prompt_review_v21_adapter as expanded


class OfflinePublicationTests(unittest.TestCase):
    def test_fetch_is_exact_bounded_and_credential_free(self):
        process = Mock()
        process.wait.return_value = 0
        shas = ['a'*40, 'b'*40]
        with patch.object(objects.subprocess, 'Popen', return_value=process) as launch, \
                patch.dict(objects.os.environ, {'COPILOT_GITHUB_TOKEN': 'PRIVATE_TEST_SENTINEL'}):
            objects.fetch('/synthetic', 'fakepooh/CodexBar', shas)
        args, kwargs = launch.call_args
        self.assertIn('--depth=32', args[0])
        self.assertEqual(args[0][-2:], shas)
        self.assertTrue(kwargs['start_new_session'])
        self.assertNotIn('COPILOT_GITHUB_TOKEN', kwargs['env'])
        self.assertNotIn('shell', kwargs)

    def test_fetch_timeout_cleans_owned_process_group_and_does_not_retry(self):
        process = Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired('synthetic', 120), 0]
        with patch.object(objects.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(objects.os, 'killpg') as cleanup:
            with self.assertRaises(ValueError):
                objects.fetch('/synthetic', 'fakepooh/CodexBar', ['a'*40])
        launch.assert_called_once()
        cleanup.assert_called_once_with(12345, objects.signal.SIGTERM)

    def fixture(self):
        manifest = series.SERIES/'manifest.json'
        contract = p.load(series.SERIES/'expanded-v2.1.0/contract.json')
        rows = [dict(case=c, methodology=expanded.VERSION, status='PASS',
                     diff_bytes=100, diff_sha256='a'*64, context_sha256='b'*64,
                     prompt_sha256='c'*64, prompt_bytes=1000, pages=1, omitted_pages=0,
                     schema_fixture_valid=True, evaluator_rejected_missing_ai_evidence=True,
                     ai_requests=0, model_consumption_proven=False)
                for c in series.cases(manifest)]
        value = dict(cases=rows, methodology=expanded.VERSION,
                     freeze_sha256=expanded.check_freeze(),
                     contract_sha256=p.digest(expanded.canonical(contract).encode()),
                     manifest_sha256=p.digest(manifest.read_bytes()),
                     ai_reviews=0, ground_truth_loaded=False)
        return value, manifest, contract

    def validate(self, value):
        _, manifest, contract = self.fixture()
        return report.receipt(value, manifest, contract, 'd'*40, 'synthetic-run')

    def test_both_frozen_versions_match(self):
        original.check_freeze()
        expanded.check_freeze()
        self.assertEqual(original.LIMITS['max_diff_bytes'], 65536)
        self.assertEqual(expanded.LIMITS['max_diff_bytes'], 196608)

    def test_credentials_are_unavailable(self):
        with self.assertRaises(keychain_helper.KeychainBlocked):
            with keychain_helper.pat():
                self.fail('Credential access enabled')

    def test_exact_ten_case_receipt_without_network(self):
        value, _, _ = self.fixture()
        with patch.object(socket, 'socket', side_effect=AssertionError('No API access')):
            result = self.validate(value)
        self.assertEqual(len(result['cases']), 10)
        self.assertEqual(result['ai_reviews'], 0)

    def test_missing_duplicate_or_changed_identity_rejected(self):
        value, _, _ = self.fixture()
        missing = copy.deepcopy(value)
        missing['cases'].pop()
        duplicate = copy.deepcopy(value)
        duplicate['cases'][-1] = duplicate['cases'][0]
        changed = copy.deepcopy(value)
        changed['cases'][0]['case']['head'] = 'e'*40
        for invalid in (missing, duplicate, changed):
            with self.assertRaises(ValueError):
                self.validate(invalid)

    def test_failed_case_or_inference_cannot_be_reported_pass(self):
        value, _, _ = self.fixture()
        for key, bad in [('status', 'BLOCKED'), ('ai_requests', 1),
                         ('schema_fixture_valid', False), ('model_consumption_proven', True),
                         ('prompt_bytes', 262145), ('prompt_sha256', '')]:
            invalid = copy.deepcopy(value)
            invalid['cases'][0][key] = bad
            with self.assertRaises(ValueError):
                self.validate(invalid)

    def test_public_receipt_excludes_private_content(self):
        value, _, _ = self.fixture()
        value['cases'][0]['unexpected_private_field'] = 'PRIVATE_TEST_SENTINEL'
        self.assertNotIn('PRIVATE_TEST_SENTINEL', json.dumps(self.validate(value)))

    def test_contract_drift_or_live_authorization_rejected(self):
        value, manifest, contract = self.fixture()
        for key, bad in [('ai_authorized', True), ('freeze_sha256', 'f'*64),
                         ('manifest_sha256', 'f'*64), ('methodology', original.VERSION)]:
            invalid = dict(contract, **{key: bad})
            with self.assertRaises(ValueError):
                report.receipt(value, manifest, invalid, 'd'*40, 'synthetic-run')

    def test_workflow_is_manual_offline_only(self):
        text = (p.ROOT.parent.parent/'.github/workflows/copilot-public-offline.yml').read_text()
        self.assertIn('workflow_dispatch:', text)
        self.assertIn('if: ${{ false }}', text)
        for forbidden in ('pull_request:', 'push:', 'schedule:', 'secrets.',
                          'COPILOT_GITHUB_TOKEN', 'upload-artifact', 'actions/cache'):
            self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
