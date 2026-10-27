import io
import json
import threading
import unittest
from unittest.mock import Mock, patch
import urllib.error

from repo_wide_readonly.ledger import GitHubStore, RefAlreadyExists
from repo_wide_readonly.ledger_fixture import probe


class ConflictClassification(unittest.TestCase):
    def error(self, detail, path='/git/refs'):
        store = GitHubStore('synthetic-not-a-token', 'a' * 40)
        store.opener = Mock()
        store.opener.open.side_effect = urllib.error.HTTPError('https://api.github.com/fixture',
            422, 'fixture', {}, io.BytesIO(json.dumps(detail).encode()))
        return store, path

    def test_only_explicit_reference_conflict_is_classified(self):
        store, path = self.error({'message': 'Reference already exists', 'private_fixture': 'DO_NOT_LOG'})
        with self.assertRaisesRegex(RefAlreadyExists, '^Remote ledger reference already exists$'):
            store.request('POST', path, {})

    def test_spam_validation_or_tag_object_conflict_is_not_reference_proof(self):
        for detail, path in [({'message': 'rate limit fixture'}, '/git/refs'),
                             ({'message': 'Validation Failed'}, '/git/refs'),
                             ({'message': 'Reference already exists'}, '/git/tags')]:
            with self.subTest(path=path):
                store, _ = self.error(detail, path)
                with self.assertRaises(ValueError) as result: store.request('POST', path, {})
                self.assertNotIsInstance(result.exception, RefAlreadyExists)


class FixtureOrchestration(unittest.TestCase):
    def store(self, uncertain=False):
        lock = threading.Lock(); refs = {}
        class Store:
            def __init__(self, token, workflow): pass
            def create_ref(self, ref, value):
                if 'PUB-' in ref or 'offline-cas' not in ref:
                    raise AssertionError('Fixture must never use a live case guard')
                with lock:
                    if ref in refs:
                        if uncertain: raise ValueError('Remote ledger HTTP 422')
                        raise RefAlreadyExists('Remote ledger reference already exists')
                    refs[ref] = value
                return {'created': True, 'ref': ref, 'intent': value}
            def read(self, ref): return refs[ref]
        return Store

    def test_exactly_one_racing_writer_and_duplicate_exclusion(self):
        with patch('repo_wide_readonly.ledger_fixture.hosted'), \
             patch('repo_wide_readonly.ledger_fixture.GitHubStore', self.store()):
            result = probe('synthetic', 'a' * 40, 42, 1)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['new_live_reservations'], 0)
        self.assertEqual(result['real_model_requests'], 0)

    def test_uncertain_or_generic_422_never_proves_exclusion(self):
        with patch('repo_wide_readonly.ledger_fixture.hosted'), \
             patch('repo_wide_readonly.ledger_fixture.GitHubStore', self.store(True)):
            with self.assertRaises(ValueError): probe('synthetic', 'a' * 40, 42, 1)

    def test_workflow_rerun_fails_before_remote_mutation(self):
        with patch('repo_wide_readonly.ledger_fixture.hosted'), \
             patch('repo_wide_readonly.ledger_fixture.GitHubStore') as store:
            with self.assertRaises(ValueError): probe('synthetic', 'a' * 40, 42, 2)
            store.assert_not_called()


if __name__ == '__main__': unittest.main()
