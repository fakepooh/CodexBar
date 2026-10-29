import json
import unittest
from unittest.mock import Mock, patch
import urllib.error
from repo_wide_readonly.ledger import GitHubStore, NoRedirect


class RemoteLedgerContract(unittest.TestCase):
    def setUp(self):
        self.store = GitHubStore('synthetic-fixture-not-a-credential', 'a' * 40)
        self.ref = 'refs/tags/repo-wide-readonly-offline-fixture'

    def test_only_exact_authenticated_repository_git_endpoints(self):
        self.store.opener = Mock()
        for method, path in [('PUT', '/git/refs'), ('DELETE', '/git/refs'),
                             ('POST', '/git/refs?other=1'), ('GET', '/user'),
                             ('GET', '/git/tags/../../user'), ('GET', '/git/ref/tags/foreign')]:
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                self.store.request(method, path)
        self.store.opener.open.assert_not_called()

    def test_redirect_refused_without_forwarding_credential(self):
        with self.assertRaises(ValueError): NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_http_error_is_sanitized(self):
        self.store.opener = Mock()
        self.store.opener.open.side_effect = urllib.error.HTTPError(
            'https://api.github.com/fixture', 403, 'SENSITIVE_FIXTURE', {'Authorization': 'SENSITIVE_FIXTURE'}, None)
        with self.assertRaisesRegex(ValueError, '^Remote ledger HTTP 403$'):
            self.store.request('POST', '/git/refs', {})

    def test_create_only_then_readback(self):
        tag = 'b' * 40; value = {'fixture': True}
        self.store.request = Mock(side_effect=[{'sha': tag}, {'ref': self.ref, 'object': {'sha': tag}},
            {'object': {'sha': tag, 'type': 'tag'}},
            {'object': {'sha': 'a' * 40, 'type': 'commit'}, 'message': json.dumps(value)}])
        result = self.store.create_ref(self.ref, value)
        self.assertTrue(result['created'])
        self.assertEqual([c.args[0] for c in self.store.request.call_args_list], ['POST', 'POST', 'GET', 'GET'])

    def test_conflict_or_uncertain_mutation_is_not_retried(self):
        self.store.request = Mock(side_effect=ValueError('uncertain'))
        with self.assertRaises(ValueError): self.store.create_ref(self.ref, {})
        self.assertEqual(self.store.request.call_count, 1)

    def test_foreign_workflow_readback_rejected(self):
        self.store.request = Mock(side_effect=[{'object': {'sha': 'b' * 40, 'type': 'tag'}},
            {'object': {'sha': 'c' * 40, 'type': 'commit'}, 'message': '{}'}])
        with self.assertRaises(ValueError): self.store.read(self.ref)

    def test_malicious_or_foreign_refs_never_reach_network(self):
        self.store.request = Mock()
        for ref in ['refs/tags/v1', self.ref + '/nested', self.ref + '#fragment', self.ref + '?query']:
            with self.subTest(ref=ref), self.assertRaises(ValueError): self.store.create_ref(ref, {})
        self.store.request.assert_not_called()


if __name__ == '__main__': unittest.main()
