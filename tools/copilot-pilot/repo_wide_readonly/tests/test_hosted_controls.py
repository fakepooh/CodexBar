import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from repo_wide_readonly.reservations import intent, reserve, verify
from repo_wide_readonly.prepare import prepare, hosted


class StrictReservations(unittest.TestCase):
    def setUp(self):
        self.value = intent('PUB-01', 1, 1, 'a' * 40, 'b' * 64, 'c' * 64)

    def test_mutated_identity_never_reaches_writer(self):
        class NoCalls:
            def create_ref(self, *_):
                raise AssertionError('Writer must not run')
        for key, value in [('run_id', True), ('run_attempt', True), ('automatic_retry', 0),
                           ('experiment', 'old-consumed-grant'), ('case', 'PUB-11')]:
            mutated = dict(self.value, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError): reserve(NoCalls(), mutated)

    def test_extra_fields_cannot_change_authorization(self):
        with self.assertRaises(ValueError): reserve(None, dict(self.value, bypass=True))

    def test_remote_numeric_created_is_not_boolean_success(self):
        class Store:
            def create_ref(self, ref, value): return {'created': 1, 'ref': ref, 'intent': value}
        with self.assertRaises(ValueError): reserve(Store(), self.value)

    def test_remote_boolean_identity_is_not_integer_identity(self):
        receipt = {'created': True, 'ref': 'refs/tags/repo-wide-readonly-v1-20261026-PUB-01',
                   'intent': dict(self.value, run_id=True)}
        with self.assertRaises(ValueError): verify(receipt, self.value, 1)


class HostedPreparation(unittest.TestCase):
    def test_local_environment_is_blocked_before_any_files(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            target = Path(tmp) / 'not-created'
            with self.assertRaises(ValueError): prepare(target, fixture=True)
            self.assertFalse(target.exists())

    def test_fixture_readable_by_nonroot_even_under_private_umask(self):
        # No container, runtime or historical code is run by this deterministic test.
        with tempfile.TemporaryDirectory() as tmp, patch('repo_wide_readonly.prepare.hosted'):
            target = Path(tmp) / 'fixture'
            before = os.umask(0o077)
            try: prepare(target, fixture=True)
            finally: os.umask(before)
            self.assertEqual(stat.S_IMODE((target / 'snapshot.json').stat().st_mode), 0o444)
            for path in (target / 'snapshot').rglob('*'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555 if path.is_dir() else 0o444)
            # Restore only this test's own temporary inert files for cleanup.
            for path in (target / 'snapshot').rglob('*'):
                path.chmod(0o755 if path.is_dir() else 0o644)
            (target / 'snapshot').chmod(0o755)


if __name__ == '__main__': unittest.main()
