import concurrent.futures
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from repo_wide_readonly.broker import Broker
from repo_wide_readonly.snapshot import build, relative, sha
from repo_wide_readonly.reservations import intent, reserve, verify


class SnapshotTools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'snapshot'; self.root.mkdir()
        contents = {'src/large.swift': ('unchanged\n' * 8000 + 'caller configuration\n').encode(),
                    'config/defaults.json': b'{"enabled":true}', 'link': b'/proc/self/environ',
                    'long.txt': ('x' * 20000).encode(), 'binary.bin': b'\xff\x00'}
        rows = []
        for name, content in contents.items():
            p = self.root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(content)
            rows.append({'path': name, 'sha256': sha(content), 'bytes': len(content),
                         'blob_oid': hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()})
        self.receipt = {'complete': True, 'files': rows, 'file_count': len(rows)}
        self.b = Broker(self.root, self.receipt)

    def test_exact_unchanged_large_file_range(self):
        v = self.b.view('src/large.swift', 8001, 8001)
        self.assertEqual(v['lines'][0]['text'], 'caller configuration')
        self.assertEqual(v['lines'][0]['line'], 8001)
        self.assertIsNone(v['next_cursor'])

    def test_full_inventory_pagination(self):
        first = self.b.glob('*', limit=2)
        self.assertEqual(first['next_cursor'], 2)
        self.assertEqual(len(self.b.glob('*', cursor=2, limit=200)['paths']), 3)

    def test_literal_search_and_line(self):
        self.assertEqual(self.b.grep('caller')['matches'][0]['line'], 8001)
        self.assertEqual(self.b.grep('.*')['matches'], [])

    def test_search_pages_are_explicit(self):
        v = self.b.grep('unchanged', limit=2)
        self.assertFalse(v['search_complete']); self.assertIsNone(v['total_matches'])
        self.assertEqual(v['next_cursor'], 2)

    def test_long_line_is_reconstructible_without_hidden_truncation(self):
        cursor = {'start_line': 1, 'column': 0}; fragments = []
        while cursor:
            v = self.b.view('long.txt', end_line=1, **cursor)
            fragments.extend(x['text'] for x in v['lines']); cursor = v['next_cursor']
        self.assertEqual(''.join(fragments), 'x' * 20000)

    def test_binary_disclosed_without_execution(self):
        self.assertTrue(self.b.view('binary.bin')['source_not_text'])

    def test_binary_bytes_are_available_exactly_with_explicit_pagination(self):
        import base64
        a = self.b.view('binary.bin', encoding='base64', byte_limit=1)
        b = self.b.view('binary.bin', byte_limit=1, **a['next_cursor'])
        self.assertEqual(base64.b64decode(a['content']) + base64.b64decode(b['content']), b'\xff\x00')
        self.assertIsNone(b['next_cursor'])

    def test_contradictory_byte_and_line_modes_fail_closed(self):
        with self.assertRaises(ValueError):
            self.b.view('long.txt', start_line=2, encoding='base64')

    def test_search_large_cursor_does_not_return_prior_matches(self):
        v = self.b.grep('unchanged', cursor=7999, limit=2)
        self.assertEqual([r['line'] for r in v['matches']], [8000])
        self.assertEqual(v['total_matches'], 8000)

    def test_symlink_blob_is_inert_text(self):
        self.assertEqual(self.b.view('link')['lines'][0]['text'], '/proc/self/environ')

    def test_outside_and_git_and_untracked_forbidden(self):
        for path in ['/proc/self/environ', '../private', '.git/config', 'src/../../secret', 'missing']:
            with self.subTest(path=path), self.assertRaises(ValueError): self.b.view(path)

    def test_real_filesystem_alias_forbidden(self):
        p = self.root / 'link'; p.unlink(); p.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): self.b.view('link')

    def test_source_change_rejected(self):
        (self.root / 'config/defaults.json').write_text('future fix')
        with self.assertRaises(ValueError): self.b.view('config/defaults.json')

    def test_contradictory_blob_identity_is_not_reported_as_verified(self):
        self.receipt['files'][0]['blob_oid'] = '0' * 40
        with self.assertRaises(ValueError): self.b.view('src/large.swift')

    def test_shell_write_delegation_not_tools(self):
        for tool in ['bash', 'edit', 'task', 'web_fetch', 'memory']:
            with self.subTest(tool=tool), self.assertRaises(ValueError): self.b.call(tool, {})

    def test_bool_not_a_line_number(self):
        with self.assertRaises(ValueError): self.b.view('long.txt', True)

    def test_calls_record_paths_and_ranges(self):
        self.b.view('config/defaults.json', 1, 1)
        self.assertEqual(self.b.calls[-1]['path'], 'config/defaults.json')
        self.assertEqual(self.b.calls[-1]['start_line'], 1)


class ImmutableReservations(unittest.TestCase):
    def setUp(self):
        self.i = intent('PUB-01', 123, 1, 'a' * 40, 'b' * 64, 'c' * 64)

    def test_exact_binding(self):
        class Store:
            def create_ref(self, ref, value): return {'created': True, 'ref': ref, 'intent': value}
        self.assertTrue(verify(reserve(Store(), self.i), self.i, 1))

    def test_rerun_or_unauthorized_case_rejected(self):
        for case, attempt in [('PUB-01', 2), ('PUB-11', 1), ('CP-01', 1)]:
            with self.assertRaises(ValueError): intent(case, 123, attempt, 'a' * 40, 'b' * 64, 'c' * 64)

    def test_contradictory_or_uncertain_remote_receipt_rejected(self):
        for result in [None, {}, {'created': False}, {'created': True}]:
            class Store:
                def create_ref(self, ref, value): return result
            with self.assertRaises(ValueError): reserve(Store(), self.i)

    def test_atomic_remote_conflict_allows_only_one_claim(self):
        class Store:
            def __init__(self): self.refs = set(); self.lock = threading.Lock()
            def create_ref(self, ref, value):
                with self.lock:
                    if ref in self.refs: return {'created': False}
                    self.refs.add(ref); return {'created': True, 'ref': ref, 'intent': value}
        store = Store()
        def claim(_):
            try: return bool(reserve(store, self.i))
            except ValueError: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(claim, range(2))), 1)

    def test_different_run_cannot_reuse_receipt(self):
        class Store:
            def create_ref(self, ref, value): return {'created': True, 'ref': ref, 'intent': value}
        receipt = reserve(Store(), self.i)
        other = dict(self.i, run_id=124)
        with self.assertRaises(ValueError): verify(receipt, other, 1)


class InertConstruction(unittest.TestCase):
    def test_exact_full_tree_diff_and_symlink_bytes(self):
        contents = {'a.txt': b'historical\n', 'link': b'../outside'}
        rows = []
        blobs = {}
        for name, value in contents.items():
            oid = hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()
            blobs[oid] = value; rows.append(('120000' if name == 'link' else '100644') + ' blob ' + oid + '\t' + name)
        def fake(repo, *args):
            if args[0] == 'rev-parse': return (('d' * 40 if args[-1].endswith('^{tree}') else args[-1][:40]) + '\n').encode()
            if args[0] == 'merge-base': return b''
            if args[0] == 'diff': return b'complete cumulative diff\n'
            if args[0] == 'ls-tree': return ('\0'.join(rows) + '\0').encode()
            if args[0] == 'cat-file': return blobs[args[-1]]
            raise AssertionError('Unexpected operation')
        with tempfile.TemporaryDirectory() as tmp, patch('repo_wide_readonly.snapshot.git', side_effect=fake):
            receipt, diff = build('/unused', {'base': 'a' * 40, 'head': 'b' * 40}, Path(tmp) / 'tree')
            self.assertTrue(receipt['complete']); self.assertEqual(receipt['file_count'], 2)
            self.assertEqual({r['path']: r['line_count'] for r in receipt['files']}, {'a.txt': 1, 'link': 1})
            self.assertEqual(diff, b'complete cumulative diff\n')
            self.assertFalse((Path(tmp) / 'tree/link').is_symlink())
            self.assertEqual((Path(tmp) / 'tree/link').read_bytes(), b'../outside')
            for p in (Path(tmp) / 'tree').rglob('*'): p.chmod(0o755 if p.is_dir() else 0o644)
            (Path(tmp) / 'tree').chmod(0o755)

    def test_dangerous_paths_rejected(self):
        for p in ['../x', '/etc/passwd', 'x//y', './x', '.git/index', 'x/../y', 'x\\y']:
            with self.subTest(path=p), self.assertRaises(ValueError): relative(p)


if __name__ == '__main__': unittest.main()
