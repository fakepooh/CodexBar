import json
from pathlib import Path
import shutil
import tempfile
import unittest
from repo_wide_readonly.freeze import create, verify, DRAFT
from repo_wide_readonly.snapshot import canonical


class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); repo = Path(self.temp.name)
        self.root = repo / 'tools/copilot-pilot/repo_wide_readonly'; self.root.mkdir(parents=True)
        self.workflow = repo / '.github/workflows'; self.workflow.mkdir(parents=True)
        for name in ['ci.yml', 'copilot-repo-wide-live.yml']:
            (self.workflow / name).write_text('fixture-workflow-' + name)
        (self.root / 'adapter.mjs').write_text('FIXTURE; no model or secret')
        (self.root / 'methodology.json').write_text(json.dumps({'status': 'FROZEN', 'unknown_allowance_exception': True, 'live_enabled': True}))

    def tearDown(self): self.temp.cleanup()

    def test_exact_freeze_and_repeat_verification(self):
        create(self.root); self.assertEqual(verify(self.root), verify(self.root))
        with self.assertRaises(ValueError): create(self.root)

    def test_changes_additions_and_workflow_drift_fail_closed(self):
        create(self.root)
        for path in [self.root / 'adapter.mjs', self.workflow / 'copilot-repo-wide-live.yml', self.workflow / 'ci.yml']:
            old = path.read_bytes(); path.write_bytes(old + b'DRIFT')
            with self.assertRaises(ValueError): verify(self.root)
            path.write_bytes(old)
        (self.root / 'extra.py').write_text('unexpected adapter')
        with self.assertRaises(ValueError): verify(self.root)

    def test_draft_is_not_frozen_and_no_receipt_created(self):
        (self.root / 'methodology.json').write_text(json.dumps({'status': 'DRAFT'}))
        with self.assertRaises(ValueError): create(self.root)
        self.assertFalse((self.root / 'freeze.json').exists())

    def test_only_exact_not_frozen_placeholder_can_transition_once(self):
        path = self.root / 'freeze.json'; path.write_text(canonical(DRAFT) + '\n')
        with self.assertRaises(ValueError): verify(self.root)
        create(self.root); self.assertEqual(verify(self.root), verify(self.root))
        before = path.read_bytes()
        with self.assertRaises(ValueError): create(self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_disabled_or_unapproved_live_configuration_cannot_freeze(self):
        path = self.root / 'methodology.json'
        for key in ['live_enabled', 'unknown_allowance_exception']:
            for value in [False, None, 1, 'true']:
                method = {'status': 'FROZEN', 'unknown_allowance_exception': True, 'live_enabled': True}
                method[key] = value; path.write_text(json.dumps(method))
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): create(self.root)
                self.assertFalse((self.root / 'freeze.json').exists())


if __name__ == '__main__': unittest.main()
