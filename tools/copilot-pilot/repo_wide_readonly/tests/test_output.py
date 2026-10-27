import copy
import json
import unittest
from repo_wide_readonly.validate import validate


class OutputContract(unittest.TestCase):
    def setUp(self):
        self.case = {'base': 'a' * 40, 'head': 'b' * 40}
        self.receipt = {'complete': True, 'case': self.case, 'file_count': 1,
                        'files': [{'path': 'src/public.txt', 'line_count': 10}]}
        self.value = {'schema_version': 1, 'base_sha': 'a' * 40, 'head_sha': 'b' * 40,
                      'summary': 'Synthetic protocol fixture only; no historical finding.', 'findings': [],
                      'coverage': {'inspected_paths': ['src/public.txt'], 'limitations': []}}
        self.finding = {'id': 'F1', 'priority': 'P2', 'title': 'Synthetic protocol fixture',
                        'path': 'src/public.txt', 'side': 'head', 'line_start': 2, 'line_end': 3,
                        'trigger': 'fixture', 'impact': 'fixture', 'evidence': 'fixture', 'confidence': 'high'}

    def apply(self, value=None, raw=None, **kwargs):
        return validate(raw if raw is not None else json.dumps(value or self.value),
                        self.receipt, ['src/public.txt'], **kwargs)

    def test_exact_schema_and_known_json_framing(self):
        value, proof = self.apply(raw='```json\n' + json.dumps(self.value) + '\n```')
        self.assertEqual(value, self.value)
        self.assertTrue(proof['json_framing_removed'])
        self.assertFalse(proof['semantic_correctness_proved'])
        self.assertFalse(proof['model_consumption_proved'])

    def test_non_json_or_duplicate_fields_are_not_repaired(self):
        for raw in ['explanation\n' + json.dumps(self.value), json.dumps(self.value) + '{}',
                    '{"schema_version":1,"schema_version":1}', 'NaN']:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError): self.apply(raw=raw)

    def test_wrong_historical_sha_or_typed_version_fails(self):
        for key, value in [('head_sha', 'c' * 40), ('schema_version', True), ('schema_version', 1.0)]:
            with self.subTest(key=key), self.assertRaises(ValueError): self.apply(dict(self.value, **{key: value}))

    def test_extra_fields_and_unknown_context_claims_fail(self):
        with self.assertRaises(ValueError): self.apply(dict(self.value, extra='not allowed'))
        value = copy.deepcopy(self.value); value['coverage']['inspected_paths'] = ['private/ground-truth.json']
        with self.assertRaises(ValueError): self.apply(value)

    def test_valid_range_and_deleted_base_range_are_separate(self):
        value = dict(self.value, findings=[self.finding]); self.apply(value)
        value = copy.deepcopy(value); value['findings'][0]['side'] = 'base'
        with self.assertRaises(ValueError): self.apply(value)
        self.apply(value, base_files={'src/public.txt': {'line_count': 5}})

    def test_future_path_and_invalid_line_range_fail(self):
        for patch in [{'path': 'future-fix.txt'}, {'path': '../private'}, {'line_end': 11},
                      {'line_start': True}, {'line_start': 4, 'line_end': 3}]:
            value = dict(self.value, findings=[dict(self.finding, **patch)])
            with self.subTest(patch=patch), self.assertRaises(ValueError): self.apply(value)

    def test_duplicate_ids_fail_without_merging_findings(self):
        with self.assertRaises(ValueError): self.apply(dict(self.value, findings=[self.finding, self.finding]))


if __name__ == '__main__': unittest.main()
