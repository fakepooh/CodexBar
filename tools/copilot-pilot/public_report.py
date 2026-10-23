"""Emit only allowlisted offline metadata. Never print prompts, blobs or evaluator data."""
import json
import os
from pathlib import Path
import pilot as p
import public_series as series

FIELDS = ('case', 'methodology', 'status', 'diff_bytes', 'diff_sha256',
          'context_sha256', 'prompt_sha256', 'prompt_bytes', 'pages', 'omitted_pages',
          'schema_fixture_valid', 'evaluator_rejected_missing_ai_evidence', 'ai_requests')

def receipt(report, manifest, contract, commit, run_id):
    adapter, freeze = series.check_contract(contract, 'prompt-review-v2.1.0', manifest)
    expected = {c['id']: c for c in series.cases(manifest)}
    rows = report['cases']
    if (report.get('methodology') != adapter.VERSION or report.get('freeze_sha256') != freeze
            or report.get('contract_sha256') != p.digest(adapter.canonical(contract).encode())
            or report.get('manifest_sha256') != p.digest(Path(manifest).read_bytes())
            or report.get('ai_reviews') != 0 or report.get('ground_truth_loaded') is not False
            or len(rows) != 10 or {r['case']['id'] for r in rows} != set(expected)):
        raise ValueError('Incomplete or contradictory offline receipt')
    for row in rows:
        if (row['case'] != expected[row['case']['id']] or row.get('methodology') != adapter.VERSION
                or row.get('status') != 'PASS' or row.get('ai_requests') != 0
                or row.get('schema_fixture_valid') is not True
                or row.get('evaluator_rejected_missing_ai_evidence') is not True
                or row.get('model_consumption_proven') is not False):
            raise ValueError('Case is not exact verified offline input')
        for key in ('diff_sha256', 'context_sha256', 'prompt_sha256'):
            value = row.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('Missing input hash')
        if not (0 < row['diff_bytes'] <= adapter.LIMITS['max_diff_bytes']
                and 0 < row['prompt_bytes'] <= adapter.LIMITS['max_prompt_bytes']
                and 0 < row['pages'] <= adapter.LIMITS['max_pages']):
            raise ValueError('Frozen limits violated')
    return {'commit': commit, 'run_id': run_id, 'methodology': adapter.VERSION,
            'freeze_sha256': freeze, 'contract_sha256': report['contract_sha256'],
            'ai_reviews': 0, 'ground_truth_loaded': False,
            'cases': [{k: row[k] for k in FIELDS} for row in rows]}

if __name__ == '__main__':
    report = p.load(Path(os.environ['REPORT']))
    result = receipt(report, series.SERIES/'manifest.json',
                     p.load(series.SERIES/'expanded-v2.1.0/contract.json'),
                     os.environ['GITHUB_SHA'], os.environ['GITHUB_RUN_ID'])
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
        output.write('Offline only; 10/10 PASS; AI invocations: 0\n\n')
        for row in result['cases']:
            output.write(row['case']['id'] + ': ' + row['status'] + '\n\n')
    print('COPILOT_PILOT_OFFLINE_RECEIPT=' + json.dumps(result, sort_keys=True))
