"""Only allowlisted offline identities/counts may enter public Actions logs."""
import json
import os
from pathlib import Path
import pilot as p
import public_series
from . import adapter


def sanitized(value):
    expected=public_series.cases(public_series.SERIES/'manifest.json')
    rows=value.get('cases',[])
    if (value.get('methodology')!=adapter.VERSION or value.get('freeze_sha256')!=adapter.check_freeze()
            or [r.get('case') for r in rows]!=expected or value.get('ai_requests')!=0
            or value.get('ground_truth_loaded') is not False or value.get('all_passed') is not True):
        raise ValueError('Offline published receipt identity mismatch')
    for row in rows:
        if (row.get('status')!='PASS' or row.get('ai_requests')!=0
                or row.get('ground_truth_loaded') is not False or row.get('model_consumption_proven') is not False
                or row.get('deterministic') is not True or row.get('schema_fixture_valid') is not True
                or row['prompt_bytes']>adapter.POLICY['max_prompt_bytes']):
            raise ValueError('Incomplete offline case')
    fields=('case','status','prompt_sha256','prompt_bytes','diff_bytes','pages','source_ranges',
            'containing_function_ranges','dependencies','covered_dependencies','unresolved_or_uncovered_dependencies',
            'context_status','deterministic')
    return dict(methodology=adapter.VERSION,freeze_sha256=adapter.check_freeze(),
                commit=os.environ.get('GITHUB_SHA'),run=os.environ.get('GITHUB_RUN_ID'),
                cases=[{k:r[k] for k in fields} for r in rows],ai_requests=0,live_enabled=False,
                semantic_completeness=False,model_consumption_proven=False)

if __name__=='__main__':
    report=sanitized(p.load(Path(os.environ['REPORT'])))
    output=json.dumps(report,indent=2)
    print(output)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as target:target.write('```json\n'+output+'\n```\n')
