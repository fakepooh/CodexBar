"""Evaluator-only contract. Never import into the reviewer input builder.

Machines validate evidence bindings and explicit adjudication, not defect truth.
Human/static causal adjudication is recorded separately from visibility.
"""
import re
from .context import canonical, digest

VERSION = 'ground-truth-admissibility-v1.0.0'
STATUSES = {'ADMISSIBLE', 'CONDITIONAL', 'PRE_EXISTING', 'INVALID', 'INDETERMINATE'}


def verify_sources(record, evidence, context, case):
    """Bind evaluator claims to freshly verified immutable historical blobs."""
    from .adapter import snapshot
    from .context import safe_path
    _, trees, texts = snapshot(context, case)
    if record['reviewed_sha'] != case['head'] or record['base_sha'] != case['base']:
        raise ValueError('Adjudication endpoint mismatch')
    for row in evidence:
        side='head' if row['commit']==case['head'] else 'base' if row['commit']==case['base'] else None
        path=safe_path(row['path'])
        if (not side or path not in texts[side] or row['blob_oid'] != trees[side][path]['oid']
                or row['content_sha256'] != trees[side][path]['sha256']
                or not 1 <= row['line_start'] <= row['line_end'] <= len(texts[side][path].splitlines())):
            raise ValueError('Admissibility source identity/range mismatch')
    return dict(status='VERIFIED_HISTORICAL_SOURCES',evidence_sha256=digest(canonical(evidence).encode()))


def classify(record, evidence):
    required = {'id', 'reviewed_sha', 'base_sha', 'defect_exists', 'introduced',
                'configuration', 'reproduction', 'severity', 'duplicate_of',
                'adjudicator', 'rationale', 'evidence_sha256'}
    if set(record) != required:
        raise ValueError('Admissibility record fields incomplete or unexpected')
    for key in ('reviewed_sha', 'base_sha'):
        if not re.fullmatch(r'[0-9a-f]{40}', record[key]):
            raise ValueError('Exact historical identities required')
    if record['reviewed_sha'] == record['base_sha']:
        raise ValueError('Distinct regression endpoints required')
    if record['evidence_sha256'] != digest(canonical(evidence).encode()):
        raise ValueError('Evidence integrity mismatch')
    if not evidence or not record['adjudicator'] or not record['rationale']:
        raise ValueError('Independent evidence and causal adjudication required')
    for row in evidence:
        if (row.get('commit') not in (record['base_sha'], record['reviewed_sha'])
                or not re.fullmatch(r'[0-9a-f]{40}', row.get('blob_oid', ''))
                or not re.fullmatch(r'[0-9a-f]{64}', row.get('content_sha256', ''))
                or not isinstance(row.get('line_start'), int)
                or row['line_start'] < 1 or row.get('line_end', 0) < row['line_start']):
            raise ValueError('Unbound historical evidence')
    if record['defect_exists'] not in ('SUPPORTED', 'REFUTED', 'UNCONFIRMED'):
        raise ValueError('Explicit defect-truth status required')
    if record['introduced'] not in ('YES', 'NO', 'UNKNOWN'):
        raise ValueError('Explicit regression status required')
    if record['duplicate_of'] or record['defect_exists'] == 'REFUTED':
        status = 'INVALID'
    elif record['defect_exists'] != 'SUPPORTED':
        status = 'INDETERMINATE'
    elif record['introduced'] == 'NO':
        status = 'PRE_EXISTING'
    elif record['introduced'] != 'YES':
        status = 'INDETERMINATE'
    elif (record['reproduction'].get('status') not in ('STATIC_PROOF', 'REPRODUCED')
          or not record['reproduction'].get('conditions')
          or not record['reproduction'].get('causal_steps')
          or record['severity'].get('status') != 'SUPPORTED'
          or record['severity'].get('priority') not in ('P1','P2')
          or not record['severity'].get('rationale')):
        status = 'INDETERMINATE'
    elif record['configuration'].get('status') == 'SPECIFIC_CONFIRMED':
        status = 'CONDITIONAL'
    elif record['configuration'].get('status') == 'DEFAULT_CONFIRMED':
        status = 'ADMISSIBLE'
    else:
        status = 'INDETERMINATE'
    return dict(contract=VERSION, id=record['id'], status=status,
                defect_truth=record['defect_exists'], introduced=record['introduced'],
                severity=record['severity'], evidence_sha256=record['evidence_sha256'],
                discoverability='NOT_EVALUATED', machine_check_is_not_truth_proof=True)
