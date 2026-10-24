"""Independent range/fragment verifier; does not trust selector coverage counts."""
import json
from collections import defaultdict
from .context import canonical, digest, POLICY
from .adapter import snapshot, ROOT, VERSION


def verify_payload(bundle, context, case):
    _, trees, texts = snapshot(context, case)
    prompt = bundle['prompt']
    if digest(prompt.encode()) != bundle['prompt_sha256'] or len(prompt.encode()) != bundle['prompt_bytes']:
        raise ValueError('Input hash mismatch')
    body = json.loads(prompt.split('HISTORICAL_EVIDENCE_JSON\n')[1])
    instruction=(ROOT/'review-prompt.txt').read_text().replace('BASE_SHA',case['base']).replace('HEAD_SHA',case['head'])
    if (prompt != instruction+'\n\nHISTORICAL_EVIDENCE_JSON\n'+canonical(body)
            or set(body) != {'methodology','base_sha','head_sha','diff_sha256','complete_diff','source_pages','coverage_limits'}
            or body['methodology'] != VERSION or bundle['methodology'] != VERSION):
        raise ValueError('Unexpected instructions or model-visible fields')
    limits=body['coverage_limits']
    if (set(limits) != {'discovery','semantic_completeness','omitted_units','static_unresolved_edges'}
            or limits['discovery'] != POLICY or limits['semantic_completeness'] is not False
            or any(type(limits[k]) is not int or limits[k]<0 for k in ('omitted_units','static_unresolved_edges'))
            or bundle['prompt_bytes'] > POLICY['max_prompt_bytes']
            or len(body['source_pages']) > POLICY['max_pages']):
        raise ValueError('Unexpected context limits')
    if body['base_sha'] != case['base'] or body['head_sha'] != case['head']:
        raise ValueError('Payload revision mismatch')
    from pathlib import Path
    diff = (Path(context)/'diff.txt').read_text()
    if body['complete_diff'] != diff or body['diff_sha256'] != digest(diff.encode()):
        raise ValueError('Complete diff changed')
    expected = [{k:v for k,v in x.items() if k != 'content'} for x in body['source_pages']]
    if bundle['expected_pages'] != expected:
        raise ValueError('Page ordering or metadata differs')
    fragments = defaultdict(list)
    for ordinal, page in enumerate(body['source_pages']):
        if set(page) != {'path','side','commit','blob_oid','source_sha256','line_start','line_end','content_sha256','content','unit','page'}:
            raise ValueError('Unexpected model-visible source fields')
        side, path = page['side'], page['path']
        if (page['page'] != ordinal or page['commit'] != case[side]
                or page['blob_oid'] != trees[side][path]['oid']
                or page['source_sha256'] != trees[side][path]['sha256']
                or page['content_sha256'] != digest(page['content'].encode())):
            raise ValueError('Source identity mismatch')
        if len(page['content'].encode()) > POLICY['page_bytes']:
            raise ValueError('Oversized source page')
        records = [json.loads(s) for s in page['content'].splitlines()]
        if not records or records[0]['line'] != page['line_start'] or records[-1]['line'] != page['line_end']:
            raise ValueError('Page line range mismatch')
        for record in records:
            if set(record) != {'line', 'part', 'text'}:
                raise ValueError('Invalid source record')
            fragments[(side, path, page['unit'], record['line'])].append((record['part'], record['text']))
    visibility = defaultdict(set)
    for (side, path, unit, number), parts in fragments.items():
        if [i for i, _ in parts] != list(range(len(parts))):
            raise ValueError('Missing or reordered source fragments')
        if ''.join(s for _, s in parts) != texts[side][path].splitlines()[number-1]:
            raise ValueError('Source content altered or truncated')
        visibility[(side, path, unit)].add(number)
    receipt = bundle['coverage_receipt']
    if receipt['prompt_sha256'] != bundle['prompt_sha256'] or receipt['case'] != case:
        raise ValueError('Coverage receipt identity mismatch')
    seen = set()
    for row in receipt['selected_sources']:
        key = (row['side'], row['path'], row['unit'])
        if key in seen or visibility[key] != set(range(row['start'], row['end']+1)):
            raise ValueError('Incomplete logical range or duplicate receipt')
        seen.add(key)
    if set(visibility) != seen:
        raise ValueError('Unreceipted source content')
    head = {r['unit'] for r in receipt['selected_sources'] if r['side'] == 'head'}
    for edge in receipt['dependencies']:
        targets = [t for t in edge['targets'] if t in head]
        status = 'COVERED' if edge['status'] == 'RESOLVED' and len(targets) == len(edge['targets']) else 'MISSING_OR_UNCERTAIN'
        if edge['delivered_targets'] != targets or edge['coverage'] != status:
            raise ValueError('Contradictory dependency coverage')
    if receipt['semantic_completeness'] is not False:
        raise ValueError('Semantic completeness cannot be asserted')
    partial=bool(receipt['omissions'] or any(e['coverage']!='COVERED' for e in receipt['dependencies']))
    if receipt['status'] != ('PARTIAL' if partial else 'SCOPED_STATIC_CLOSURE'):
        raise ValueError('Coverage status contradicts unresolved dependencies')
    return dict(status='PASS', page_count=len(expected), source_range_count=len(seen),
                complete_diff=True, exact_source_fragments=True,
                prompt_sha256=bundle['prompt_sha256'], semantic_completeness=False,
                transport_proven=False, model_consumption_proven=False)
