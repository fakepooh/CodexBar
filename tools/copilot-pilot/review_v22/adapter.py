"""Versioned offline input builder. No live launcher or credential operations."""
import base64
import hashlib
import json
from pathlib import Path

import pilot as p
import prompt_review_v21_adapter as prior
import prompt_review_v21_sources as old_sources
from . import VERSION
from .context import CODE, CONFIG, CONTRACT, POLICY, canonical, digest, discover, safe_path

ROOT = Path(__file__).resolve().parent
LIMITS = POLICY


def snapshot(context, case):
    context = Path(context)
    meta = p.check_context(context, case)
    index = p.load(context/'index.json')
    if index['base'] != case['base'] or index['head'] != case['head']:
        raise ValueError('Historical SHA mismatch')
    trees, texts, decoded = {}, {}, {}
    for side in ('base', 'head'):
        trees[side], texts[side] = {}, {}
        for row in index['trees'][side]:
            path = safe_path(row['path'])
            if row['type'] != 'blob':
                continue
            if path in trees[side]:
                raise ValueError('Duplicate historical path')
            oid = row['oid']
            if not p.SHA.fullmatch(oid):
                raise ValueError('Invalid blob identity')
            if oid not in decoded:
                value = p.load(context/'blobs'/(oid+'.json'))
                if value['encoding'] not in ('utf-8', 'base64'):
                    raise ValueError('Unsupported historical encoding')
                raw = value['content'].encode() if value['encoding'] == 'utf-8' else base64.b64decode(value['content'], validate=True)
                actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
                if actual != oid or value['git_oid'] != oid:
                    raise ValueError('Historical blob mismatch')
                decoded[oid] = raw
            trees[side][path] = dict(row, sha256=digest(decoded[oid]))
            if row['mode'] not in ('100644', '100755'):
                continue
            try:
                texts[side][path] = decoded[oid].decode('utf-8')
            except UnicodeDecodeError:
                continue
    return meta, trees, texts


def build(context, case):
    meta, trees, texts = snapshot(context, case)
    diff = (Path(context)/'diff.txt').read_text()
    if not diff.strip() or len(diff.encode()) > POLICY['max_diff_bytes']:
        raise ValueError('Complete diff outside fixed budget; never clip')
    selection = discover(texts['head'], diff)
    # Base bodies supply removed/changed preconditions. No future commits.
    base_policy = dict(POLICY, max_depth=0)
    base = discover(texts['base'], diff, base_policy, 'base')
    candidates = [(r, 'head') for r in selection['selected']]
    # Behavioral source precedes documentation. Changed docs still exist in the
    # complete diff; large doc supplements must not displace caller bodies.
    seeds = set(selection['seed_units'])
    candidates = ([(r, s) for r, s in candidates if r['unit'] in seeds]
                  + [(r, 'base') for r in base['selected']]
                  + [(r, s) for r, s in candidates if r['unit'] not in seeds])
    def priority(item):
        row,side=item;ext=Path(row['path']).suffix
        if ext in CODE:
            rank=(0 if side=='head' else 1) if row['depth']==0 else 2+row['depth']
        elif ext in CONFIG:
            rank=2 if row['depth']==0 else 5
        else:
            rank=6
        if any(part.lower() in ('test','tests','fixtures','__tests__') for part in Path(row['path']).parts):
            rank=max(rank,5)
        return rank,row['depth'],row['path'],row['start'],side
    candidates.sort(key=priority)
    instruction = (ROOT/'review-prompt.txt').read_text().replace('BASE_SHA', case['base']).replace('HEAD_SHA', case['head'])
    body = dict(methodology=VERSION, base_sha=case['base'], head_sha=case['head'],
                diff_sha256=digest(diff.encode()), complete_diff=diff, source_pages=[],
                coverage_limits=dict(discovery=POLICY, semantic_completeness=False,
                                     omitted_units=0, static_unresolved_edges=0))
    def render():
        return instruction+'\n\nHISTORICAL_EVIDENCE_JSON\n'+canonical(body)
    if len(render().encode()) > POLICY['max_prompt_bytes']:
        raise ValueError('Instructions and complete diff exceed prompt limit')
    delivered, omitted = [], []
    # Reserve constant-width receipt counters before packing, so final metadata
    # can never silently evict a page. Actual omissions are in the sidecar receipt.
    body['coverage_limits']['omitted_units'] = len(candidates)
    body['coverage_limits']['static_unresolved_edges'] = sum(e['status'] != 'RESOLVED' for e in selection['dependencies'])
    for row, side in candidates:
        source = texts[side][row['path']].splitlines()
        encoded = []
        pages, records, used = [], [], 0
        # Encode original line numbers BEFORE packing. Relocating already full
        # pages can exceed their bound on files with many short lines.
        for number in range(row['start'], row['end']+1):
            line = source[number-1]
            fragments = [line[i:i+300] for i in range(0,len(line),300)] or ['']
            for part, text in enumerate(fragments):
                rec = dict(line=number, part=part, text=text)
                size = len((json.dumps(rec, ensure_ascii=True)+'\n').encode())
                if size > POLICY['page_bytes']:
                    raise ValueError('Source fragment cannot fit page')
                if records and used+size > POLICY['page_bytes']:
                    pages.append(records); records=[]; used=0
                records.append(rec); used+=size
        if records:
            pages.append(records)
        for records in pages:
            content = ''.join(json.dumps(rec, ensure_ascii=True)+'\n' for rec in records)
            encoded.append(dict(path=row['path'], side=side, commit=case[side],
                                blob_oid=trees[side][row['path']]['oid'],
                                source_sha256=trees[side][row['path']]['sha256'],
                                line_start=records[0]['line'], line_end=records[-1]['line'],
                                content_sha256=digest(content.encode()), content=content,
                                unit=row['unit'], page=len(body['source_pages'])+len(encoded)))
        before = len(body['source_pages'])
        body['source_pages'].extend(encoded)
        body['coverage_limits']['omitted_units'] -= 1
        if (len(body['source_pages']) > POLICY['max_pages'] or len(render().encode()) > POLICY['max_prompt_bytes']):
            del body['source_pages'][before:]
            body['coverage_limits']['omitted_units'] += 1
            omitted.append(dict(side=side, unit=row['unit'], path=row['path'], start=row['start'], end=row['end'], reason='transport_budget'))
        else:
            delivered.append(dict(side=side, **{k: row[k] for k in row if k != 'text'}))
    if not body['source_pages']:
        raise ValueError('No source ranges delivered')
    prompt = render(); prior.assert_clean(prompt)
    head_units = {r['unit'] for r in delivered if r['side'] == 'head'}
    edges = [dict(e, delivered_targets=[t for t in e['targets'] if t in head_units],
                  coverage=('COVERED' if e['status'] == 'RESOLVED' and all(t in head_units for t in e['targets'])
                            else 'MISSING_OR_UNCERTAIN')) for e in selection['dependencies']]
    receipt = dict(contract=CONTRACT, methodology=VERSION, case=case,
                   input_sha256=meta['context_sha256'], prompt_sha256=digest(prompt.encode()),
                   diff_sha256=body['diff_sha256'], prompt_bytes=len(prompt.encode()),
                   selected_sources=delivered, dependencies=edges,
                   omissions=selection['omissions']+omitted,
                   base_scope='changed-containing ranges only; full removed lines also in complete diff',
                   base_omissions=base['omissions'],
                   unavailable_sources=[dict(side=side,path=path,reason='nonregular_or_non_utf8')
                       for side in ('base','head') for path in sorted(trees[side]) if path not in texts[side]],
                   semantic_completeness=False,
                   status='PARTIAL' if omitted or selection['omissions'] or any(e['coverage'] != 'COVERED' for e in edges) else 'SCOPED_STATIC_CLOSURE',
                   model_consumption_proven=False, ai_requests=0,
                   limits=POLICY, limitations=selection['limitations'])
    return dict(methodology=VERSION, case=case, prompt=prompt,
                context_sha256=meta['context_sha256'],
                prompt_sha256=digest(prompt.encode()), prompt_bytes=len(prompt.encode()),
                expected_pages=[{k:v for k,v in page.items() if k != 'content'} for page in body['source_pages']],
                coverage_receipt=receipt, requested_selection='auto',
                actual_model=None, routing_events=[], live_authorized=False, ai_requests=0)


def verify(bundle, context, case):
    if bundle != build(context, case):
        raise ValueError('Historical reconstruction mismatch')
    return bundle


def freeze_description():
    # Delivery attestation/orchestration can evolve independently without
    # changing review instructions, selection, ordering or model-visible bytes.
    names=['__init__.py','adapter.py','context.py','audit.py','admissibility.py',
           'review-prompt.txt','output.schema.json','methodology.json',
           'CONTEXT-CONTRACT.md','ADMISSIBILITY-CONTRACT.md','CHANGES.md']
    paths=sorted(ROOT/name for name in names)
    return dict(methodology=VERSION, cli_version='1.0.98', requested_selection='auto',
                policy=POLICY, artifacts={p.name:digest(p.read_bytes()) for p in paths},
                reused_v21_freeze=prior.check_freeze(),
                reviewer_prompt_unchanged=digest((ROOT/'review-prompt.txt').read_bytes()) == digest(prior.TEMPLATE.read_bytes()))


def check_freeze():
    value = json.loads((ROOT/'freeze.json').read_text())
    if value != freeze_description():
        raise ValueError('Frozen v2.2.0 drift')
    return digest(canonical(value).encode())


def cli_args(credit_limit=30):
    return prior.cli_args(credit_limit)
