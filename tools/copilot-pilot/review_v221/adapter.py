"""Retain v2.1 whole-line evidence; admit only novel bounded v2.2 ranges.

No evaluator input. Same static discovery, review task, model selection and hard
prompt/diff budget. Coverage comes from exact diff + retained + novel pages.
"""
import json
import ast
from pathlib import Path
import re
import pilot as p
import prompt_review_v21_adapter as prior
from review_v22 import adapter as base
from review_v22.context import CODE,CONFIG,POLICY,canonical,digest,discover
from . import VERSION
ROOT=Path(__file__).resolve().parent
snapshot=base.snapshot
cli_args=base.cli_args


def line_map(diff):
    result={side:{} for side in ('base','head')};paths={};old=new=0;active=False
    def path(value,prefix):
        if value=='/dev/null':return None
        if value.startswith('"'):
            try:
                value=ast.literal_eval(value)
                try:value=value.encode('latin1').decode('utf-8')
                except (UnicodeEncodeError,UnicodeDecodeError):pass
            except (SyntaxError,ValueError):raise ValueError('Invalid quoted diff path') from None
        if not isinstance(value,str) or not value.startswith(prefix):raise ValueError('Unexpected diff path')
        return value[len(prefix):]
    for line in diff.splitlines():
        if line.startswith('diff --git'):active=False
        elif line.startswith('--- '):paths['base']=path(line[4:],'a/')
        elif line.startswith('+++ '):paths['head']=path(line[4:],'b/')
        elif line.startswith('@@ '):
            match=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@',line)
            if not match:raise ValueError('Invalid hunk')
            old,new=map(int,match.groups());active=True
        elif active:
            if line.startswith((' ','-')) and paths.get('base'):
                result['base'].setdefault(paths['base'],{})[old]=line[1:];old+=1
            if line.startswith((' ','+')) and paths.get('head'):
                result['head'].setdefault(paths['head'],{})[new]=line[1:];new+=1
    return result


def runs(numbers):
    start=end=None
    for n in sorted(numbers):
        if end is not None and n!=end+1:yield start,end;start=None
        if start is None:start=n
        end=n
    if start is not None:yield start,end


def build(context,case):
    meta,trees,texts=snapshot(context,case)
    legacy=prior.build(context,case)
    old=json.loads(legacy['prompt'].split('HISTORICAL_EVIDENCE_JSON\n')[1])
    diff=old['complete_diff'];visible=line_map(diff)
    selection=discover(texts['head'],diff)
    base_selection=discover(texts['base'],diff,dict(POLICY,max_depth=0),'base')
    # Complete original source lines touched by each old page. Never retain a
    # clipped line fragment as if it were a whole line. If closure cannot fit,
    # fail closed instead of dropping any previously supplied evidence.
    retained={}
    for page in old['source_pages']:
        key=(page['side'],page['path'])
        retained.setdefault(key,set()).update(json.loads(s)['line'] for s in page['content'].splitlines())
    candidates=[]
    for (side,path),numbers in sorted(retained.items()):
        for start,end in runs(numbers):
            candidates.append((dict(path=path,start=start,end=end,unit=f'baseline:{path}:{start}-{end}',
                                    kind='retained_v21_range',depth=0,reason='monotonic_v21_retention',origin=None,
                                    parent_start=start,parent_end=end,partial_parent=False),side,True))
    seeds=set(selection['seed_units'])
    discovered=[(r,'head',False) for r in selection['selected']]+[(r,'base',False) for r in base_selection['selected']]
    def priority(item):
        r,side,_=item;ext=Path(r['path']).suffix
        rank=((0 if side=='head' else 1) if r['depth']==0 else 2+r['depth']) if ext in CODE else (2 if ext in CONFIG else 6)
        if any(x.lower() in ('tests','test','fixtures','__tests__') for x in Path(r['path']).parts):rank=max(rank,5)
        return rank,r['depth'],r['path'],r['start'],side
    candidates+=sorted(discovered,key=priority)
    instruction=prior.TEMPLATE.read_text().replace('BASE_SHA',case['base']).replace('HEAD_SHA',case['head'])
    body=dict(methodology=VERSION,base_sha=case['base'],head_sha=case['head'],diff_sha256=digest(diff.encode()),
              complete_diff=diff,source_pages=[],coverage_limits=dict(discovery=POLICY,semantic_completeness=False,
                omitted_units=len(candidates),static_unresolved_edges=sum(e['status']!='RESOLVED' for e in selection['dependencies'])))
    def render():return instruction+'\n\nHISTORICAL_EVIDENCE_JSON\n'+canonical(body)
    sources=[];omitted=[];covered_without_pages=[]
    for row,side,mandatory in candidates:
        path=row['path'];lines=texts[side][path].splitlines();seen=visible[side].setdefault(path,{})
        # Existing diff/retained evidence is verified against the same blob.
        if any(lines[n-1]!=s for n,s in seen.items()):raise ValueError('Conflicting historical line evidence')
        missing=[n for n in range(row['start'],row['end']+1) if n not in seen]
        segments=list(runs(missing))
        pages=[];new_sources=[]
        for start,end in segments:
            unit=f'{row["unit"]}@{start}-{end}'
            records=[];used=0;chunks=[]
            for number in range(start,end+1):
                line=lines[number-1]
                fragments=[line[i:i+300] for i in range(0,len(line),300)] or ['']
                for part,text in enumerate(fragments):
                    rec=dict(line=number,part=part,text=text);size=len((json.dumps(rec,ensure_ascii=True)+'\n').encode())
                    if size>POLICY['page_bytes']:raise ValueError('Oversized source record')
                    if records and used+size>POLICY['page_bytes']:chunks.append(records);records=[];used=0
                    records.append(rec);used+=size
            if records:chunks.append(records)
            for records in chunks:
                content=''.join(json.dumps(x,ensure_ascii=True)+'\n' for x in records)
                pages.append(dict(path=path,side=side,commit=case[side],blob_oid=trees[side][path]['oid'],
                                  source_sha256=trees[side][path]['sha256'],line_start=records[0]['line'],line_end=records[-1]['line'],
                                  content_sha256=digest(content.encode()),content=content,unit=unit,page=len(body['source_pages'])+len(pages)))
            new_sources.append(dict({k:v for k,v in row.items() if k!='text'},side=side,
                                    source_unit=row['unit'],unit=unit,start=start,end=end))
        old_count=len(body['source_pages']);body['source_pages']+=pages
        body['coverage_limits']['omitted_units']-=1
        if len(body['source_pages'])>POLICY['max_pages'] or len(render().encode())>POLICY['max_prompt_bytes']:
            del body['source_pages'][old_count:];body['coverage_limits']['omitted_units']+=1
            if mandatory:raise ValueError('Complete legacy line closure cannot fit fixed budget; monotonicity blocks')
            omitted.append(dict(side=side,unit=row['unit'],path=path,start=row['start'],end=row['end'],reason='transport_budget'))
        else:
            sources+=new_sources
            if not pages:covered_without_pages.append(dict(side=side,unit=row['unit'],path=path,start=row['start'],end=row['end'],channel='existing_exact_diff_or_source_pages'))
            for n in missing:seen[n]=lines[n-1]
    if not body['source_pages']:raise ValueError('No historical source pages')
    def covered(unit):
        path,span=unit.rsplit(':',1);start,end=map(int,span.split('-'))
        return all(n in visible['head'].get(path,{}) for n in range(start,end+1))
    edges=[dict(e,delivered_targets=[t for t in e['targets'] if covered(t)],
                coverage='COVERED' if e['status']=='RESOLVED' and all(covered(t) for t in e['targets']) else 'MISSING_OR_UNCERTAIN') for e in selection['dependencies']]
    prompt=render();prior.assert_clean(prompt)
    receipt=dict(contract='context-completeness-v1.0.0',methodology=VERSION,case=case,input_sha256=meta['context_sha256'],
        prompt_sha256=digest(prompt.encode()),diff_sha256=body['diff_sha256'],prompt_bytes=len(prompt.encode()),selected_sources=sources,
        dependencies=edges,omissions=selection['omissions']+omitted,base_omissions=base_selection['omissions'],
        covered_without_new_pages=covered_without_pages,
        baseline_retention=dict(methodology=prior.VERSION,prompt_sha256=legacy['prompt_sha256'],
                               original_page_count=len(old['source_pages']),whole_line_closure=True,all_previous_source_lines_retained=True),
        semantic_completeness=False,status='PARTIAL' if selection['omissions'] or omitted or any(e['coverage']!='COVERED' for e in edges) else 'SCOPED_STATIC_CLOSURE',
        model_consumption_proven=False,ai_requests=0,limits=POLICY,limitations=selection['limitations'])
    return dict(methodology=VERSION,case=case,context_sha256=meta['context_sha256'],prompt=prompt,
        prompt_sha256=digest(prompt.encode()),prompt_bytes=len(prompt.encode()),
        expected_pages=[{k:v for k,v in page.items() if k!='content'} for page in body['source_pages']],
        coverage_receipt=receipt,requested_selection='auto',actual_model=None,routing_events=[],live_authorized=False,ai_requests=0)


def verify(bundle,context,case):
    if bundle!=build(context,case):raise ValueError('Frozen historical reconstruction mismatch')
    return bundle


def freeze_description():
    return dict(methodology=VERSION,cli_version='1.0.98',requested_selection='auto',policy=POLICY,
                reused_v22_freeze=base.check_freeze(),reused_v21_freeze=prior.check_freeze(),
                artifacts={name:digest((ROOT/name).read_bytes()) for name in ['__init__.py','adapter.py','audit.py','methodology.json','CHANGES.md']})


def check_freeze():
    if p.load(ROOT/'freeze.json')!=freeze_description():raise ValueError('Frozen v2.2.1 drift')
    return digest(canonical(freeze_description()).encode())
