"""Public historical series: reuse frozen v2 offline planner. No AI or evaluator inputs."""
import argparse
import functools
import json
import os
import subprocess
from pathlib import Path
import re
import pilot as p
import prompt_review as v1
import prompt_review_v2_adapter as adapter

SERIES = p.ROOT / 'series/public-2026-10-22'

def selected_adapter(methodology):
    if methodology == adapter.VERSION: return adapter
    if methodology == 'prompt-review-v2.1.0':
        import prompt_review_v21_adapter
        return prompt_review_v21_adapter
    raise ValueError('Unsupported public series methodology')

def check_contract(contract, methodology, manifest):
    selected=selected_adapter(methodology)
    freeze=selected.check_freeze()
    if contract is not None:
        expected={'methodology':methodology,'freeze_sha256':freeze,
                  'manifest_sha256':p.digest(Path(manifest).read_bytes()),
                  'limits':selected.LIMITS,'cli_version':'1.0.98','requested_selection':'auto',
                  'ai_authorized':False}
        if contract != expected:raise ValueError('Expanded offline contract identity mismatch')
    elif methodology != adapter.VERSION:
        raise ValueError('Expanded series requires explicit frozen offline contract')
    return selected,freeze

def blob_cache(rows,repos):
    """Batch immutable object reads; the existing prepare/verify still checks every OID."""
    cache={}
    for name in sorted({c['repository'] for c in rows}):
        repo=repos[name]
        shas={c[k] for c in rows if c['repository']==name for k in ('base','head')}
        ids=sorted({r['oid'] for sha in shas for r in p.tree(repo,sha) if r['type']=='blob'})
        env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
        process=subprocess.Popen(['git','--no-replace-objects','-c','core.hooksPath=/dev/null','-C',repo,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try: data,error=process.communicate(('\n'.join(ids)+'\n').encode(),timeout=120)
        except BaseException:
            process.kill();process.communicate();raise
        if process.returncode:raise ValueError('Batch historical object read failed')
        cursor=0;total=0
        for oid in ids:
            stop=data.index(b'\n',cursor);header=data[cursor:stop].decode().split();cursor=stop+1
            if len(header)!=3 or header[:2]!=[oid,'blob']:raise ValueError('Unexpected batch object identity')
            size=int(header[2]);raw=data[cursor:cursor+size];cursor+=size+1;total+=size
            if total>256*1024*1024 or len(raw)!=size or data[cursor-1:cursor]!=b'\n':raise ValueError('Batch object limit or truncation')
            import hashlib
            if hashlib.sha1(b'blob '+str(size).encode()+b'\0'+raw).hexdigest()!=oid:raise ValueError('Batch blob OID mismatch')
            cache[(repo,oid)]=subprocess.CompletedProcess([],0,raw,b'')
        if cursor!=len(data):raise ValueError('Unexpected trailing batch objects')
    return cache

def cases(path):
    value = p.load(path)
    rows = value['cases']
    if len(rows) != 10 or {c['id'] for c in rows} != {f'PUB-{i:02}' for i in range(1,11)}:
        raise ValueError('Exactly ten unique PUB cases required')
    for c in rows:
        if set(c) != {'id','repository','pr','base','head'} or not all(p.SHA.fullmatch(c[k]) for k in ('base','head')):
            raise ValueError('Unsealed manifest or historical identity')
        if (c['repository'],c['pr']) not in {('fakepooh/CodexBar',1),('fakepooh/homebridge-gree-airconditioner',1),('fakepooh/homebridge-gree-airconditioner',2)}:
            raise ValueError('Unexpected public PR')
    return rows

def dry_case(c, repo, root, methodology=adapter.VERSION, contexts_root=None):
    selected=selected_adapter(methodology)
    context = (contexts_root if contexts_root is not None else root/'contexts')/c['id']
    out = root/'dry-run'/c['id']
    if not context.exists(): p.prepare(c,repo,context)
    history = v1.verify_history(c,context,repo)
    row = dict(case=c, methodology=selected.VERSION, status='BLOCKED', diff_bytes=(context/'diff.txt').stat().st_size,
               diff_sha256=history['diff_sha256'],context_sha256=history['context_sha256'],
               ai_requests=0,model_consumption_proven=False)
    try:
        bundle=selected.build(context,c);selected.verify(bundle,context,c)
        p.save(out/'bundle.json',bundle)
        path=bundle['expected_pages'][0]['path']
        synthetic={'schema_version':1,'base_sha':c['base'],'head_sha':c['head'],
                   'summary':'Synthetic offline schema fixture, not a review.', 'findings':[],
                   'coverage':{'inspected_paths':[path],'limitations':['No AI inference performed.']}}
        v1.validate_review(json.dumps(synthetic),context,c)
        # A fixture cannot be admitted as completed AI evidence by the evaluator.
        try: p.evaluate({'cases':{}},{'cases':{c['id']:{}}},[])
        except ValueError: pass
        else: raise ValueError('Evaluator accepted missing model result')
        row.update(status='PASS',prompt_sha256=bundle['prompt_sha256'],prompt_bytes=bundle['prompt_bytes'],
                   pages=len(bundle['expected_pages']),omitted_pages=len(bundle['omitted_pages']),
                   schema_fixture_valid=True,evaluator_rejected_missing_ai_evidence=True,
                   transport='Canonical prompt built and rebuilt byte-exactly; native CLI-to-mock not executed for PUB.')
    except ValueError as e: row['reason']=str(e)
    p.save(out/'receipt.json',row)
    return row

def run(manifest,repos,output,methodology=adapter.VERSION,contexts_root=None,contract=None):
    selected,frozen=check_contract(contract,methodology,manifest);rows=[]
    if (output/'dry-run.json').exists():raise ValueError('Preserve previous series receipt; use fresh output')
    # Cache immutable object reads only, without changing any frozen source file.
    original=p.git;rows_input=cases(manifest);cache=blob_cache(rows_input,repos)
    cached=functools.lru_cache(maxsize=50000)(original)
    def read(repo,*args,**kwargs):
        if len(args)==3 and args[:2]==('cat-file','blob') and (str(repo),args[2]) in cache:return cache[(str(repo),args[2])]
        return cached(repo,*args,**kwargs)
    p.git=read
    try:
        for c in rows_input:
            try: row=dry_case(c,repos[c['repository']],output,methodology,contexts_root)
            except (ValueError,OSError,KeyError) as e: row={'case':c,'status':'BLOCKED','reason':str(e),'ai_requests':0}
            rows.append(row);print(json.dumps({k:row[k] for k in ('case','status','reason') if k in row}),flush=True)
    finally:p.git=original
    result={'methodology':selected.VERSION,'freeze_sha256':frozen,'checked_at':p.now(),'cases':rows,
            'manifest_sha256':p.digest(Path(manifest).read_bytes()),'limits':selected.LIMITS,
            'contract_sha256':p.digest(selected.canonical(contract).encode()) if contract is not None else None,
            'ai_reviews':0,'ai_credits_consumed':0,'github_actions_started':0,
            'ground_truth_loaded':False,'native_cli_transport_tested':False}
    p.save(output/'dry-run.json',result)
    return result

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--manifest',type=Path,default=SERIES/'manifest.json');a.add_argument('--repos',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    a.add_argument('--methodology',choices=['prompt-review-v2.0.0','prompt-review-v2.1.0'],default=adapter.VERSION)
    a.add_argument('--contexts-root',type=Path);a.add_argument('--contract',type=Path)
    args=a.parse_args();run(args.manifest,p.load(args.repos),args.output,args.methodology,args.contexts_root,p.load(args.contract) if args.contract else None)
