"""Offline ten-case reconstruction. No evaluator or model invocation."""
import argparse
import functools
import json
from pathlib import Path
import secrets
import time

import pilot as p
import public_series as legacy
import prompt_review as history
from . import adapter as a, audit, transport


def run(manifest, repos, contexts_root, output, require_freeze=True):
    if output.exists():raise ValueError('Fresh immutable output directory required')
    freeze=a.check_freeze() if require_freeze else None
    cases=legacy.cases(manifest)
    # Reuse immutable, verified Git batch reads only; no historical code execution.
    original=p.git;cache=legacy.blob_cache(cases,repos)
    cached=functools.lru_cache(maxsize=50000)(original)
    def read(repo,*args,**kwargs):
        if len(args)==3 and args[:2]==('cat-file','blob') and (str(repo),args[2]) in cache:
            return cache[(str(repo),args[2])]
        return cached(repo,*args,**kwargs)
    rows=[];p.git=read
    try:
        for case in cases:
            started=time.monotonic();context=contexts_root/case['id']
            if not context.exists():p.prepare(case,repos[case['repository']],context)
            identity=history.verify_history(case,context,repos[case['repository']])
            first=a.build(context,case);second=a.build(context,case)
            if first!=second:raise ValueError('Nondeterministic reconstruction')
            checked=audit.verify_payload(first,context,case)
            key=secrets.token_bytes(32);nonce=secrets.token_hex(24)
            envelope=transport.receive(transport.frame(first),first,key,nonce)
            delivery=transport.validate(envelope,first,context,case,key,nonce)
            # Deterministic oracle is not native CLI or an AI result.
            synthetic=dict(schema_version=1,base_sha=case['base'],head_sha=case['head'],
                summary='Offline schema fixture only.',findings=[],
                coverage=dict(inspected_paths=[first['expected_pages'][0]['path']],limitations=['No model executed.']))
            history.validate_review(json.dumps(synthetic),context,case)
            receipt=first['coverage_receipt']
            row=dict(case=case,status='PASS',methodology=a.VERSION,freeze_sha256=freeze,
                     context_sha256=identity['context_sha256'],diff_sha256=identity['diff_sha256'],
                     diff_bytes=(context/'diff.txt').stat().st_size,prompt_bytes=first['prompt_bytes'],
                     prompt_sha256=first['prompt_sha256'],pages=len(first['expected_pages']),
                     source_ranges=len(receipt['selected_sources']),
                     containing_function_ranges=sum(r['kind']=='function' for r in receipt['selected_sources']),
                     dependencies=len(receipt['dependencies']),
                     covered_dependencies=sum(e['coverage']=='COVERED' for e in receipt['dependencies']),
                     unresolved_or_uncovered_dependencies=sum(e['coverage']!='COVERED' for e in receipt['dependencies']),
                     omissions=len(receipt['omissions']),context_status=receipt['status'],
                     semantic_completeness=False,deterministic=True,source_audit=checked,transport=delivery,
                     schema_fixture_valid=True,native_cli_transport_proven=False,model_consumption_proven=False,
                     ground_truth_loaded=False,ai_requests=0,seconds=round(time.monotonic()-started,3))
            p.save(output/case['id']/'bundle.json',first)
            p.save(output/case['id']/'receipt.json',row)
            rows.append(row)
            print(json.dumps({k:row[k] for k in ('case','status','prompt_bytes','pages','context_status','seconds')}),flush=True)
    finally:p.git=original
    result=dict(methodology=a.VERSION,freeze_sha256=freeze,manifest_sha256=p.digest(manifest.read_bytes()),
                cases=rows,ai_requests=0,ground_truth_loaded=False,all_passed=all(r['status']=='PASS' for r in rows))
    p.save(output/'dry-run.json',result)
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--repos',type=Path,required=True)
    parser.add_argument('--contexts-root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,default=legacy.SERIES/'manifest.json')
    args=parser.parse_args();run(args.manifest,p.load(args.repos),args.contexts_root,args.output)
