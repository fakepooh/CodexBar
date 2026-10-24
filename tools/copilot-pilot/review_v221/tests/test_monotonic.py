import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import pilot as p
from review_v221 import adapter as a,audit,transport
from review_v22.context import POLICY


def fixture(root):
    case=dict(id='SYN-01',repository='example/fixture',pr=1,base='a'*40,head='b'*40)
    root.mkdir();(root/'blobs').mkdir();trees={}
    for side,value in [('base',1),('head',2)]:
        rows=[]
        for name,text in {'engine.py':f'def calculate():\n    return {value}\n','caller.py':'def entry():\n    return calculate()\n'}.items():
            raw=text.encode();oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            p.save(root/'blobs'/(oid+'.json'),dict(git_oid=oid,encoding='utf-8',content=text))
            rows.append(dict(path=name,oid=oid,type='blob',mode='100644'))
        trees[side]=rows
    p.save(root/'index.json',dict(base=case['base'],head=case['head'],trees=trees))
    (root/'diff.txt').write_text('diff --git a/engine.py b/engine.py\n--- a/engine.py\n+++ b/engine.py\n@@ -1,2 +1,2 @@\n def calculate():\n-    return 1\n+    return 2\n')
    hashes={str(x.relative_to(root)):p.digest(x.read_bytes()) for x in root.rglob('*') if x.is_file()}
    p.save(root/'context.json',dict(case=case,files=hashes,context_sha256=p.digest(json.dumps(hashes,sort_keys=True).encode())))
    return case


class MonotonicTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.context=Path(temp.name)/'context';self.case=fixture(self.context)
    def test_retention_and_independent_audit(self):
        b=a.build(self.context,self.case)
        self.assertEqual(audit.verify_payload(b,self.context,self.case)['status'],'PASS')
        self.assertTrue(b['coverage_receipt']['baseline_retention']['all_previous_source_lines_retained'])
    def test_deterministic(self):self.assertEqual(a.build(self.context,self.case),a.build(self.context,self.case))
    def test_no_duplicate_source_lines(self):
        b=a.build(self.context,self.case);body=json.loads(b['prompt'].split('HISTORICAL_EVIDENCE_JSON\n')[1]);seen=set()
        for page in body['source_pages']:
            for line in page['content'].splitlines():
                r=json.loads(line);key=(page['side'],page['path'],r['line'],r['part'])
                self.assertNotIn(key,seen);seen.add(key)
    def test_retention_budget_failure_blocks(self):
        with patch.dict(POLICY,max_pages=0):
            with self.assertRaises(ValueError):a.build(self.context,self.case)
    def test_actual_transport_and_bad_mac(self):
        b=a.build(self.context,self.case);key=b'x'*32
        envelope=transport.receive(transport.frame(b),b,key,'n')
        self.assertEqual(transport.validate(envelope,b,self.context,self.case,key,'n')['status'],'PASS')
        with self.assertRaises(ValueError):transport.validate(envelope,b,self.context,self.case,b'y'*32,'n')
    def test_input_prompt_is_unchanged_task(self):
        b=a.build(self.context,self.case);old=a.prior.build(self.context,self.case)
        self.assertEqual(b['prompt'].split('HISTORICAL_EVIDENCE_JSON\n')[0],old['prompt'].split('HISTORICAL_EVIDENCE_JSON\n')[0])
    def test_old_frozen_sources_not_modified(self):a.base.check_freeze();a.prior.check_freeze()
    def test_no_known_case_tuning(self):
        for name in ['adapter.py','audit.py']:
            text=(a.ROOT/name).read_text()
            for bad in ['PUB-','CodexBar','Capmetry','defects.json','ground-truth']:
                self.assertNotIn(bad,text)

if __name__=='__main__':unittest.main()
