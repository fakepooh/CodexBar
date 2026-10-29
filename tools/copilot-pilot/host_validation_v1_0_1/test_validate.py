import copy
import json
import unittest

from repo_wide_readonly.snapshot import canonical, sha
from host_validation_v1_0_1.validate import attest, diff_paths


def build_prompt(task, receipt, diff, schema):
    return task + canonical(receipt['case']) + diff.decode()


class SourceChannelTests(unittest.TestCase):
    def setUp(self):
        self.diff = b'diff --git a/a.txt b/a.txt\nindex 111..222 100644\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n'
        self.case = dict(id='TEST', repository='example/project', pr=1, base='a'*40, head='b'*40)
        sources = [dict(path=p, blob_oid='c'*40, sha256='d'*64, line_count=3) for p in ['a.txt', 'caller.txt']]
        receipt = dict(complete=True, case=self.case, file_count=2, files=sources,
                       snapshot_sha256=sha(canonical(sources).encode()),
                       diff_sha256=sha(self.diff), diff_bytes=len(self.diff))
        response = dict(path='caller.txt', commit=self.case['head'], side='head',
                        blob_oid='c'*40, source_sha256='d'*64, lines=[dict(line=1,text='source')])
        text = canonical(response)
        self.data = dict(snapshot_receipt=receipt, base=self.case['base'], head=self.case['head'],
                         binding={'case':'TEST'}, session_id='fixture-session', snapshot_sha256=receipt['snapshot_sha256'],
                         diff_sha256=receipt['diff_sha256'], status='COMPLETED', initial_user_prompts=1,
                         os_isolation={str(i):True for i in range(9)},
                         tool_catalog={'tools':[{'name':n} for n in ['repo_view','repo_glob','repo_grep']]},
                         tool_audit=[dict(tool='view', arguments={'path':'caller.txt'}, ok=True,
                                          response=response,response_sha256=sha(text.encode()),response_bytes=len(text.encode()))],
                         events=[{'type':'tool.execution_complete','data':{'success':True,'result':{'content':text}}}])
        self.data['prompt_sha256'] = sha(build_prompt('fixed',receipt,self.diff,{}).encode())
        self.data['host_receipt'] = dict(prompt_sha256=self.data['prompt_sha256'], execution_status='COMPLETED', owned_containers_absent=True, binding={'case':'TEST'})
        self.output(['a.txt','caller.txt'])

    def output(self, paths):
        self.data['raw_output'] = canonical(dict(schema_version=1, base_sha=self.case['base'], head_sha=self.case['head'],
                                               summary='review',findings=[],coverage=dict(inspected_paths=paths,limitations=[])))

    def run_attest(self, diff=None, expected=None):
        raw=canonical(self.data).encode()
        return attest(raw,expected or sha(raw),self.case,self.diff if diff is None else diff,'fixed',{},'fixture-session',{'case':'TEST'},prompt_builder=build_prompt)

    def test_both_channels(self):
        self.assertEqual(self.run_attest()['diff_only_claims'],['a.txt'])

    def test_diff_only(self):
        self.output(['a.txt']); self.data['events']=[]
        self.assertEqual(self.run_attest()['status'],'PASS')

    def test_tool_only(self):
        self.output(['caller.txt']); self.assertEqual(self.run_attest()['status'],'PASS')

    def test_missing_tool_content(self):
        self.data['events']=[]
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_CONTEXT'): self.run_attest()

    def test_redacted_event_never_reconstructed(self):
        self.data['events'][0]['data']['result']['content']='******'; self.output(['a.txt'])
        r=self.run_attest(); self.assertEqual(r['uncorroborated_tool_rows_excluded'],1)
        self.assertEqual(r['corroborated_tool_paths'],[])

    def test_modified_private_evidence(self):
        with self.assertRaisesRegex(ValueError,'IMMUTABLE_PRIVATE'): self.run_attest(expected='0'*64)

    def test_changed_diff(self):
        with self.assertRaisesRegex(ValueError,'DIFF_INTEGRITY'): self.run_attest(self.diff.replace(b'new',b'bad'))

    def test_truncated_diff(self):
        with self.assertRaisesRegex(ValueError,'DIFF_INTEGRITY'): self.run_attest(self.diff[:-2])

    def test_contradictory_prompt(self):
        self.data['prompt_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'INITIAL_INPUT'): self.run_attest()

    def test_bad_head(self):
        self.data['head']='f'*40
        with self.assertRaisesRegex(ValueError,'HISTORICAL_IDENTITY'): self.run_attest()

    def test_bad_inventory(self):
        self.data['snapshot_receipt']['files'][0]['sha256']='e'*64
        with self.assertRaisesRegex(ValueError,'INVENTORY_HASH'): self.run_attest()

    def test_bad_tool_identity(self):
        row=self.data['tool_audit'][0]; row['response']['commit']='f'*40
        text=canonical(row['response']); row['response_sha256']=sha(text.encode()); row['response_bytes']=len(text.encode())
        self.data['events'][0]['data']['result']['content']=text
        with self.assertRaisesRegex(ValueError,'TOOL_SOURCE_IDENTITY'): self.run_attest()

    def test_metadata_only_not_content(self):
        self.assertEqual(diff_paths(b'diff --git a/a.txt b/a.txt\nold mode 100644\nnew mode 100755\n'),set())

    def test_incomplete_hunk(self):
        with self.assertRaisesRegex(ValueError,'HUNK_INCOMPLETE'): diff_paths(self.diff[:-5])

    def test_path_escape(self):
        with self.assertRaises(ValueError): diff_paths(self.diff.replace(b'a.txt',b'../a.txt'))

    def test_timeout_fails_closed(self):
        self.data['status']='TIMEOUT_NO_RETRY'
        with self.assertRaisesRegex(ValueError,'INCOMPLETE_EXECUTION'): self.run_attest()

    def test_receipt_contains_no_source_or_prompt(self):
        text=canonical(self.run_attest()); self.assertNotIn('fixed',text); self.assertNotIn('"source"',text)

    def test_no_mutation(self):
        before=copy.deepcopy(self.data); self.run_attest(); self.assertEqual(before,self.data)


    def test_wrong_session(self):
        self.data['session_id']='replayed'
        with self.assertRaisesRegex(ValueError,'SESSION_EXECUTION_BINDING'): self.run_attest()

    def test_wrong_run_binding(self):
        self.data['binding']['run_id']=99
        with self.assertRaisesRegex(ValueError,'SESSION_EXECUTION_BINDING'): self.run_attest()

    def test_duplicate_output_keys(self):
        self.data['raw_output']='{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'): self.run_attest()

    def test_broken_json(self):
        self.data['raw_output']='{'
        with self.assertRaisesRegex(ValueError,'OUTPUT_NOT_SINGLE_JSON'): self.run_attest()

    def test_wrong_schema(self):
        self.data['raw_output']='{}'
        with self.assertRaisesRegex(ValueError,'OUTPUT_REQUIRED'): self.run_attest()

    def test_invented_path(self):
        self.output(['invented.txt'])
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_CONTEXT'): self.run_attest()

    def test_invalid_finding_range(self):
        v=json.loads(self.data['raw_output']); v['findings']=[dict(id='F1',priority='P2',title='fixture',path='a.txt',side='head',line_start=1,line_end=999,trigger='fixture',impact='fixture',evidence='fixture',confidence='high')];self.data['raw_output']=canonical(v)
        with self.assertRaisesRegex(ValueError,'UNVERIFIED_SOURCE_RANGE'): self.run_attest()

    def test_unverified_base_range(self):
        v=json.loads(self.data['raw_output']);v['findings']=[dict(id='F1',priority='P2',title='fixture',path='a.txt',side='base',line_start=1,line_end=1,trigger='fixture',impact='fixture',evidence='fixture',confidence='high')];self.data['raw_output']=canonical(v)
        with self.assertRaisesRegex(ValueError,'UNVERIFIED_SOURCE_RANGE'): self.run_attest()


if __name__=='__main__': unittest.main()
