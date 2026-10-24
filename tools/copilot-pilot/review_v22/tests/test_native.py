import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from test_contracts import fixture
from review_v22 import adapter as a, native


class NativeVerifierTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.context=Path(t.name)/'c';self.case=fixture(self.context)
        self.b=a.build(self.context,self.case);self.key=b'x'*32
        self.events=[dict(type='v2.transport_prepared',data=dict(prompt_sha256=self.b['prompt_sha256'],
            prompt_bytes=self.b['prompt_bytes'],mock=True,home_empty=True,requested_selection='offline-stub-only',settings_model=None,environment_model=None)),
            dict(type='user.message',data=dict(content='security-redacted',transformedContent='wrapped-redacted')),
            dict(type='model.call_start'),dict(type='attestation.receiver'),
            dict(type='v2.mock_endpoint',data=dict(requests=1,real_model_requests=0)),
            dict(type='result',exitCode=0),
            dict(type='v2.transport_finished',data=dict(cli_exit_code=0,timed_out=False,mock=True,automatic_retry=False))]
        self.wire=dict(version='source-delivery-attestation-v1.0.0',nonce='n',freeze_sha256='f'*64,
            request_number=1,method='POST',path='/v1/chat/completions',authenticated_header_present=False,
            wire_bytes=self.b['prompt_bytes']+1000,wire_sha256='d'*64,complete=True,
            prompt_sha256=self.b['prompt_sha256'],prompt_bytes=self.b['prompt_bytes'],pages=self.b['expected_pages'],
            canonical_telemetry_sha256=a.digest(b'security-redacted'),transformed_telemetry_sha256=a.digest(b'wrapped-redacted'),
            native_filter_sha256='e'*64,tools=['view'])

    def validate(self, wire=None, events=None):
        wire=self.wire if wire is None else wire;events=copy.deepcopy(self.events if events is None else events)
        raw=json.dumps(wire).encode();envelope=dict(payload=base64.b64encode(raw).decode(),mac=hmac.new(self.key,raw,hashlib.sha256).hexdigest())
        next(e for e in events if e['type']=='attestation.receiver')['data']=envelope
        return native.validate(self.b,self.context,events,self.key,'n','f'*64)

    def test_independent_native_redaction_allowed_with_exact_receiver(self):
        r=self.validate();self.assertEqual(r['status'],'PASS');self.assertFalse(r['model_consumption_proven'])
    def test_missing_page_rejected_even_if_telemetry_matches(self):
        wire=copy.deepcopy(self.wire);wire['pages'].pop()
        with self.assertRaises(ValueError):self.validate(wire)
    def test_redacted_telemetry_mutation_fails(self):
        events=copy.deepcopy(self.events);events[1]['data']['content']='changed'
        with self.assertRaises(ValueError):self.validate(events=events)
    def test_incomplete_or_timeout_fails(self):
        for key,value in [('timed_out',True),('cli_exit_code',1)]:
            events=copy.deepcopy(self.events);events[-1]['data'][key]=value
            with self.assertRaises(ValueError):self.validate(events=events)
    def test_additional_turn_or_session_rejected(self):
        with self.assertRaises(ValueError):self.validate(events=self.events+[self.events[1]])
    def test_tools_or_delegation_rejected(self):
        for kind in ['tool.execution_start','subagent.started','session.agent_selected']:
            with self.assertRaises(ValueError):self.validate(events=self.events+[dict(type=kind)])
    def test_wrong_frozen_identity_rejected(self):
        wire=dict(self.wire,freeze_sha256='a'*64)
        with self.assertRaises(ValueError):self.validate(wire)

if __name__=='__main__':unittest.main()
