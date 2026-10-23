"""Sessionless CLI authentication probe. Never creates a session or sends a prompt."""
import argparse
import contextlib
import json
import os
import re
from pathlib import Path
import select
import struct
import subprocess
import time
import uuid

import keychain_helper
import offline_preflight
import pilot
import runtime_setup

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / 'evidence/cp01-auth-diagnosis-2026-10-19'
AUTH_ARGS = [*pilot.FLAGS, '--headless', '--stdio', '--log-level=error',
             '--auth-token-env', 'COPILOT_GITHUB_TOKEN', '--no-auto-login']
LOGIN_ARGS = ['--log-level=error', 'login', '--host', 'https://github.com']

# Trusted transport only: read an exact binary credential frame, then replace
# this process with the pinned CLI. Docker's configured environment has no token.
# No secret is passed as an argument, written to disk, or echoed to stdout.
BOOTSTRAP = r"""
const fs = require('fs');
function readExact(n) {
  const b=Buffer.alloc(n); let at=0;
  while(at<n) { const k=fs.readSync(0,b,at,n-at,null); if(!k) process.exit(70); at+=k; }
  return b;
}
const header=readExact(4), n=header.readUInt32BE(); header.fill(0);
if(n<12 || n>1024 || typeof process.execve!=='function') process.exit(71);
const token=readExact(n);
if(!/^github_pat_[A-Za-z0-9_]+$/.test(token.toString('ascii'))) process.exit(72);
const env={...process.env,COPILOT_GITHUB_TOKEN:token.toString('ascii')}; token.fill(0);
try { process.execve('/usr/local/bin/copilot',['copilot',...process.argv.slice(1)],env); }
catch { process.exit(73); }
"""


class ProbeBlocked(Exception):
    pass


def error_metadata(error):
    # Classify in memory. Never serialize the raw error, which may contain data
    # from a remote response or credential-handling code.
    message = str(error.get('message', '')).lower()
    categories = [name for name, pattern in (
        ('unauthenticated', r'not authenticated|unauthenticated|authentication required'),
        ('bad_credentials', r'bad credentials|invalid token|expired token'),
        ('permission_denied', r'forbidden|permission denied|insufficient scope|not accessible by|does not have.*permission'),
        ('tls', r'certificate|ssl|tls'),
        ('dns', r'enotfound|eai_again|dns|could not resolve'),
        ('network', r'fetch failed|econnrefused|network|connection|timed out|error sending request|unexpected eof'),
        ('missing_auth', r'no auth|no token|authentication information'),
        ('cli_argument', r'unknown option|unrecognized.*option|unexpected argument|unexpected option'),
        ('authentication_validation', r'failed to authenticate|authentication failed|token validation|login failed'),
        ('policy', r'organization.*policy|sign-in policy|policy-undetermined'),
        ('credential_storage', r'keychain|plaintext|credential.*stor'),
        ('endpoint_rejection', r'http|status code|unauthorized|request failed'),
        ('http_401', r'\b401\b'), ('http_403', r'\b403\b'),
    ) if re.search(pattern, message)]
    statuses = sorted({int(x) for x in re.findall(r'\b(400|401|403|404|406|407|408|409|422|429|500|502|503|504)\b', message)})
    endpoints = [name for name in ('api.github.com', 'api.githubcopilot.com',
                                  'copilot-proxy.githubusercontent.com') if name in message]
    return {'rpc_error_code': error.get('code'), 'error_categories':categories or ['unclassified'],
            'http_status_candidates':statuses,'known_endpoints':endpoints}


def launch_command(image, endpoint, name, args, case_id='CP-01'):
    if args != AUTH_ARGS:
        raise ProbeBlocked('Only the sessionless server command is permitted')
    return transport_command(image, endpoint, name, args, case_id)


def transport_command(image, endpoint, name, args, case_id='CP-01'):
    if args not in (AUTH_ARGS, LOGIN_ARGS):
        raise ProbeBlocked('Only fixed non-AI authentication commands are permitted')
    context = runtime_setup.context_mount(case_id)
    cmd = offline_preflight.command(image, context, endpoint,
                                   ['-e', BOOTSTRAP, '--', *args], entrypoint='node', name=name)
    cmd[cmd.index('--network=none')] = '--network=bridge'
    cmd.insert(cmd.index('run') + 1, '--interactive')
    cmd.insert(cmd.index('run') + 1, '--log-driver=none')
    cmd.insert(cmd.index('run') + 1, '--ulimit=core=0:0')
    return cmd


class Rpc:
    def __init__(self, process):
        self.process, self.buffer, self.ident = process, bytearray(), 0

    def request(self, method):
        if method not in ('connect', 'ping', 'auth.getStatus', 'account.getQuota'):
            raise ProbeBlocked('Session/model methods are prohibited')
        self.ident += 1
        params = {'supportedTaskKinds': []} if method == 'connect' else {}
        body = json.dumps({'jsonrpc': '2.0', 'id': self.ident,
                           'method': method, 'params': params}).encode()
        self.process.stdin.write(b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        self.process.stdin.flush()
        end = time.monotonic() + 45
        while time.monotonic() < end:
            while b'\r\n\r\n' in self.buffer:
                header, data = self.buffer.split(b'\r\n\r\n', 1)
                try:
                    length = int(next(x.split(b':', 1)[1] for x in header.split(b'\r\n')
                                      if x.lower().startswith(b'content-length:')))
                except (StopIteration, ValueError):
                    raise ProbeBlocked('Invalid server framing') from None
                if not 0 <= length <= 1024*1024:
                    raise ProbeBlocked('Server frame exceeds metadata limit')
                if len(data) < length:
                    break
                message = json.loads(data[:length])
                self.buffer = bytearray(data[length:])
                if message.get('id') == self.ident and 'method' not in message:
                    if 'error' in message:
                        return error_metadata(message['error'])
                    return message.get('result', {})
                if 'method' in message and 'id' in message:
                    raise ProbeBlocked('Unexpected server request; no permission granted')
            ready, _, _ = select.select([self.process.stdout], [], [], max(0, end-time.monotonic()))
            if not ready:
                break
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise ProbeBlocked('CLI server exited before metadata response')
            self.buffer.extend(chunk)
            if len(self.buffer) > 2*1024*1024:
                raise ProbeBlocked('Server metadata buffer limit exceeded')
        raise ProbeBlocked('CLI metadata request timed out')


def auth_metadata(data):
    result = {}
    for key in ('isAuthenticated', 'authType', 'host', 'login', 'activeLogin',
                'activeHost', 'copilotPlan', 'accountCount', 'statusMessage', 'rpc_error_code'):
        value = data.get(key)
        if isinstance(value, (str, bool, int)):
            result[key] = pilot.scrub(value) if isinstance(value, str) else value
    return result


def quota_metadata(data):
    if 'rpc_error_code' in data:
        return {key:data[key] for key in ('rpc_error_code','error_categories') if key in data}
    result = {}
    for name, values in data.get('quotaSnapshots', {}).items():
        if name not in ('chat', 'completions', 'premium_interactions', 'ai_credits') or not isinstance(values, dict):
            continue
        result[name] = {k:v for k,v in values.items() if k in (
            'isUnlimitedEntitlement', 'entitlementRequests', 'usedRequests',
            'usageAllowedWithExhaustedQuota', 'remainingPercentage', 'overage',
            'overageAllowedWithExhaustedQuota', 'resetDate') and
            isinstance(v, (bool, int, float, str))}
    return {'quotaSnapshots':result,
            'unit_warning':'Request counters and percentages are not AI Credits.'}


def probe(interactive=False, login_diagnostic=False, evidence_dir=None, case_id='CP-01', credential=None):
    evidence = Path(evidence_dir) if evidence_dir is not None else EVIDENCE
    context_path = runtime_setup.context_mount(case_id)
    case = next(c for c in pilot.cases() if c['id'] == case_id)
    context = pilot.check_context(context_path, case)
    state, env = runtime_setup.environment()
    image = pilot.load(evidence / 'runtime-image-with-ca.json')
    offline = pilot.load(evidence / 'offline-runtime-preflight-with-ca.json')
    vm = pilot.load(evidence / 'vm-isolation-runtime.json')
    if offline['runtime'] != 'passed' or not all(vm['checks'].values()):
        raise ProbeBlocked('Current offline isolation evidence must pass first')
    if offline['context_sha256'] != context['context_sha256']:
        raise ProbeBlocked('Historical context changed after isolation preflight')
    endpoint = 'unix://' + str(Path(state['root']) / 'colima/copilot-pilot/docker.sock')
    if endpoint != image['docker_host'] or offline['image'] != image['image']:
        raise ProbeBlocked('Private runtime receipt mismatch')
    name = 'cp01-auth-' + uuid.uuid4().hex
    args = LOGIN_ARGS if login_diagnostic else AUTH_ARGS
    command = transport_command(image['image'], endpoint, name, args, case_id)
    report = {'checked_at':pilot.now(),'ai_invocations':0,'sessions_created':0,
              'token_transport':'private stdin frame; execve into isolated CLI',
              'token_in_docker_environment':False,'cli_version':'1.0.98','case':case_id}
    proc = None
    try:
        # The Docker client sees only the encrypted VM transport and stdin bytes;
        # it never receives a token in its own environment, argv or saved config.
        with (contextlib.nullcontext(credential) if credential is not None else
              keychain_helper.pat(user_interaction=interactive)) as secret:
            proc = subprocess.Popen(command,
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if login_diagnostic else subprocess.DEVNULL, bufsize=0)
            proc.stdin.write(struct.pack('>I',len(secret._buffer)))
            proc.stdin.write(secret._buffer)
            proc.stdin.flush()
        if login_diagnostic:
            stdout, stderr = proc.communicate(timeout=60)
            text = (stdout + stderr).decode(errors='replace')
            report['login_exit_code'] = proc.returncode
            report['signed_in_as_expected_user'] = 'Signed in successfully as fakepooh' in text
            report['validated_but_persistence_declined'] = 'Login succeeded, but the token was not saved.' in text
            report['diagnostic'] = error_metadata({'code':proc.returncode,'message':text})
            report['status'] = 'passed' if report['signed_in_as_expected_user'] else 'blocked'
            del stdout, stderr, text
        else:
            rpc = Rpc(proc)
            connected = rpc.request('connect')
            if 'rpc_error_code' in connected:
                raise ProbeBlocked('Required sessionless connect handshake failed')
            report['connect_protocol_version'] = connected.get('protocolVersion')
            ping = rpc.request('ping')
            report['protocol_version'] = ping.get('protocolVersion')
            report['auth'] = auth_metadata(rpc.request('auth.getStatus'))
            report['quota'] = quota_metadata(rpc.request('account.getQuota'))
            report['status'] = 'passed' if report['auth'].get('isAuthenticated') is True else 'blocked'
    finally:
        if proc and not proc.stdin.closed:
            proc.stdin.close()
        docker = str(ROOT / '.cache/components/bin/docker')
        subprocess.run([docker,'--host='+endpoint,'rm','-f',name],env=env,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        if proc:
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=10)
        absent = subprocess.run([docker,'--host='+endpoint,'ps','-aq','--filter=name=^/'+name+'$'],
            env=env,capture_output=True,timeout=30)
        if absent.returncode or absent.stdout.strip():
            raise ProbeBlocked('Credential container cleanup not confirmed')
        report['container_removed'] = True
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interactive',action='store_true')
    parser.add_argument('--login-diagnostic',action='store_true')
    parser.add_argument('--case',default='CP-01')
    parser.add_argument('--evidence-dir',type=Path)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists(): parser.error('Preserve previous evidence')
    try:
        result=probe(args.interactive,args.login_diagnostic,args.evidence_dir,args.case)
    except (ProbeBlocked,keychain_helper.KeychainBlocked) as exc:
        result={'status':'blocked','reason':str(exc),'ai_invocations':0,'sessions_created':0}
    except Exception:
        result={'status':'blocked','reason':'Isolated authentication probe failed safely',
                'ai_invocations':0,'sessions_created':0}
    pilot.save(args.out,result)
    print(json.dumps(result))
    raise SystemExit(0 if result['status']=='passed' else 2)
