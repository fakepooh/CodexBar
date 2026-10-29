// Fixed production container entry. Control/credential come only through stdin.
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { spawn } from 'node:child_process';
import { readFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { writeSync, writeFileSync, renameSync } from 'node:fs';
import http from 'node:http';
import { networkInterfaces } from 'node:os';
import { randomBytes } from 'node:crypto';
import { BrokerRpc } from './sdk-tools.mjs';
import { emptyClientOptions } from './client-options.mjs';
import { prepareReview, requireOsProof, promptTransport } from './review-session.mjs';
import { NAMES } from './sdk-tools.mjs';
import { completionFixture } from './mock-completions.mjs';

let client, prepared, rpc, broker, token = '', unsub, mockServer, localNonce = '';
const fixtureMode = process.argv.length === 3 && process.argv[2] === '--offline-fixture';
const started = performance.now(), events = [];
const evidence = { status: 'BLOCKED', inference_dispatched: false, initial_user_prompts: 0,
  requested_model: 'auto', cli_version: null, events, model_consumption_proven: false };
function serialize() {
  let text = JSON.stringify(evidence);
  for (const secret of [token, localNonce].filter(Boolean).flatMap(s => [s, Buffer.from(s).toString('base64')]))
    text = text.split(secret).join('[CREDENTIAL_REDACTED]');
  return text;
}
function checkpoint() {
  // Host-owned private evidence, outside the source tree and outside broker access.
  evidence.tool_audit = rpc?.audit || [];
  writeFileSync('/tmp/review-checkpoint.tmp', serialize(), { mode: 0o600 });
  renameSync('/tmp/review-checkpoint.tmp', '/tmp/review-checkpoint.json');
}
const deadline = setTimeout(() => {
  evidence.status = 'TIMEOUT_NO_RETRY'; evidence.tool_audit = rpc?.audit || [];
  evidence.duration_seconds = (performance.now() - started) / 1000;
  if (broker) broker.kill('SIGKILL'); client?.cliProcess?.kill('SIGKILL');
  writeSync(1, serialize() + '\n'); process.exit(2);
}, 1260000);
try {
  if (Object.keys(process.env).some(k => /TOKEN|SECRET|PASSWORD|API_KEY/i.test(k))) throw Error('CONTAINER_CREDENTIAL_ENV');
  const chunks = []; let bytes = 0;
  for await (const b of process.stdin) {
    bytes += b.length; if (bytes > 1048576) throw Error('CONTROL_LIMIT'); chunks.push(b);
  }
  const control = JSON.parse(Buffer.concat(chunks).toString()); token = control.token;
  const hash = s => createHash('sha256').update(s).digest('hex');
  if (control.version !== 1 || !token || typeof token !== 'string' || !control.prompt
      || hash(control.prompt) !== control.prompt_sha256 || control.prompt.includes(token)
      || Buffer.byteLength(control.prompt) > 262144
      || control.model !== (fixtureMode ? 'offline-tool-stub' : 'auto')
      || (!fixtureMode && process.argv.length !== 2)) throw Error('CONTROL_BINDING');
  const snapshot = JSON.parse(await readFile('/metadata/snapshot.json'));
  if (fixtureMode) {
    if (token !== 'OFFLINE_NO_REAL_CREDENTIAL' || control.model !== 'offline-tool-stub'
        || snapshot.fixture_only !== true || control.binding?.case !== 'OFFLINE-FIXTURE'
        || !Object.values(networkInterfaces()).flat().every(n => n.internal)) throw Error('OFFLINE_FIXTURE_BOUNDARY');
    evidence.fixture_only = true; evidence.requested_model = 'offline-tool-stub'; evidence.real_model_requests = 0;
  } else if (snapshot.complete !== true || snapshot.case.id !== control.binding.case
      || snapshot.case.base !== control.base || snapshot.case.head !== control.head
      || snapshot.snapshot_sha256 !== control.snapshot_sha256 || snapshot.diff_sha256 !== control.diff_sha256)
    throw Error('HISTORICAL_IDENTITY');
  evidence.binding = control.binding; evidence.base = control.base; evidence.head = control.head;
  evidence.snapshot_sha256 = control.snapshot_sha256; evidence.diff_sha256 = control.diff_sha256;
  evidence.prompt_sha256 = control.prompt_sha256; evidence.freeze_sha256 = control.freeze_sha256;
  checkpoint();
  await mkdir('/tmp/home', { recursive: true });
  broker = spawn('python3', ['-m', 'repo_wide_readonly.broker_stdio', '/snapshot', '/metadata/snapshot.json'],
    { shell: false, env: { PATH: process.env.PATH, PYTHONPATH: '/app', PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['pipe', 'pipe', 'pipe'] });
  broker.stderr.on('data', () => {}); rpc = new BrokerRpc(broker);
  const proof = await rpc.call('__probe__');
  requireOsProof(proof);
  evidence.os_isolation = proof.result;
  let provider, fixtureRequests = 0, fixtureReceiverFailed = false, fixturePayloadBytes = 0;
  const runtimeEnv = { PATH: process.env.PATH, HOME: '/tmp/home', COPILOT_HOME: '/tmp/home/.copilot',
    GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'fakepooh/CodexBar' };
  if (fixtureMode) {
    localNonce = randomBytes(32).toString('hex');
    evidence.offline_received_payloads = [];
    const planned = [['repo_view', { path: 'source/example.txt', start_line: 2, end_line: 3 }],
      ['repo_view', { path: 'source/large.txt', start_line: 1, end_line: 200 }],
      ['repo_grep', { query: 'OFFLINE_FIXTURE_CONTENT' }], ['repo_glob', { pattern: '*' }],
      ['repo_view', { path: '/proc/self/environ' }]];
    mockServer = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/v1/models') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ object: 'list', data: [{ id: 'offline-tool-stub', object: 'model' }] })); return;
      }
      if (req.method !== 'POST' || req.url !== '/v1/chat/completions'
          || req.headers.authorization !== 'Bearer ' + localNonce) { res.writeHead(403); res.end(); return; }
      const chunks = []; let size = 0;
      req.on('data', b => { size += b.length; if (size > 4194304) req.destroy(); else chunks.push(b); });
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString()); fixtureRequests++;
          const serialized = JSON.stringify(body); fixturePayloadBytes += Buffer.byteLength(serialized);
          if (serialized.includes(localNonce) || fixturePayloadBytes > 8388608) throw Error('FIXTURE_PAYLOAD_LIMIT_OR_CREDENTIAL');
          evidence.offline_received_payloads.push(body);
          const names = (body.tools || []).map(t => t.function?.name || t.name).sort();
          if (JSON.stringify(names) !== JSON.stringify([...NAMES].sort())) throw Error('CATALOG');
          const users = (body.messages || []).filter(m => m.role === 'user').flatMap(m => typeof m.content === 'string'
            ? [m.content] : (m.content || []).filter(x => x.type === 'text').map(x => x.text));
          const canonicalDeliveries = users.map(text => promptTransport(text, control.prompt)).filter(Boolean);
          if (canonicalDeliveries.length !== 1) throw Error('INITIAL_PROMPT_TRANSPORT');
          evidence.offline_prompt_delivery = canonicalDeliveries[0];
          const received = (body.messages || []).filter(m => m.role === 'tool').flatMap(m => typeof m.content === 'string'
            ? [m.content] : (m.content || []).filter(x => x.type === 'text').map(x => x.text));
          if (JSON.stringify(received) !== JSON.stringify(rpc.audit.map(x => JSON.stringify(x.response)))
              || fixtureRequests > 6) throw Error('SOURCE_TRANSPORT');
          const response = completionFixture(planned[fixtureRequests - 1], fixtureRequests, body.stream);
          res.writeHead(200, { 'Content-Type': response.contentType }); res.end(response.body);
        } catch { fixtureReceiverFailed = true; res.writeHead(400); res.end(); }
      });
    });
    await new Promise(resolve => mockServer.listen(0, '127.0.0.1', resolve));
    const url = 'http://127.0.0.1:' + mockServer.address().port + '/v1';
    Object.assign(runtimeEnv, { COPILOT_OFFLINE: 'true', COPILOT_PROVIDER_TYPE: 'openai',
      COPILOT_PROVIDER_BASE_URL: url, COPILOT_PROVIDER_WIRE_API: 'completions',
      COPILOT_PROVIDER_MODEL_ID: 'offline-tool-stub', COPILOT_PROVIDER_WIRE_MODEL: 'offline-tool-stub',
      COPILOT_PROVIDER_MAX_PROMPT_TOKENS: '131072', COPILOT_PROVIDER_MAX_OUTPUT_TOKENS: '4096' });
    provider = { type: 'openai', baseUrl: url, wireApi: 'completions', apiKey: localNonce };
  } else runtimeEnv.GITHUB_TOKEN = token;
  client = new CopilotClient({ ...emptyClientOptions('/tmp/home'), ...(fixtureMode ? {} : { gitHubToken: token }), logLevel: 'error',
    connection: RuntimeConnection.forStdio({ args: ['--no-remote', '--no-remote-export'],
      env: runtimeEnv }) });
  await client.start(); evidence.cli_version = (await client.getStatus()).version;
  if (evidence.cli_version !== '1.0.98' || (!fixtureMode && (await client.getAuthStatus()).isAuthenticated !== true))
    throw Error('PIN_OR_AUTH');
  prepared = await prepareReview(client, rpc, { model: fixtureMode ? 'offline-tool-stub' : 'auto', home: '/tmp/home', provider });
  evidence.session_id = prepared.session.sessionId; evidence.tool_catalog = prepared.catalog;
  evidence.pre_dispatch_metadata = { sessionLimits: { maxAiCredits: prepared.metadata.sessionLimits.maxAiCredits } };
  let nextCheckpoint = 0;
  unsub = prepared.session.on(e => {
    events.push(e);
    if (performance.now() >= nextCheckpoint) { checkpoint(); nextCheckpoint = performance.now() + 1000; }
  });
  evidence.inference_dispatched = !fixtureMode; evidence.initial_user_prompts = 1;
  checkpoint();
  const result = await prepared.sendOnce(control.prompt, 1200000);
  evidence.raw_output = result?.data?.content ?? null;
  if (fixtureMode) {
    if (fixtureReceiverFailed || fixtureRequests !== 6 || rpc.audit.length !== 5
        || rpc.audit.slice(0, 4).some(x => !x.ok) || rpc.audit[4].ok
        || rpc.audit[1].response_bytes <= 51200 || !rpc.audit[1].response.partial
        || evidence.raw_output !== 'OFFLINE_CALLBACK_PROOF_COMPLETE') throw Error('ENTRY_TRANSPORT_INCOMPLETE');
    evidence.offline_entry_transport = { status: 'PASS', mock_requests: fixtureRequests,
      callback_count: rpc.audit.length, initial_prompt_sha256: control.prompt_sha256,
      prompt_delivery: evidence.offline_prompt_delivery,
      exact_source_order_and_content: true, host_escape_denied: true };
  }
  checkpoint();
  try { evidence.full_session_events = await prepared.session.getMessages(); }
  catch { evidence.full_session_history_unavailable = true; }
  evidence.status = typeof evidence.raw_output === 'string' ? 'COMPLETED' : 'INVALID_NO_FINAL_TEXT';
} catch (error) {
  // Only class labels, never raw exception/authentication responses.
  const allowed = ['CONTROL_LIMIT', 'CONTROL_BINDING', 'CONTAINER_CREDENTIAL_ENV', 'HISTORICAL_IDENTITY',
    'OS_ISOLATION', 'PIN_OR_AUTH', 'SESSION_LIMIT_UNPROVED', 'PRE_DISPATCH_TOOL_CATALOG'];
  evidence.reason = allowed.includes(error?.message) ? error.message : 'RUNTIME_OR_REVIEW_FAILED_NO_RETRY';
} finally {
  if (unsub) unsub();
  if (rpc) evidence.tool_audit = rpc.audit;
  if (prepared) try { await prepared.session.destroy(); } catch { evidence.session_cleanup_uncertain = true; }
  if (client) try { await client.stop(); } catch { evidence.cli_cleanup_uncertain = true; }
  if (rpc) rpc.stop();
  if (broker && broker.exitCode === null) broker.kill('SIGTERM');
  if (mockServer) { mockServer.closeAllConnections?.(); await new Promise(resolve => mockServer.close(resolve)); }
  clearTimeout(deadline); evidence.duration_seconds = (performance.now() - started) / 1000;
  // stdout is captured privately by the trusted parent, NEVER printed in Actions.
  console.log(serialize()); process.exitCode = evidence.status === 'COMPLETED' ? 0 : 2;
}
