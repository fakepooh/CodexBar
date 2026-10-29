// Run ONLY in the credential-free network-none GitHub-hosted probe container.
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { spawn } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { BrokerRpc, NAMES, digest } from './sdk-tools.mjs';
import { emptyClientOptions, initializationOnly } from './client-options.mjs';
import { completionFixture } from './mock-completions.mjs';
import { prepareReview, requireOsProof } from './review-session.mjs';

let client, session, rpc, server, broker;
let stage = 'os_boundary';
const privateTransport = [];
let privateEntryDiagnostic;
let privateTransportBytes = 0;
const report = { status: 'BLOCKED', real_model_requests: 0, model_consumption_proven: false,
  native_cli_version: null, mock_requests: 0, selected_tools: null };
// Ephemeral local receiver authentication, not a GitHub/API credential.
const receiverNonce = randomBytes(32).toString('hex');
const planned = [ ['repo_view', { path: 'source/example.txt', start_line: 2, end_line: 3 }],
  ['repo_view', { path: 'source/large.txt', start_line: 1, end_line: 200 }],
  ['repo_grep', { query: 'OFFLINE_FIXTURE_CONTENT' }], ['repo_glob', { pattern: '*' }],
  ['repo_view', { path: '/proc/self/environ' }] ];
const deadline = setTimeout(() => {
  if (broker) broker.kill('SIGKILL');
  console.log(JSON.stringify({ ...report, reason: 'NATIVE_OFFLINE_DEADLINE' })); process.exit(2);
}, 120000);
try {
  if (!Object.values(networkInterfaces()).flat().every(n => n.internal)) throw Error('NETWORK_NOT_NONE');
  if (Object.keys(process.env).some(k => /TOKEN|SECRET|PASSWORD|API_KEY/i.test(k))) throw Error('CREDENTIAL_ENV');
  await mkdir('/tmp/home', { recursive: true });
  broker = spawn('python3', ['-m', 'repo_wide_readonly.broker_stdio', '/snapshot', '/metadata/snapshot.json'],
    { shell: false, env: { PATH: process.env.PATH, PYTHONPATH: '/app', PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['pipe', 'pipe', 'pipe'] });
  broker.stderr.on('data', () => {}); rpc = new BrokerRpc(broker);
  const proof = await rpc.call('__probe__');
  requireOsProof(proof);
  report.os_isolation = proof.result;
  stage = 'local_receiver';
  server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/v1/models') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ object: 'list', data: [{ id: 'offline-tool-stub', object: 'model', owned_by: 'local-fixture' }] })); return;
    }
    if (req.method !== 'POST' || req.url !== '/v1/chat/completions') { res.writeHead(404); res.end(); return; }
    if (req.headers.authorization !== 'Bearer ' + receiverNonce) {
      report.receiver_failed = true; res.writeHead(403); res.end(); return;
    }
    const chunks = []; let bytes = 0;
    req.on('data', b => { bytes += b.length; if (bytes > 4194304) req.destroy(); else chunks.push(b); });
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString()); report.mock_requests++;
        if (JSON.stringify(body).includes(receiverNonce)) throw Error('RECEIVER_CREDENTIAL_IN_CONTEXT');
        const raw = Buffer.concat(chunks).toString(); privateTransportBytes += Buffer.byteLength(raw);
        if (privateTransportBytes > 8388608) throw Error('PRIVATE_DIAGNOSTIC_LIMIT');
        privateTransport.push(raw);
        const names = (body.tools || []).map(t => t.function?.name || t.name).sort();
        if (JSON.stringify(names) !== JSON.stringify([...NAMES].sort())) throw Error('TOOL_CATALOG');
        report.selected_tools = names;
        const received = (body.messages || []).filter(m => m.role === 'tool').flatMap(m => typeof m.content === 'string'
          ? [m.content] : (m.content || []).filter(x => x.type === 'text').map(x => x.text));
        // Exact textual tool-result proof; no fuzzy matching/redaction reconstruction.
        const expected = rpc.audit.map(row => JSON.stringify(row.response));
        if (JSON.stringify(received) !== JSON.stringify(expected)) throw Error('TOOL_RESULT_ORDER_OR_CONTENT');
        if (received.join('\n').includes('PRIVATE_HOST_SENTINEL')) throw Error('HOST_LEAK');
        const step = planned[report.mock_requests - 1];
        if (report.mock_requests > planned.length + 1) throw Error('UNEXPECTED_ADDITIONAL_CALL');
        const response = completionFixture(step, report.mock_requests, body.stream);
        res.writeHead(200, { 'Content-Type': response.contentType }); res.end(response.body);
      } catch (error) {
        const allowed = ['RECEIVER_CREDENTIAL_IN_CONTEXT', 'TOOL_CATALOG',
          'TOOL_RESULT_ORDER_OR_CONTENT', 'UNEXPECTED_ADDITIONAL_CALL', 'PRIVATE_DIAGNOSTIC_LIMIT'];
        report.receiver_failure_code = allowed.includes(error?.message) ? error.message : 'MOCK_PROTOCOL_REJECTED';
        report.receiver_failed = true; res.writeHead(400); res.end();
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const env = { PATH: process.env.PATH, HOME: '/tmp/home', COPILOT_HOME: '/tmp/home/.copilot',
    COPILOT_OFFLINE: 'true', COPILOT_PROVIDER_TYPE: 'openai',
    COPILOT_PROVIDER_BASE_URL: 'http://127.0.0.1:' + server.address().port + '/v1',
    COPILOT_PROVIDER_WIRE_API: 'completions', COPILOT_PROVIDER_MODEL_ID: 'offline-tool-stub',
    COPILOT_PROVIDER_WIRE_MODEL: 'offline-tool-stub',
    COPILOT_PROVIDER_MAX_PROMPT_TOKENS: '131072', COPILOT_PROVIDER_MAX_OUTPUT_TOKENS: '4096' };
  stage = 'cli_initialization';
  // Compare bootstrap syntax only; these clients never create review sessions.
  const bootstrap = [ ['sdk_only', []],
    ['tool_flags', ['--available-tools=' + NAMES.join(','), '--deny-tool=shell', '--deny-tool=write',
      '--deny-tool=read', '--deny-tool=memory', '--deny-tool=url']],
    ['instruction_flags', ['--no-custom-instructions', '--disable-builtin-mcps']],
    ['remote_flags', ['--no-remote', '--no-remote-export']],
    ['duplicate_sdk_flags', ['--no-auto-update', '--no-auto-login']] ];
  report.bootstrap_matrix = [];
  const privateBootstrap = [];
  for (const [label, args] of bootstrap) {
    const home = '/tmp/home/bootstrap-' + label; await mkdir(home, { recursive: true });
    const probe = new CopilotClient({ ...emptyClientOptions(home), logLevel: 'error',
      connection: RuntimeConnection.forStdio({ env: { ...env, HOME: home, COPILOT_HOME: home + '/.copilot' }, args }) });
    const result = await initializationOnly(probe);
    report.bootstrap_matrix.push({ label, status: result.status,
      version_matches: result.version_matches, cleanup_confirmed: result.cleanup_confirmed });
    if (result.private_error) privateBootstrap.push({ label, error: result.private_error });
    report.private_bootstrap_diagnostic = JSON.stringify(privateBootstrap).split(receiverNonce).join('[LOCAL_NONCE_REDACTED]').slice(0, 32768);
    if (!result.cleanup_confirmed) throw Error('BOOTSTRAP_CLEANUP_UNPROVED');
    if (label === 'sdk_only' && result.status !== 'PASS') throw Error('SDK_BASELINE_STARTUP_FAILED');
  }
  // SDK empty mode and session-level tool filters/hooks enforce the same closed
  // catalog. Verify that catalog at the receiver before accepting any proof.
  const supportedArgs = bootstrap.filter(([label]) => label !== 'duplicate_sdk_flags'
    && report.bootstrap_matrix.find(row => row.label === label)?.status === 'PASS').flatMap(([, args]) => args);
  report.verified_extra_bootstrap_args = supportedArgs;
  client = new CopilotClient({ ...emptyClientOptions('/tmp/home'), logLevel: 'error',
    connection: RuntimeConnection.forStdio({ env, args: supportedArgs }) });
  await client.start(); report.native_cli_version = (await client.getStatus()).version;
  if (report.native_cli_version !== '1.0.98') throw Error('CLI_PIN');
  stage = 'local_session_configuration';
  const prepared = await prepareReview(client, rpc, { model: 'offline-tool-stub', home: '/tmp/home',
    provider: { type: 'openai', baseUrl: env.COPILOT_PROVIDER_BASE_URL,
      wireApi: 'completions', apiKey: receiverNonce } });
  session = prepared.session;
  const metadata = prepared.metadata;
  if (metadata.sessionLimits?.maxAiCredits !== 30) throw Error('SESSION_LIMIT_UNPROVED');
  report.session_soft_credit_ceiling_verified = 30;
  report.pre_dispatch_tool_catalog_verified = true;
  if (report.mock_requests !== 0) throw Error('UNEXPECTED_PRE_DISPATCH_INFERENCE');
  stage = 'local_callback_transport';
  const result = await prepared.sendOnce('OFFLINE TOOL CALLBACK FIXTURE. No real review or AI service.', 60000);
  if (result?.data?.content !== 'OFFLINE_CALLBACK_PROOF_COMPLETE' || report.receiver_failed
      || report.mock_requests !== 6 || rpc.audit.length !== 5
      || rpc.audit.slice(0, 4).some(x => !x.ok) || rpc.audit[4].ok
      || rpc.audit[1].response_bytes <= 51200 || !rpc.audit[1].response.partial
      || rpc.audit[0].response.lines[0].text !== 'OFFLINE_FIXTURE_CONTENT') throw Error('CALLBACK_PROOF_INCOMPLETE');
  report.status = 'PASS'; report.callback_count = rpc.audit.length;
  report.transport = rpc.audit.map(({ tool, response_sha256, response_bytes, ok }) => ({ tool, response_sha256, response_bytes, ok }));
  report.exact_tool_results_received = true; report.host_escape_denied = true;
  report.local_receiver_authenticated = true; report.exact_tool_result_order_verified = true;
  // Exercise the actual production stdin/SDK/broker/evidence entry, not only its factory.
  // The alternate path only accepts a literal noncredential, synthetic snapshot and
  // a kernel network-none namespace; it cannot contact the Copilot service.
  const fixturePrompt = 'OFFLINE PRODUCTION ENTRY PROMPT FIXTURE';
  const control = { version: 1, token: 'OFFLINE_NO_REAL_CREDENTIAL', model: 'offline-tool-stub',
    prompt: fixturePrompt, prompt_sha256: digest(fixturePrompt), binding: { case: 'OFFLINE-FIXTURE' },
    base: 'a'.repeat(40), head: 'b'.repeat(40), freeze_sha256: '0'.repeat(64),
    snapshot_sha256: '0'.repeat(64), diff_sha256: '0'.repeat(64) };
  const entry = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['/app/repo_wide_readonly/live-entry.mjs', '--offline-fixture'],
      { shell: false, env: { PATH: process.env.PATH, HOME: '/tmp/home' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = []; let bytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(Error('PRODUCTION_ENTRY_TIMEOUT')); }, 25000);
    child.stdout.on('data', b => { bytes += b.length; if (bytes > 8388608) child.kill('SIGKILL'); else chunks.push(b); });
    child.stderr.on('data', () => {});
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => {
      clearTimeout(timer);
      try { resolve({ code, proof: JSON.parse(Buffer.concat(chunks).toString()) }); }
      catch { reject(Error('PRODUCTION_ENTRY_RECEIPT_INVALID')); }
    });
    child.stdin.end(JSON.stringify(control));
  });
  privateEntryDiagnostic = entry.proof;
  if (entry.code !== 0 || entry.proof.status !== 'COMPLETED' || entry.proof.fixture_only !== true
      || entry.proof.inference_dispatched !== false || entry.proof.real_model_requests !== 0
      || entry.proof.initial_user_prompts !== 1 || entry.proof.offline_entry_transport?.status !== 'PASS'
      || entry.proof.offline_entry_transport?.initial_prompt_sha256 !== control.prompt_sha256)
    throw Error('PRODUCTION_ENTRY_MOCK_FAILED');
  report.production_entry_mock_verified = true;
  report.production_entry_proof = entry.proof.offline_entry_transport;
} catch (error) {
  report.status = 'BLOCKED';
  report.reason = 'NATIVE_OFFLINE_PROOF_FAILED'; report.failed_stage = stage;
  // Entire probe is credential-free/network-none and uses synthetic sources.
  // Never capture headers. Body nonce checks precede capture. Parent encrypts
  // this field and publishes only bounded labels/hashes, never raw payloads.
  if (report.os_isolation && Object.values(report.os_isolation).every(x => x === true)) {
    const diagnostic = JSON.stringify({ bootstrap: report.private_bootstrap_diagnostic,
      error: String(error?.stack || error?.message || ''),
      stderr: String(client?.stderrBuffer || ''), received_payloads: privateTransport,
      callback_audit: rpc?.audit || [], receiver_failure_code: report.receiver_failure_code,
      bootstrap_matrix: report.bootstrap_matrix, production_entry: privateEntryDiagnostic });
    report.private_native_diagnostic = diagnostic.length <= 16777216
      ? diagnostic.split(receiverNonce).join('[LOCAL_NONCE_REDACTED]')
        .split(Buffer.from(receiverNonce).toString('base64')).join('[LOCAL_NONCE_REDACTED]')
      : JSON.stringify({ capture_status: 'EXPLICIT_DIAGNOSTIC_LIMIT', stage });
  }
  report.callback_count = rpc?.audit.length || 0;
  const safe = ['NETWORK_NOT_NONE', 'CREDENTIAL_ENV', 'OS_ISOLATION', 'CLI_PIN',
    'SESSION_LIMIT_UNPROVED', 'CALLBACK_PROOF_INCOMPLETE', 'BROKER_EXIT', 'BROKER_DEADLINE',
    'SDK_BASELINE_STARTUP_FAILED', 'BOOTSTRAP_CLEANUP_UNPROVED'];
  const system = { EACCES: 'RUNTIME_EXECUTION_DENIED', EROFS: 'RUNTIME_READONLY_PREPARATION_REQUIRED',
    ENOENT: 'RUNTIME_COMPONENT_MISSING' };
  report.failure_code = safe.includes(error?.message) ? error.message
    : (system[error?.code] || 'SDK_OR_LOCAL_PROTOCOL_FAILURE');
}
finally {
  if (session) try { await session.destroy(); } catch {}
  if (client) try { await client.stop(); } catch {}
  if (rpc) rpc.stop();
  if (broker && broker.exitCode === null) broker.kill('SIGTERM');
  if (server) server.closeAllConnections?.();
  if (server) await new Promise(resolve => server.close(resolve));
  clearTimeout(deadline);
  delete report.private_bootstrap_diagnostic;
  await writeFile('/tmp/native-proof.json', JSON.stringify(report));
  console.log(JSON.stringify(report)); process.exitCode = report.status === 'PASS' ? 0 : 2;
}
