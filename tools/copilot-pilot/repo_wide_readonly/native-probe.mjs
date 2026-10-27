// Run ONLY in the credential-free network-none GitHub-hosted probe container.
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { spawn } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { BrokerRpc, NAMES, toolset, permission, hooks } from './sdk-tools.mjs';
import { emptyClientOptions } from './client-options.mjs';

let client, session, rpc, server, broker;
let stage = 'os_boundary';
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
  if (!proof.ok || !Object.values(proof.result).every(x => x === true)) throw Error('OS_ISOLATION');
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
        const delta = step ? { role: 'assistant', tool_calls: [{ index: 0, id: 'probe-' + report.mock_requests,
          type: 'function', function: { name: step[0], arguments: JSON.stringify(step[1]) } }] }
          : { role: 'assistant', content: 'OFFLINE_CALLBACK_PROOF_COMPLETE' };
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write('data: ' + JSON.stringify({ id: 'probe', object: 'chat.completion.chunk', model: 'offline-tool-stub',
          choices: [{ index: 0, delta, finish_reason: null }] }) + '\n\n');
        res.write('data: ' + JSON.stringify({ id: 'probe', object: 'chat.completion.chunk', model: 'offline-tool-stub',
          choices: [{ index: 0, delta: {}, finish_reason: step ? 'tool_calls' : 'stop' }],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }) + '\n\n');
        res.end('data: [DONE]\n\n');
      } catch { report.receiver_failed = true; res.writeHead(400); res.end(); }
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
  client = new CopilotClient({ ...emptyClientOptions('/tmp/home'), logLevel: 'error',
    connection: RuntimeConnection.forStdio({ env,
      args: ['--available-tools=' + NAMES.join(','), '--deny-tool=shell', '--deny-tool=write',
        '--deny-tool=read', '--deny-tool=memory', '--deny-tool=url', '--no-custom-instructions',
        '--no-auto-update', '--disable-builtin-mcps', '--no-auto-login', '--no-remote', '--no-remote-export'] }) });
  await client.start(); report.native_cli_version = (await client.getStatus()).version;
  if (report.native_cli_version !== '1.0.98') throw Error('CLI_PIN');
  stage = 'local_session_configuration';
  session = await client.createSession({ model: 'offline-tool-stub', workingDirectory: '/tmp/home',
    availableTools: NAMES, tools: toolset(rpc), onPermissionRequest: permission, hooks: hooks(),
    skipCustomInstructions: true, sessionLimits: { maxAiCredits: 30 },
    largeOutput: { enabled: false },
    enableConfigDiscovery: false, mcpServers: {}, customAgents: [],
    provider: { type: 'openai', baseUrl: env.COPILOT_PROVIDER_BASE_URL,
      wireApi: 'completions', apiKey: receiverNonce } });
  const metadata = await session.rpc.metadata.snapshot();
  if (metadata.sessionLimits?.maxAiCredits !== 30) throw Error('SESSION_LIMIT_UNPROVED');
  report.session_soft_credit_ceiling_verified = 30;
  stage = 'local_callback_transport';
  const result = await session.sendAndWait({ prompt: 'OFFLINE TOOL CALLBACK FIXTURE. No real review or AI service.' }, 60000);
  if (result?.data?.content !== 'OFFLINE_CALLBACK_PROOF_COMPLETE' || report.receiver_failed
      || report.mock_requests !== 6 || rpc.audit.length !== 5
      || rpc.audit.slice(0, 4).some(x => !x.ok) || rpc.audit[4].ok
      || rpc.audit[1].response_bytes <= 51200 || !rpc.audit[1].response.partial
      || rpc.audit[0].response.lines[0].text !== 'OFFLINE_FIXTURE_CONTENT') throw Error('CALLBACK_PROOF_INCOMPLETE');
  report.status = 'PASS'; report.callback_count = rpc.audit.length;
  report.transport = rpc.audit.map(({ tool, response_sha256, response_bytes, ok }) => ({ tool, response_sha256, response_bytes, ok }));
  report.exact_tool_results_received = true; report.host_escape_denied = true;
  report.local_receiver_authenticated = true; report.exact_tool_result_order_verified = true;
} catch (error) {
  report.reason = 'NATIVE_OFFLINE_PROOF_FAILED'; report.failed_stage = stage;
  // This stage precedes session creation/provider credentials and has no real
  // credentials or historical source. Parent captures stdout privately and
  // encrypts this diagnostic; it must never print this field to public logs.
  if (stage === 'cli_initialization' && report.mock_requests === 0) {
    report.private_startup_diagnostic = JSON.stringify({
      error: String(error?.stack || error?.message || ''),
      stderr: String(client?.stderrBuffer || '') }).split(receiverNonce).join('[LOCAL_NONCE_REDACTED]').slice(0, 32768);
  }
  const safe = ['NETWORK_NOT_NONE', 'CREDENTIAL_ENV', 'OS_ISOLATION', 'CLI_PIN',
    'SESSION_LIMIT_UNPROVED', 'CALLBACK_PROOF_INCOMPLETE', 'BROKER_EXIT', 'BROKER_DEADLINE'];
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
  await writeFile('/tmp/native-proof.json', JSON.stringify(report));
  console.log(JSON.stringify(report)); process.exitCode = report.status === 'PASS' ? 0 : 2;
}
