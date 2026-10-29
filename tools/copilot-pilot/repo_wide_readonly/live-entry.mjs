// Fixed production container entry. Control/credential come only through stdin.
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { spawn } from 'node:child_process';
import { readFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { writeSync, writeFileSync, renameSync } from 'node:fs';
import { BrokerRpc } from './sdk-tools.mjs';
import { emptyClientOptions } from './client-options.mjs';
import { prepareReview, requireOsProof } from './review-session.mjs';

let client, prepared, rpc, broker, token = '', unsub;
const started = performance.now(), events = [];
const evidence = { status: 'BLOCKED', inference_dispatched: false, initial_user_prompts: 0,
  requested_model: 'auto', cli_version: null, events, model_consumption_proven: false };
function serialize() {
  let text = JSON.stringify(evidence);
  for (const secret of token ? [token, Buffer.from(token).toString('base64')] : [])
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
      || Buffer.byteLength(control.prompt) > 262144 || control.model !== 'auto') throw Error('CONTROL_BINDING');
  const snapshot = JSON.parse(await readFile('/metadata/snapshot.json'));
  if (snapshot.complete !== true || snapshot.case.id !== control.binding.case
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
  client = new CopilotClient({ ...emptyClientOptions('/tmp/home'), gitHubToken: token, logLevel: 'error',
    connection: RuntimeConnection.forStdio({ args: ['--no-remote', '--no-remote-export'],
      env: { PATH: process.env.PATH, HOME: '/tmp/home', COPILOT_HOME: '/tmp/home/.copilot',
        GITHUB_TOKEN: token, GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'fakepooh/CodexBar' } }) });
  await client.start(); evidence.cli_version = (await client.getStatus()).version;
  if (evidence.cli_version !== '1.0.98' || (await client.getAuthStatus()).isAuthenticated !== true)
    throw Error('PIN_OR_AUTH');
  prepared = await prepareReview(client, rpc, { model: 'auto', home: '/tmp/home' });
  evidence.session_id = prepared.session.sessionId; evidence.tool_catalog = prepared.catalog;
  evidence.pre_dispatch_metadata = { sessionLimits: { maxAiCredits: prepared.metadata.sessionLimits.maxAiCredits } };
  let nextCheckpoint = 0;
  unsub = prepared.session.on(e => {
    events.push(e);
    if (performance.now() >= nextCheckpoint) { checkpoint(); nextCheckpoint = performance.now() + 1000; }
  });
  evidence.inference_dispatched = true; evidence.initial_user_prompts = 1;
  checkpoint();
  const result = await prepared.sendOnce(control.prompt, 1200000);
  evidence.raw_output = result?.data?.content ?? null;
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
  clearTimeout(deadline); evidence.duration_seconds = (performance.now() - started) / 1000;
  // stdout is captured privately by the trusted parent, NEVER printed in Actions.
  console.log(serialize()); process.exitCode = evidence.status === 'COMPLETED' ? 0 : 2;
}
