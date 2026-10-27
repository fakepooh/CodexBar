// Hosted sessionless probe only. No createSession/send/resume APIs are called.
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { safeQuota } from './safe-quota.mjs';
import { emptyClientOptions } from './client-options.mjs';

let client, home;
let stage = 'hosted_identity';
let report = { status: 'BLOCKED', sessions_created: 0, model_requests: 0,
  cli_version_expected: '1.0.98', sdk_version_expected: '1.0.22',
  authentication: 'GITHUB_TOKEN', billing_identity_basis: 'personal repository owner seat per GitHub Docs' };
const deadline = setTimeout(() => { console.log(JSON.stringify({ ...report, reason: 'AUTH_PREFLIGHT_TIMEOUT' })); process.exit(2); }, 90000);
try {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted'
      || process.env.GITHUB_REPOSITORY !== 'fakepooh/CodexBar'
      || process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' || !process.env.GITHUB_TOKEN) {
    throw Error('HOSTED_IDENTITY_OR_TOKEN_MISSING');
  }
  home = await mkdtemp(join(tmpdir(), 'repo-wide-auth-'));
  stage = 'client_constructor';
  client = new CopilotClient({ ...emptyClientOptions(home),
    gitHubToken: process.env.GITHUB_TOKEN, logLevel: 'error',
    connection: RuntimeConnection.forStdio({ args: ['--no-custom-instructions', '--no-auto-update',
      '--disable-builtin-mcps', '--no-auto-login', '--secret-env-vars=GITHUB_TOKEN,COPILOT_SDK_AUTH_TOKEN'],
      env: { PATH: process.env.PATH, HOME: home, COPILOT_HOME: join(home, '.copilot'),
        GITHUB_TOKEN: process.env.GITHUB_TOKEN, GITHUB_ACTIONS: 'true',
        GITHUB_REPOSITORY: 'fakepooh/CodexBar' } }) });
  stage = 'cli_initialization';
  await client.start();
  report.cli_start_completed = true;
  stage = 'status';
  const version = await client.getStatus();
  stage = 'authentication_status';
  const auth = await client.getAuthStatus();
  // Strictly allowlisted metadata; never serialize auth response or raw errors.
  report.authenticated = auth.isAuthenticated === true;
  report.cli_version_matches = version.version === '1.0.98';
  report.reported_login = auth.login === 'fakepooh' ? 'fakepooh' : null;
  report.installation_token_has_no_user_identity = !auth.login;
  if (report.authenticated && report.cli_version_matches) {
    try { report.request_quota = safeQuota(await client.rpc.account.getQuota({})); }
    catch { report.request_quota = { status: 'UNAVAILABLE', live_admissible: false }; }
  }
  report.status = report.authenticated && report.cli_version_matches ? 'AUTHENTICATION_ONLY_PASS' : 'BLOCKED';
  report.included_allowance_confirmed = false;
  report.additional_paid_usage_confirmed_disabled = false;
  report.live_admissible = false;
  report.reason = 'BILLING_ALLOWANCE_TOOL_ISOLATION_AND_PRIVATE_STORAGE_REQUIRE_SEPARATE_PROOF';
} catch {
  report.reason = 'SESSIONLESS_AUTH_PREFLIGHT_FAILED';
  report.failed_stage = stage;
} finally {
  if (client) { try { await client.stop(); } catch { report.shutdown_failed = true; } }
  if (home) await rm(home, { recursive: true, force: true });
  clearTimeout(deadline);
  console.log(JSON.stringify(report));
  process.exitCode = report.status === 'AUTHENTICATION_ONLY_PASS' ? 0 : 2;
}
