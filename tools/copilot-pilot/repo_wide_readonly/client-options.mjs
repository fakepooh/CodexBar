import { isAbsolute, join } from 'node:path';

// The pinned SDK requires persistence explicitly, independently of COPILOT_HOME.
// Each caller supplies its own temporary home; this never starts a runtime.
export function emptyClientOptions(home) {
  if (typeof home !== 'string' || !isAbsolute(home)) throw Error('ISOLATED_HOME_REQUIRED');
  return { mode: 'empty', useLoggedInUser: false, enableRemoteSessions: false, workingDirectory: home,
    baseDirectory: join(home, '.copilot') };
}

// Credential-free startup diagnostics only. Never creates or resumes a session.
export async function initializationOnly(client, timeoutMs = 5000) {
  let timer, cleanupTimer;
  const result = { status: 'FAIL', version_matches: false, cleanup_confirmed: false };
  try {
    const status = await Promise.race([(async () => { await client.start(); return client.getStatus(); })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('STARTUP_DEADLINE')), timeoutMs); })]);
    result.version_matches = status.version === '1.0.98';
    result.status = result.version_matches ? 'PASS' : 'FAIL';
  } catch (error) {
    // Caller must encrypt this field; never copy it to a public status receipt.
    result.private_error = String(error?.stack || error?.message || '') + '\n' + String(client.stderrBuffer || '');
  } finally {
    clearTimeout(timer);
    try {
      await Promise.race([client.stop(), new Promise((_, reject) => {
        cleanupTimer = setTimeout(() => reject(Error('STOP_DEADLINE')), 2000); })]);
      result.cleanup_confirmed = true;
    } catch { client.cliProcess?.kill('SIGKILL'); result.status = 'FAIL'; }
    clearTimeout(cleanupTimer);
  }
  return result;
}
