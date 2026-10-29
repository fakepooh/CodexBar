// Shared by the real CLI/mock proof and production. Never falls back to native tools.
import { NAMES, toolset, permission, hooks } from './sdk-tools.mjs';
export const OS_PROOF_FIELDS = ['credential_env_absent', 'host_home_hidden', 'no_capabilities',
  'no_docker_socket', 'no_new_privileges', 'nonroot', 'root_readonly', 'snapshot_git_absent',
  'snapshot_mount_readonly'];
export function requireOsProof(proof) {
  if (!proof?.ok || JSON.stringify(Object.keys(proof.result || {}).sort()) !== JSON.stringify(OS_PROOF_FIELDS)
      || !Object.values(proof.result).every(x => x === true)) throw Error('OS_ISOLATION');
  return proof.result;
}

export async function prepareReview(client, rpc, { model, home, provider } = {}) {
  if (!['auto', 'offline-tool-stub'].includes(model) || home !== '/tmp/home') throw Error('SESSION_CONFIGURATION');
  if (model === 'auto' && provider !== undefined) throw Error('PROVIDER_OVERRIDE_REFUSED');
  if (model === 'offline-tool-stub') {
    const url = new URL(provider?.baseUrl);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') throw Error('OFFLINE_PROVIDER_REQUIRED');
  }
  const session = await client.createSession({ model, workingDirectory: home,
    availableTools: NAMES, tools: toolset(rpc), onPermissionRequest: permission, hooks: hooks(),
    skipCustomInstructions: true, sessionLimits: { maxAiCredits: 30 }, largeOutput: { enabled: false },
    enableConfigDiscovery: false, mcpServers: {}, customAgents: [], ...(provider ? { provider } : {}) });
  try {
    const metadata = await session.rpc.metadata.snapshot();
    if (metadata.sessionLimits?.maxAiCredits !== 30) throw Error('SESSION_LIMIT_UNPROVED');
    await session.rpc.tools.initializeAndValidate();
    const catalog = await session.rpc.tools.getCurrentMetadata();
    const names = catalog.tools?.map(t => t.name).sort();
    if (JSON.stringify(names) !== JSON.stringify([...NAMES].sort())) throw Error('PRE_DISPATCH_TOOL_CATALOG');
    let sent = false;
    return { session, metadata, catalog,
      sendOnce(prompt, timeoutMs) {
        if (sent || typeof prompt !== 'string' || !prompt || Buffer.byteLength(prompt) > 262144)
          throw Error('ONE_INITIAL_PROMPT_ONLY');
        sent = true; // An uncertain failure is spent, never reset or retried.
        return session.sendAndWait({ prompt }, timeoutMs);
      } };
  } catch (error) { await session.destroy(); throw error; }
}
