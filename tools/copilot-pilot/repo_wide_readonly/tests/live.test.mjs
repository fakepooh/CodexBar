import assert from 'node:assert/strict';
import { test } from 'node:test';
import { prepareReview, requireOsProof, OS_PROOF_FIELDS } from '../review-session.mjs';
import { NAMES } from '../sdk-tools.mjs';

function fixture(names = NAMES) {
  const calls = []; let config;
  const session = { rpc: { metadata: { snapshot: async () => ({ sessionLimits: { maxAiCredits: 30 } }) },
    tools: { initializeAndValidate: async () => calls.push('initialize'),
      getCurrentMetadata: async () => ({ tools: names.map(name => ({ name })) }) } },
    destroy: async () => calls.push('destroy'),
    sendAndWait: async payload => { calls.push(payload); return 'result'; } };
  const client = { createSession: async value => { config = value; return session; } };
  return { client, calls, session, get config() { return config; } };
}

test('production Auto config and tool catalog verified before any send', async () => {
  const f = fixture(); const p = await prepareReview(f.client, {}, { model: 'auto', home: '/tmp/home' });
  assert.deepEqual(f.calls, ['initialize']);
  assert.deepEqual(f.config.availableTools, NAMES); assert.equal(f.config.model, 'auto');
  assert.equal(f.config.enableConfigDiscovery, false); assert.equal(f.config.skipCustomInstructions, true);
  assert.deepEqual(f.config.customAgents, []); assert.deepEqual(f.config.mcpServers, {});
  assert.equal(f.config.largeOutput.enabled, false);
  assert.equal(await p.sendOnce('FIXED_GENERIC_FIXTURE', 100), 'result');
  assert.equal(f.calls.filter(x => typeof x === 'object').length, 1);
  assert.throws(() => p.sendOnce('follow-up', 100), /ONE_INITIAL_PROMPT/);
});
test('a failed first send never releases the one-shot gate', async () => {
  const f = fixture(); f.session.sendAndWait = async () => { throw Error('uncertain'); };
  const p = await prepareReview(f.client, {}, { model: 'auto', home: '/tmp/home' });
  await assert.rejects(p.sendOnce('fixture', 100), /uncertain/);
  assert.throws(() => p.sendOnce('retry', 100), /ONE_INITIAL_PROMPT/);
});
test('missing, additional or duplicate effective tools fail before model dispatch', async () => {
  for (const names of [[], [...NAMES, 'shell'], [NAMES[0], NAMES[0], NAMES[1]]]) {
    const f = fixture(names);
    await assert.rejects(prepareReview(f.client, {}, { model: 'auto', home: '/tmp/home' }), /TOOL_CATALOG/);
    assert.deepEqual(f.calls, ['initialize', 'destroy']);
  }
});
test('no other model, working directory or Auto provider override can create a session', async () => {
  for (const config of [{ model: 'pinned-other-model', home: '/tmp/home' },
    { model: 'auto', home: '/snapshot' }, { model: 'auto', home: '/tmp/home', provider: {} },
    { model: 'offline-tool-stub', home: '/tmp/home', provider: { baseUrl: 'https://external.invalid' } }]) {
    const f = fixture(); await assert.rejects(prepareReview(f.client, {}, config));
    assert.equal(f.config, undefined); assert.equal(f.calls.length, 0);
  }
});
test('contradictory credit configuration is rejected without a user prompt', async () => {
  const f = fixture(); f.session.rpc.metadata.snapshot = async () => ({ sessionLimits: { maxAiCredits: 300 } });
  await assert.rejects(prepareReview(f.client, {}, { model: 'auto', home: '/tmp/home' }), /LIMIT_UNPROVED/);
  assert.deepEqual(f.calls, ['destroy']);
});
test('OS proof must contain every mandatory field, all typed true', () => {
  const result = Object.fromEntries(OS_PROOF_FIELDS.map(k => [k, true]));
  assert.equal(requireOsProof({ ok: true, result }), result);
  for (const invalid of [{}, { nonroot: true }, { ...result, root_readonly: 1 }, { ...result, extra: true }])
    assert.throws(() => requireOsProof({ ok: true, result: invalid }), /OS_ISOLATION/);
});
