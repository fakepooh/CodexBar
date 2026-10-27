import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NAMES, toolset, permission, hooks } from '../sdk-tools.mjs';

test('only unique readonly SDK tools; no native fallback or skip-permission', () => {
  const defs = toolset({ tool() { throw Error('not executed'); } });
  assert.deepEqual(defs.map(x => x.name), NAMES);
  for (const def of defs) {
    assert.equal(def.overridesBuiltInTool, undefined);
    assert.equal(def.skipPermission, false);
    assert.equal(def.parameters.additionalProperties, false);
  }
});
test('one-call approval only for the three controlled external tools', () => {
  for (const toolName of NAMES)
    assert.equal(permission({ kind: 'custom-tool', toolName }, {}).kind, 'approve-once');
  for (const kind of ['read', 'shell', 'write', 'url', 'memory', 'mcp'])
    assert.equal(permission({ kind, toolName: 'view' }, {}).kind, 'reject');
  assert.equal(permission({ kind: 'custom-tool', toolName: 'bash' }, {}).kind, 'reject');
});
test('managed approvals fail closed; hooks never broadly approve', () => {
  assert.equal(permission({ kind: 'custom-tool', toolName: 'repo_view', managedApprovalRequired: true }, {}).kind, 'reject');
  assert.equal(permission({ kind: 'custom-tool', toolName: 'repo_view' }, { managedSettingsEnabled: true }).kind, 'reject');
  assert.equal(hooks().onPreToolUse({ toolName: 'repo_view' }), undefined);
  assert.equal(hooks().onPreToolUse({ toolName: 'view' }).permissionDecision, 'deny');
  assert.equal(hooks().onPreToolUse({ toolName: 'bash' }).permissionDecision, 'deny');
  assert.equal(hooks().onErrorOccurred({}).errorHandling, 'abort');
});
test('args are data, dispatched only to the fixed broker handler', async () => {
  const calls = []; const defs = toolset({ tool: async (name, args) => { calls.push({ name, args }); return 'fixture'; } });
  await defs[1].handler({ query: '$(not-executed); never a shell' });
  assert.deepEqual(calls, [{ name: 'grep', args: { query: '$(not-executed); never a shell' } }]);
});
