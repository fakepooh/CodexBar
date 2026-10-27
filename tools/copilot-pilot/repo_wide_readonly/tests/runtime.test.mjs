import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CopilotClient, RuntimeConnection } from '@github/copilot-sdk';
import { emptyClientOptions } from '../client-options.mjs';

// Exercise the actual pinned SDK constructor, never start(), createSession() or send().
const home = '/tmp/repo-wide-sdk-constructor-fixture';
const connection = RuntimeConnection.forStdio({ env: { HOME: home, COPILOT_HOME: home + '/.copilot' } });
test('COPILOT_HOME alone does not satisfy pinned SDK empty-mode persistence', () => {
  assert.throws(() => new CopilotClient({ mode: 'empty', connection }),
    /Empty mode requires an explicit per-session persistence location/);
});
test('isolated runtime options satisfy actual SDK constructor without starting runtime', () => {
  const options = emptyClientOptions(home);
  assert.equal(options.mode, 'empty');
  assert.equal(options.useLoggedInUser, false);
  assert.equal(options.baseDirectory, home + '/.copilot');
  assert.equal(options.workingDirectory, home);
  const client = new CopilotClient({ ...options, connection });
  assert.equal(client.cliProcess, null);
});
test('missing or relative persistence homes fail before runtime construction', () => {
  for (const path of [undefined, '', 'relative/home'])
    assert.throws(() => emptyClientOptions(path), /ISOLATED_HOME_REQUIRED/);
});
