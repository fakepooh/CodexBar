import { isAbsolute, join } from 'node:path';

// The pinned SDK requires persistence explicitly, independently of COPILOT_HOME.
// Each caller supplies its own temporary home; this never starts a runtime.
export function emptyClientOptions(home) {
  if (typeof home !== 'string' || !isAbsolute(home)) throw Error('ISOLATED_HOME_REQUIRED');
  return { mode: 'empty', useLoggedInUser: false, workingDirectory: home,
    baseDirectory: join(home, '.copilot') };
}
