// Host-side evidence packaging only. Never takes a private key or model credential.
import { readFile, writeFile } from 'node:fs/promises';
import { createPublicKey, createHash } from 'node:crypto';
import { seal } from './seal.mjs';
const EXPECTED = '672c1ecd0677e1083494fe80462bdaee1f685a23a0728143daaa48d92d251abb';
try {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted'
      || process.env.GITHUB_REPOSITORY !== 'fakepooh/CodexBar') throw Error('HOSTED_ONLY');
  const [input, output, identityFile] = process.argv.slice(2);
  const pem = process.env.COPILOT_REPO_WIDE_PUBLIC_RECIPIENT;
  const actual = createHash('sha256').update(createPublicKey(pem).export({ type: 'spki', format: 'der' })).digest('hex');
  if (actual !== EXPECTED) throw Error('RECIPIENT_MISMATCH');
  const identity = JSON.parse(await readFile(identityFile, 'utf8'));
  const envelope = seal(await readFile(input), pem, identity);
  await writeFile(output, JSON.stringify(envelope), { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ status: 'SEALED', recipient_sha256: actual,
    envelope_sha256: createHash('sha256').update(JSON.stringify(envelope)).digest('hex') }));
} catch { console.error('EVIDENCE_SEAL_BLOCKED'); process.exitCode = 2; }
