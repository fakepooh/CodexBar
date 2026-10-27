import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { seal, open } from '../seal.mjs';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 4096,
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const identity = { case: 'FIXTURE', run_id: 1, method: 'candidate' };
test('recipient-only roundtrip; plaintext absent from artifact', () => {
  const e = seal(Buffer.from('private fixture evidence'), publicKey, identity);
  assert.ok(!JSON.stringify(e).includes('private fixture evidence'));
  assert.equal(open(e, privateKey, identity).toString(), 'private fixture evidence');
});
test('ciphertext and identity tampering fail closed', () => {
  const e = seal(Buffer.from('fixture'), publicKey, identity);
  const raw = Buffer.from(e.ciphertext, 'base64'); raw[0] ^= 1;
  assert.throws(() => open({ ...e, ciphertext: raw.toString('base64') }, privateKey, identity));
  assert.throws(() => open(e, privateKey, { ...identity, run_id: 2 }));
});
test('fresh encryption is randomized', () => {
  assert.notEqual(seal(Buffer.from('fixture'), publicKey, identity).ciphertext,
    seal(Buffer.from('fixture'), publicKey, identity).ciphertext);
});
