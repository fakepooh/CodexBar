// Recipient private key is never needed on a public runner.
import { createPublicKey, createHash, randomBytes, publicEncrypt, privateDecrypt,
  createCipheriv, createDecipheriv, constants } from 'node:crypto';

export function seal(plaintext, recipientPem, identity) {
  const recipient = createPublicKey(recipientPem);
  if (recipient.asymmetricKeyType !== 'rsa' || recipient.asymmetricKeyDetails.modulusLength < 4096)
    throw Error('RSA_4096_RECIPIENT_REQUIRED');
  if (!Buffer.isBuffer(plaintext) || plaintext.length > 134217728) throw Error('EVIDENCE_LIMIT');
  const key = randomBytes(32), iv = randomBytes(12);
  try {
    const aad = Buffer.from(JSON.stringify(identity));
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const wrapped = publicEncrypt({ key: recipient, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
    return { version: 'repo-wide-evidence-envelope-v1', identity,
      recipient_sha256: createHash('sha256').update(recipient.export({ type: 'spki', format: 'der' })).digest('hex'),
      iv: iv.toString('base64'), wrapped_key: wrapped.toString('base64'),
      auth_tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
  } finally { key.fill(0); }
}

export function open(envelope, recipientPrivatePem, expectedIdentity) {
  if (envelope.version !== 'repo-wide-evidence-envelope-v1'
      || JSON.stringify(envelope.identity) !== JSON.stringify(expectedIdentity)) throw Error('IDENTITY_MISMATCH');
  const key = privateDecrypt({ key: recipientPrivatePem, padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256' }, Buffer.from(envelope.wrapped_key, 'base64'));
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(JSON.stringify(expectedIdentity)));
    decipher.setAuthTag(Buffer.from(envelope.auth_tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  } finally { key.fill(0); }
}
