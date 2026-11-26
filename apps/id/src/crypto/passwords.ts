import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT_KEY_LENGTH = 64;

export function hashPassword(plainPassword: string): string {
  const salt = randomBytes(16).toString('hex');
  const derivedKey = scryptSync(plainPassword, salt, SCRYPT_KEY_LENGTH).toString('hex');
  return `scrypt$${salt}$${derivedKey}`;
}

export function verifyPassword(plainPassword: string, storedHash: string): boolean {
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const [, salt, expectedHex] = parts;
  const derivedBuffer = scryptSync(plainPassword, salt, SCRYPT_KEY_LENGTH);
  const expectedBuffer = Buffer.from(expectedHex, 'hex');
  if (derivedBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return timingSafeEqual(derivedBuffer, expectedBuffer);
}

export function hashSecretSha256(plainSecret: string): string {
  return createHash('sha256').update(plainSecret, 'utf8').digest('hex');
}

export function verifySecretSha256(plainSecret: string, expectedSha256Hex: string): boolean {
  const actualBuffer = Buffer.from(hashSecretSha256(plainSecret), 'hex');
  const expectedBuffer = Buffer.from(expectedSha256Hex, 'hex');
  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return timingSafeEqual(actualBuffer, expectedBuffer);
}
