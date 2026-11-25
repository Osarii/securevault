import argon2 from 'argon2';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';
import { config } from '../config/env.js';

const ARGON2_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB (OWASP minimum >= 19 MiB)
  timeCost: 2,
  parallelism: 1,
});

// 1. Slow salted password hashing with Argon2id (NEVER reversible)
export async function hashPassword(plainPassword) {
  return argon2.hash(plainPassword, ARGON2_OPTIONS);
}

export async function verifyPassword(storedHash, plainPassword) {
  if (!storedHash || !plainPassword) return false;
  try {
    return await argon2.verify(storedHash, plainPassword);
  } catch {
    return false;
  }
}

// 2. Authenticated encryption AES-256-GCM with unique 12-byte IV + 16-byte auth tag + key rotation
export function encrypt(plaintext, keyVersion = config.activeEncryptionKeyVersion) {
  const key = config.encryptionKeys.get(keyVersion);
  if (!key) {
    throw new Error(`Encryption key version ${keyVersion} not available`);
  }
  const iv = randomBytes(12); // Unique 96-bit IV per encryption
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    payload: [iv, tag, encrypted].map((b) => b.toString('base64')).join('.'),
    keyVersion,
  };
}

export function decrypt(payload, keyVersion = 1) {
  if (typeof payload !== 'string') {
    throw new Error('Encrypted payload must be a string');
  }
  const parts = payload.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted payload format');
  }
  const key = config.encryptionKeys.get(keyVersion);
  if (!key) {
    throw new Error(`Decryption key version ${keyVersion} not available`);
  }

  const [iv, tag, data] = parts.map((segment) => Buffer.from(segment, 'base64'));
  if (iv.length !== 12 || tag.length !== 16) {
    throw new Error('Invalid IV or authentication tag length');
  }

  const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag); // Throws automatically if tampered
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

// 3. High-entropy opaque tokens + fast SHA-256 hashing for storage
export function generateOpaqueToken(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

export function sha256Hex(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

// 4. HMAC-SHA256 signing & constant-time verification (OWASP A08 / Data Integrity)
export function hmacSign(data) {
  return createHmac('sha256', config.hmacSecret).update(String(data), 'utf8').digest('base64url');
}

export function hmacVerify(data, signature) {
  if (typeof signature !== 'string' || signature.length === 0) return false;
  const expected = hmacSign(data);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(signature, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// 5. Fixed-algorithm HS256 JWT (rejects alg: "none" and any algorithm other than HS256 - OWASP A08)
export function signShortJwt(payload, ttlSeconds = 300) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(
    JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds })
  ).toString('base64url');
  const signingInput = `${header}.${body}`;
  const sig = hmacSign(signingInput);
  return `${signingInput}.${sig}`;
}

export function verifyShortJwt(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, sig] = parts;
  let header;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  // Strictly enforce fixed algorithm HS256 (blocks alg: none and algorithm confusion)
  if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') {
    return null;
  }

  if (!hmacVerify(`${headerB64}.${payloadB64}`, sig)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp <= now) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

// 6. Mask sensitive profile fields (RF-05: ***-***-1234)
export function maskSensitiveValue(value) {
  if (!value) return null;
  const trimmed = String(value).trim();
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length >= 4) {
    return `***-***-${digits.slice(-4)}`;
  }
  if (trimmed.length <= 4) {
    return '****';
  }
  return `${'*'.repeat(Math.max(4, trimmed.length - 4))}${trimmed.slice(-4)}`;
}
