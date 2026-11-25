import 'dotenv/config';
import { randomBytes } from 'node:crypto';

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';
const isTest = NODE_ENV === 'test';

function parseIntEnv(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw new Error(`Invalid integer environment variable: ${name}`);
  }
  return parsed;
}

function parseBoolEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return raw === 'true' || raw === '1';
}

function decodeKeyBase64(b64, label) {
  const buf = Buffer.from(b64.trim(), 'base64');
  if (buf.length !== 32) {
    throw new Error(`${label} must decode to exactly 32 bytes (256 bits)`);
  }
  return buf;
}

function loadEncryptionKeys() {
  const keys = new Map();

  if (process.env.DATA_ENCRYPTION_KEYS && process.env.DATA_ENCRYPTION_KEYS.trim() !== '') {
    for (const entry of process.env.DATA_ENCRYPTION_KEYS.split(',')) {
      const trimmed = entry.trim();
      if (!trimmed) continue;
      const colonIdx = trimmed.indexOf(':');
      if (colonIdx <= 0) {
        throw new Error('DATA_ENCRYPTION_KEYS entries must follow "<version>:<base64>" format');
      }
      const version = Number.parseInt(trimmed.slice(0, colonIdx), 10);
      if (!Number.isInteger(version) || version < 1) {
        throw new Error('DATA_ENCRYPTION_KEYS version must be a positive integer');
      }
      const keyBuf = decodeKeyBase64(trimmed.slice(colonIdx + 1), `DATA_ENCRYPTION_KEYS[${version}]`);
      keys.set(version, keyBuf);
    }
  }

  if (process.env.DATA_ENCRYPTION_KEY && process.env.DATA_ENCRYPTION_KEY.trim() !== '') {
    if (!keys.has(1)) {
      keys.set(1, decodeKeyBase64(process.env.DATA_ENCRYPTION_KEY, 'DATA_ENCRYPTION_KEY'));
    }
  }

  if (keys.size === 0) {
    if (isProduction) {
      // Fail closed in production (OWASP A04 / A10)
      throw new Error('FATAL: DATA_ENCRYPTION_KEY or DATA_ENCRYPTION_KEYS is required in production');
    }
    // Ephemeral dev/test key when no .env is configured yet (never hardcoded!)
    keys.set(1, randomBytes(32));
  }

  const activeVersion = parseIntEnv('ACTIVE_ENCRYPTION_KEY_VERSION', Math.max(...keys.keys()), { min: 1 });
  if (!keys.has(activeVersion)) {
    throw new Error(`ACTIVE_ENCRYPTION_KEY_VERSION=${activeVersion} is not present in loaded keys`);
  }

  return { keys, activeVersion };
}

function loadHmacSecret() {
  const raw = process.env.HMAC_SECRET;
  if (raw && raw.trim() !== '') {
    const buf = Buffer.from(raw.trim(), 'base64');
    if (buf.length < 32) {
      throw new Error('HMAC_SECRET must decode to at least 32 bytes');
    }
    return buf;
  }
  if (isProduction) {
    throw new Error('FATAL: HMAC_SECRET is required in production');
  }
  return randomBytes(32);
}

const { keys: encryptionKeys, activeVersion: activeEncryptionKeyVersion } = loadEncryptionKeys();
const hmacSecret = loadHmacSecret();

const corsOrigins = (process.env.CORS_ALLOWED_ORIGINS || (isProduction ? '' : 'http://localhost:3000'))
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const allowedWebhookHosts = (process.env.ALLOWED_WEBHOOK_HOSTS || 'hooks.slack.com,discord.com,api.resend.com')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

export const config = Object.freeze({
  nodeEnv: NODE_ENV,
  isProduction,
  isTest,
  port: parseIntEnv('PORT', 3000, { min: 0, max: 65535 }),
  trustProxy: parseIntEnv('TRUST_PROXY', isProduction ? 1 : 0, { min: 0, max: 5 }),
  corsAllowedOrigins: corsOrigins,
  databaseUrl: process.env.DATABASE_URL ? process.env.DATABASE_URL.trim() : '',
  sqlitePath: process.env.SQLITE_PATH || './data/securevault.db',
  dbSslRejectUnauthorized: parseBoolEnv('DB_SSL_REJECT_UNAUTHORIZED', true),
  dbQueryTimeoutMs: parseIntEnv('DB_QUERY_TIMEOUT_MS', 5000, { min: 500, max: 60000 }),
  encryptionKeys,
  activeEncryptionKeyVersion,
  hmacSecret,
  sessionTtlMinutes: parseIntEnv('SESSION_TTL_MINUTES', 120, { min: 5, max: 1440 }),
  cookieSecure: parseBoolEnv('COOKIE_SECURE', isProduction),
  maxNotesPerUser: parseIntEnv('MAX_NOTES_PER_USER', 50, { min: 1, max: 500 }),
  maxNoteTitleLength: parseIntEnv('MAX_NOTE_TITLE_LENGTH', 150, { min: 10, max: 500 }),
  maxNoteContentLength: parseIntEnv('MAX_NOTE_CONTENT_LENGTH', 10000, { min: 100, max: 100000 }),
  loginRateLimitMax: parseIntEnv('LOGIN_RATE_LIMIT_MAX', 10, { min: 3, max: 100 }),
  loginRateLimitWindowMin: parseIntEnv('LOGIN_RATE_LIMIT_WINDOW_MIN', 15, { min: 1, max: 60 }),
  accountLockoutThreshold: parseIntEnv('ACCOUNT_LOCKOUT_THRESHOLD', 5, { min: 2, max: 20 }),
  accountLockoutMinutes: parseIntEnv('ACCOUNT_LOCKOUT_MINUTES', 15, { min: 1, max: 120 }),
  alertFailedLoginThreshold: parseIntEnv('ALERT_FAILED_LOGIN_THRESHOLD', 5, { min: 2, max: 50 }),
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL ? process.env.ALERT_WEBHOOK_URL.trim() : '',
  allowedWebhookHosts,
  outboundTimeoutMs: parseIntEnv('OUTBOUND_TIMEOUT_MS', 4000, { min: 500, max: 15000 }),
});
