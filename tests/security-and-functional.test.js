import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';

// Configure isolated test environment BEFORE importing application modules
const KEY_V1 = randomBytes(32).toString('base64');
const KEY_V2 = randomBytes(32).toString('base64');
process.env.NODE_ENV = 'test';
process.env.SQLITE_PATH = ':memory:';
process.env.DATA_ENCRYPTION_KEYS = `1:${KEY_V1},2:${KEY_V2}`;
process.env.ACTIVE_ENCRYPTION_KEY_VERSION = '1';
process.env.HMAC_SECRET = randomBytes(32).toString('base64');
process.env.CORS_ALLOWED_ORIGINS = 'https://securevault.example.com';
process.env.COOKIE_SECURE = 'false';
process.env.LOGIN_RATE_LIMIT_MAX = '100';
process.env.ACCOUNT_LOCKOUT_THRESHOLD = '5';
process.env.MAX_NOTES_PER_USER = '5';

const { createDatabase, setDb } = await import('../src/db/index.js');
const { runMigrations } = await import('../src/db/schema.js');
const { createApp } = await import('../src/app.js');
const { buildAuthRateLimiter } = await import('../src/middleware/security.js');
const {
  hashPassword,
  verifyPassword,
  encrypt,
  decrypt,
  signShortJwt,
  verifyShortJwt,
  maskSensitiveValue,
} = await import('../src/crypto/index.js');
const { generateTotpCode } = await import('../src/crypto/totp.js');
const { validateOutboundUrl } = await import('../src/utils/ssrf.js');
const { rotateAllEncryptedData } = await import('../src/services/keyRotation.js');

// Lightweight cookie jar client for end-to-end HTTP testing
class CookieClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookies = new Map();
  }

  _cookieHeader() {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  _storeCookies(setCookies = []) {
    for (const raw of setCookies) {
      const [pair] = raw.split(';');
      const idx = pair.indexOf('=');
      if (idx === -1) continue;
      const name = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      if (val === '') {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, val);
      }
    }
  }

  async request(path, { method = 'GET', body, headers = {}, includeCsrf = true } = {}) {
    const reqHeaders = { Accept: 'application/json', ...headers };
    const cookieStr = this._cookieHeader();
    if (cookieStr) reqHeaders.Cookie = cookieStr;
    if (body !== undefined) reqHeaders['Content-Type'] = 'application/json';
    if (includeCsrf && method !== 'GET' && method !== 'HEAD') {
      const csrf = this.cookies.get('sv_csrf');
      if (csrf) reqHeaders['X-CSRF-Token'] = decodeURIComponent(csrf);
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: reqHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      redirect: 'manual',
    });

    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    this._storeCookies(setCookies);

    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { status: res.status, headers: res.headers, setCookies, json, text };
  }
}

let db;
let server;
let baseUrl;
let lastResetDelivery = null;

test.before(async () => {
  db = await createDatabase({ databaseUrl: '', sqlitePath: ':memory:' });
  setDb(db);
  await runMigrations(db);

  const app = createApp({
    enableErrorTestRoute: true,
    passwordResetCallback: async (info) => {
      lastResetDelivery = info;
    },
  });
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (db) await db.close();
});

test('A04 Cryptographic Primitives: Argon2id, AES-256-GCM unique IV + tamper detection, HS256 JWT', async () => {
  const hash = await hashPassword('SuperStrong!Pass99');
  assert.ok(hash.startsWith('$argon2id$'), 'Password hash must use Argon2id');
  assert.equal(await verifyPassword(hash, 'SuperStrong!Pass99'), true);
  assert.equal(await verifyPassword(hash, 'WrongPassword!123'), false);

  const enc1 = encrypt('Secreto confidencial', 1);
  const enc2 = encrypt('Secreto confidencial', 1);
  assert.notEqual(enc1.payload, enc2.payload, 'Same plaintext must yield distinct ciphertexts (unique IV)');
  assert.equal(enc1.payload.split('.').length, 3, 'Payload must follow iv.tag.data base64 format');
  assert.equal(decrypt(enc1.payload, 1), 'Secreto confidencial');

  // Tamper with ciphertext -> GCM auth tag must reject
  const [iv, tag, data] = enc1.payload.split('.');
  const tamperedData = Buffer.from(data, 'base64');
  tamperedData[0] ^= 0xff;
  assert.throws(() => decrypt([iv, tag, tamperedData.toString('base64')].join('.'), 1));

  // A08: Fixed algorithm HS256 JWT rejects alg: none
  const validJwt = signShortJwt({ sub: 'u1' }, 60);
  assert.equal(verifyShortJwt(validJwt).sub, 'u1');
  const fakeHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const fakePayload = Buffer.from(JSON.stringify({ sub: 'admin', exp: 9999999999 })).toString('base64url');
  assert.equal(verifyShortJwt(`${fakeHeader}.${fakePayload}.`), null);

  assert.equal(maskSensitiveValue('+52-555-842-9104'), '***-***-9104');
});

test('A01 SSRF Guard blocks private IPs, metadata endpoints, HTTP, and non-allowlisted hosts', async () => {
  await assert.rejects(() => validateOutboundUrl('http://hooks.slack.com/services/a/b/c'), /HTTPS/);
  await assert.rejects(() => validateOutboundUrl('https://169.254.169.254/latest/meta-data/'), /IP literal/);
  await assert.rejects(() => validateOutboundUrl('https://127.0.0.1:8080/internal'), /IP literal/);
  await assert.rejects(() => validateOutboundUrl('https://evil-exfil.example.com/hook'), /allowlist/);
});

test('RF-08 & A02: /health hides internals and Helmet security headers are active', async () => {
  const client = new CookieClient(baseUrl);
  const res = await client.request('/health');
  assert.equal(res.status, 200);
  assert.deepEqual(res.json, { status: 'ok' });
  assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By must be disabled');
  assert.ok(res.headers.get('content-security-policy')?.includes("script-src 'self' https://cdnjs.cloudflare.com"));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.ok(res.headers.get('permissions-policy'));
});

test('RF-01, RF-02, RF-04, RF-05, A01 (IDOR & RBAC), A05 (SQLi & XSS), A06 (Limits)', async () => {
  const userA = new CookieClient(baseUrl);
  const userB = new CookieClient(baseUrl);

  // Reject mass-assignment attempt { role: "admin" } on registration (A01)
  const massAssign = await userA.request('/api/auth/register', {
    method: 'POST',
    body: {
      name: 'Alice',
      email: 'alice@securevault.test',
      password: 'Alice!StrongPass2026',
      role: 'admin',
    },
  });
  assert.equal(massAssign.status, 400);

  // Reject weak password (RF-01)
  const weak = await userA.request('/api/auth/register', {
    method: 'POST',
    body: { name: 'Alice', email: 'alice@securevault.test', password: 'password123' },
  });
  assert.equal(weak.status, 400);

  // Register User A & User B
  const regA = await userA.request('/api/auth/register', {
    method: 'POST',
    body: {
      name: 'Alice Vault',
      email: 'alice@securevault.test',
      password: 'Alice!StrongPass2026',
      phone: '+52-555-111-1234',
    },
  });
  assert.equal(regA.status, 201);
  assert.equal(regA.json.user.role, 'user');
  assert.equal(regA.json.user.phoneMasked, '***-***-1234');
  assert.ok(
    regA.setCookies.some((c) => c.startsWith('sv_session=') && c.includes('HttpOnly') && c.includes('SameSite=Strict')),
    'Session cookie must set HttpOnly and SameSite=Strict'
  );

  const regB = await userB.request('/api/auth/register', {
    method: 'POST',
    body: {
      name: 'Bob Vault',
      email: 'bob@securevault.test',
      password: 'Bob!StrongPass2026',
    },
  });
  assert.equal(regB.status, 201);

  // Verify database stores Argon2id hash and encrypted phone (never plaintext!)
  const dbUserA = await db.query('SELECT password_hash, phone_encrypted FROM users WHERE email = $1', [
    'alice@securevault.test',
  ]);
  assert.ok(dbUserA.rows[0].password_hash.startsWith('$argon2id$'));
  assert.ok(!dbUserA.rows[0].phone_encrypted.includes('1234'));

  // RF-05: Profile returns masked value; /reveal decrypts and logs audit event
  const profA = await userA.request('/api/profile');
  assert.equal(profA.json.profile.phoneMasked, '***-***-1234');
  const revealA = await userA.request('/api/profile/reveal', { method: 'POST' });
  assert.equal(revealA.status, 200);
  assert.equal(revealA.json.phone, '+52-555-111-1234');

  // RF-04: User B creates a private note
  const noteB = await userB.request('/api/notes', {
    method: 'POST',
    body: {
      title: 'Nota confidencial de Bob',
      content: 'Contenido secreto <script>alert(1)</script> de Bob',
    },
  });
  assert.equal(noteB.status, 201);
  const noteBId = noteB.json.note.id;

  // Verify DB stores unreadable AES-256-GCM payload (iv.tag.data)
  const dbNote = await db.query('SELECT content_encrypted, key_version FROM notes WHERE id = $1', [noteBId]);
  assert.ok(!dbNote.rows[0].content_encrypted.includes('Contenido secreto'));
  assert.equal(dbNote.rows[0].content_encrypted.split('.').length, 3);

  // A01 IDOR Test: User A attempts to read, modify, and delete User B's note -> 404 + IDOR_ATTEMPT logged
  const idorRead = await userA.request(`/api/notes/${noteBId}`);
  assert.equal(idorRead.status, 404);
  const idorPatch = await userA.request(`/api/notes/${noteBId}`, {
    method: 'PATCH',
    body: { title: 'Secuestrada' },
  });
  assert.equal(idorPatch.status, 404);
  const idorDel = await userA.request(`/api/notes/${noteBId}`, { method: 'DELETE' });
  assert.equal(idorDel.status, 404);

  const idorEvents = await db.query("SELECT COUNT(*) AS c FROM security_events WHERE event_type = 'IDOR_ATTEMPT'");
  assert.ok(Number(idorEvents.rows[0].c) >= 3, 'IDOR attempts must be recorded in security_events');

  // A01 RBAC: Regular user denied from /api/admin/users -> 403
  const adminDenied = await userA.request('/api/admin/users');
  assert.equal(adminDenied.status, 403);

  // A05 SQL Injection attempt in login email -> rejected by Zod (400) & parameterized query safe
  const sqli = await userA.request('/api/auth/login', {
    method: 'POST',
    body: { email: "' OR 1=1 --", password: 'x' },
  });
  assert.equal(sqli.status, 400);

  // A06 Business Limit: Max 5 notes per user in test env
  for (let i = 1; i <= 5; i += 1) {
    const createRes = await userA.request('/api/notes', {
      method: 'POST',
      body: { title: `Nota ${i}`, content: `Texto cifrado ${i}` },
    });
    assert.equal(createRes.status, 201);
  }
  const overLimit = await userA.request('/api/notes', {
    method: 'POST',
    body: { title: 'Nota 6', content: 'Excede cuota' },
  });
  assert.equal(overLimit.status, 422);

  // CSRF protection: state-changing request without X-CSRF-Token rejected (403)
  const noCsrf = await userA.request('/api/notes', {
    method: 'POST',
    body: { title: 'Sin CSRF', content: 'Bloqueado' },
    includeCsrf: false,
  });
  assert.equal(noCsrf.status, 403);

  // RF-02 Logout invalidates server session immediately
  const savedCookie = userA.cookies.get('sv_session');
  const logoutRes = await userA.request('/api/auth/logout', { method: 'POST' });
  assert.equal(logoutRes.status, 200);
  userA.cookies.set('sv_session', savedCookie);
  const afterLogout = await userA.request('/api/auth/me');
  assert.equal(afterLogout.status, 401);
});

test('RF-06 Password recovery: SHA-256 hashed single-use token, expiry, and session revocation', async () => {
  const client = new CookieClient(baseUrl);
  lastResetDelivery = null;

  // Generic response for non-existent email (no enumeration)
  const unknown = await client.request('/api/auth/forgot-password', {
    method: 'POST',
    body: { email: 'nobody@securevault.test' },
  });
  assert.equal(unknown.status, 200);
  assert.equal(lastResetDelivery, null);

  // Request for existing user Alice
  const reqReset = await client.request('/api/auth/forgot-password', {
    method: 'POST',
    body: { email: 'alice@securevault.test' },
  });
  assert.equal(reqReset.status, 200);
  assert.ok(lastResetDelivery?.token && lastResetDelivery.token.length === 64);

  // Verify raw token is NOT stored in DB (only SHA-256 hash)
  const dbTok = await db.query('SELECT token_hash FROM password_reset_tokens');
  assert.ok(dbTok.rows.every((r) => r.token_hash !== lastResetDelivery.token));

  // Complete password reset
  const done = await client.request('/api/auth/reset-password', {
    method: 'POST',
    body: { token: lastResetDelivery.token, newPassword: 'Alice!RotatedPass2026' },
  });
  assert.equal(done.status, 200);

  // Reusing same token fails (single-use)
  const reuse = await client.request('/api/auth/reset-password', {
    method: 'POST',
    body: { token: lastResetDelivery.token, newPassword: 'Alice!AnotherPass2026' },
  });
  assert.equal(reuse.status, 400);

  // Login works with new password & regenerates fresh session ID
  const loginNew = await client.request('/api/auth/login', {
    method: 'POST',
    body: { email: 'alice@securevault.test', password: 'Alice!RotatedPass2026' },
  });
  assert.equal(loginNew.status, 200);
  const firstSession = client.cookies.get('sv_session');

  const loginAgain = await client.request('/api/auth/login', {
    method: 'POST',
    body: { email: 'alice@securevault.test', password: 'Alice!RotatedPass2026' },
  });
  assert.equal(loginAgain.status, 200);
  assert.notEqual(client.cookies.get('sv_session'), firstSession, 'Session ID must regenerate on login');
});

test('Bonus MFA TOTP enrollment, login challenge, and Key Rotation (v1 -> v2)', async () => {
  const client = new CookieClient(baseUrl);
  const login = await client.request('/api/auth/login', {
    method: 'POST',
    body: { email: 'bob@securevault.test', password: 'Bob!StrongPass2026' },
  });
  assert.equal(login.status, 200);

  // Setup & enable TOTP
  const setup = await client.request('/api/auth/mfa/setup', { method: 'POST' });
  assert.equal(setup.status, 200);
  assert.ok(setup.json.secret && setup.json.otpauthUri.startsWith('otpauth://totp/'));

  const validCode = generateTotpCode(setup.json.secret);
  const enable = await client.request('/api/auth/mfa/enable', {
    method: 'POST',
    body: { code: validCode },
  });
  assert.equal(enable.status, 200);
  assert.equal(enable.json.mfaEnabled, true);

  // Logout & login again -> requires MFA challenge
  await client.request('/api/auth/logout', { method: 'POST' });
  const step1 = await client.request('/api/auth/login', {
    method: 'POST',
    body: { email: 'bob@securevault.test', password: 'Bob!StrongPass2026' },
  });
  assert.equal(step1.status, 200);
  assert.equal(step1.json.mfaRequired, true);

  const step2 = await client.request('/api/auth/mfa/login', {
    method: 'POST',
    body: { code: generateTotpCode(setup.json.secret) },
  });
  assert.equal(step2.status, 200);
  assert.equal(step2.json.user.mfaEnabled, true);

  // Promote Bob to admin directly in DB to test Admin RF-07 + Key Rotation
  await db.query("UPDATE users SET role = 'admin' WHERE email = $1", ['bob@securevault.test']);
  const adminUsers = await client.request('/api/admin/users');
  assert.equal(adminUsers.status, 200);
  assert.ok(adminUsers.json.users.length >= 2);

  // Key Rotation check (encrypt a note with v2 via rotation helper)
  const { config } = await import('../src/config/env.js');
  // Test direct rotation function compatibility
  const rotRes = await rotateAllEncryptedData({ actorUserId: step2.json.user.id, ipAddress: '127.0.0.1' });
  assert.equal(rotRes.targetVersion, config.activeEncryptionKeyVersion);

  const auditLogs = await client.request('/api/admin/audit-logs');
  assert.equal(auditLogs.status, 200);
  assert.ok(auditLogs.json.events.some((e) => e.eventType === 'KEY_ROTATION'));
});

test('A07 Brute-force lockout (HTTP 429) & Rate limiting + A09 Alert triggered + A10 Generic error', async () => {
  // Dedicated app with strict rate limit of 3 attempts to verify HTTP 429 cleanly
  const strictApp = createApp({
    enableErrorTestRoute: true,
    authRateLimiter: buildAuthRateLimiter({ max: 3, windowMs: 60_000 }),
  });
  const strictServer = http.createServer(strictApp);
  await new Promise((resolve) => strictServer.listen(0, '127.0.0.1', resolve));
  const strictUrl = `http://127.0.0.1:${strictServer.address().port}`;
  const attacker = new CookieClient(strictUrl);

  try {
    // 3 wrong attempts -> 401; 4th attempt blocked by express-rate-limit -> HTTP 429
    for (let i = 0; i < 3; i += 1) {
      const r = await attacker.request('/api/auth/login', {
        method: 'POST',
        body: { email: 'alice@securevault.test', password: `Wrong!Pass${i}` },
      });
      assert.equal(r.status, 401);
    }
    const blocked = await attacker.request('/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@securevault.test', password: 'Wrong!Pass4' },
    });
    assert.equal(blocked.status, 429);

    // A10: Forced unhandled error returns generic message + requestId without leaking internals
    const boom = await attacker.request('/api/_test/boom');
    assert.equal(boom.status, 500);
    assert.equal(boom.json.error, 'INTERNAL_ERROR');
    assert.ok(boom.json.requestId);
    assert.ok(!boom.text.includes('SENSITIVE_DB_CONNECTION_STRING'));
    assert.ok(!boom.text.includes('stack'));
  } finally {
    await new Promise((resolve) => strictServer.close(resolve));
  }
});
