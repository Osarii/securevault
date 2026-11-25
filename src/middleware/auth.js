import { randomUUID } from 'node:crypto';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import { generateOpaqueToken, sha256Hex, hmacSign, hmacVerify } from '../crypto/index.js';
import { recordSecurityEvent } from '../services/audit.js';

export const SESSION_COOKIE_NAME = 'sv_session';
export const CSRF_COOKIE_NAME = 'sv_csrf';
export const MFA_CHALLENGE_COOKIE_NAME = 'sv_mfa';

function sessionCookieOptions(maxAgeMs) {
  return {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge: maxAgeMs,
  };
}

function csrfCookieOptions(maxAgeMs) {
  return {
    httpOnly: false, // Read by JS to echo in X-CSRF-Token header (double-submit signed with HMAC)
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge: maxAgeMs,
  };
}

export function buildSignedCsrfToken(sessionId) {
  const nonce = generateOpaqueToken(16);
  const sig = hmacSign(`${sessionId}.${nonce}`);
  return `${nonce}.${sig}`;
}

export function verifySignedCsrfToken(sessionId, token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, sig] = parts;
  return hmacVerify(`${sessionId}.${nonce}`, sig);
}

// OWASP A07: Always regenerate a fresh session ID on authentication (prevents session fixation)
export async function issueFreshSession(req, res, userId) {
  const db = await getDb();

  // Invalidate any pre-existing session cookie on this client
  const existingToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (existingToken) {
    await db.query('DELETE FROM sessions WHERE token_hash = $1', [sha256Hex(existingToken)]);
  }

  const sessionId = randomUUID();
  const rawToken = generateOpaqueToken(32);
  const tokenHash = sha256Hex(rawToken);
  const now = new Date();
  const ttlMs = config.sessionTtlMinutes * 60_000;
  const expiresAt = new Date(now.getTime() + ttlMs).toISOString();

  await db.query(
    `INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      sessionId,
      userId,
      tokenHash,
      req.ip || null,
      String(req.get('user-agent') || '').slice(0, 256),
      expiresAt,
      now.toISOString(),
    ]
  );

  const csrfToken = buildSignedCsrfToken(sessionId);
  res.cookie(SESSION_COOKIE_NAME, rawToken, sessionCookieOptions(ttlMs));
  res.cookie(CSRF_COOKIE_NAME, csrfToken, csrfCookieOptions(ttlMs));
  res.clearCookie(MFA_CHALLENGE_COOKIE_NAME, { path: '/' });

  return { sessionId, csrfToken, expiresAt };
}

export async function revokeCurrentSession(req, res) {
  const rawToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (rawToken) {
    const db = await getDb();
    await db.query('DELETE FROM sessions WHERE token_hash = $1', [sha256Hex(rawToken)]);
  }
  const clearOpts = {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
  };
  res.clearCookie(SESSION_COOKIE_NAME, clearOpts);
  res.clearCookie(MFA_CHALLENGE_COOKIE_NAME, clearOpts);
  res.clearCookie(CSRF_COOKIE_NAME, {
    httpOnly: false,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
  });
}

export async function revokeAllUserSessions(userId) {
  const db = await getDb();
  await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

// OWASP A01 / A07: Fail-closed authentication middleware; verifies DB session & fresh role on every request
export async function requireAuth(req, res, next) {
  try {
    const rawToken = req.cookies?.[SESSION_COOKIE_NAME];
    if (!rawToken || typeof rawToken !== 'string') {
      return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Debes iniciar sesión.' });
    }

    const db = await getDb();
    const tokenHash = sha256Hex(rawToken);
    const result = await db.query(
      `SELECT s.id AS session_id, s.expires_at,
              u.id, u.email, u.name, u.role, u.mfa_enabled,
              u.phone_encrypted, u.phone_key_version, u.created_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1`,
      [tokenHash]
    );

    const row = result.rows[0];
    if (!row) {
      return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Sesión inválida o expirada.' });
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      await db.query('DELETE FROM sessions WHERE id = $1', [row.session_id]);
      return res.status(401).json({ error: 'SESSION_EXPIRED', message: 'Tu sesión expiró. Inicia sesión nuevamente.' });
    }

    req.session = { id: row.session_id, expiresAt: row.expires_at };
    req.user = {
      id: row.id,
      email: row.email,
      name: row.name,
      role: row.role,
      mfaEnabled: Boolean(row.mfa_enabled),
      phoneEncrypted: row.phone_encrypted,
      phoneKeyVersion: row.phone_key_version,
      createdAt: row.created_at,
    };
    return next();
  } catch (err) {
    return next(err);
  }
}

// OWASP A01: Role authorization middleware — deny by default + audit log
export function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      await recordSecurityEvent({
        eventType: 'ACCESS_DENIED',
        severity: 'warn',
        actorUserId: req.user?.id || null,
        ipAddress: req.ip,
        details: {
          requiredRoles: allowedRoles,
          actualRole: req.user?.role || 'anonymous',
          path: req.originalUrl,
          method: req.method,
        },
      });
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'No tienes permisos para acceder a este recurso.',
      });
    }
    return next();
  };
}

// State-changing requests require valid HMAC-signed CSRF token matching cookie and active session
export function requireCsrf(req, res, next) {
  const headerToken = req.get('x-csrf-token');
  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];

  if (
    !req.session?.id ||
    !headerToken ||
    !cookieToken ||
    headerToken !== cookieToken ||
    !verifySignedCsrfToken(req.session.id, headerToken)
  ) {
    recordSecurityEvent({
      eventType: 'CSRF_VALIDATION_FAILED',
      severity: 'warn',
      actorUserId: req.user?.id || null,
      ipAddress: req.ip,
      details: { path: req.originalUrl, method: req.method },
    }).catch(() => {});
    return res.status(403).json({
      error: 'CSRF_INVALID',
      message: 'Token de seguridad CSRF inválido o ausente.',
    });
  }
  return next();
}
