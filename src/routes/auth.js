import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import {
  hashPassword,
  verifyPassword,
  encrypt,
  decrypt,
  generateOpaqueToken,
  sha256Hex,
  signShortJwt,
  verifyShortJwt,
  maskSensitiveValue,
} from '../crypto/index.js';
import { generateTotpSecret, buildOtpAuthUri, verifyTotpCode } from '../crypto/totp.js';
import {
  registerSchema,
  loginSchema,
  mfaCodeSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  validateBody,
} from '../utils/validation.js';
import {
  issueFreshSession,
  revokeCurrentSession,
  revokeAllUserSessions,
  requireAuth,
  requireCsrf,
  MFA_CHALLENGE_COOKIE_NAME,
  CSRF_COOKIE_NAME,
} from '../middleware/auth.js';
import { recordSecurityEvent, checkConsecutiveFailuresAndAlert } from '../services/audit.js';

// Precomputed dummy Argon2id hash to mitigate login timing side-channel for unknown emails
let dummyHashPromise = null;
function getDummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = hashPassword('Dummy!Timing#Guard99xZ');
  }
  return dummyHashPromise;
}

export function createAuthRouter({ authRateLimiter, passwordResetCallback = null } = {}) {
  const router = Router();
  const limitAuth = authRateLimiter || ((_req, _res, next) => next());

  // RF-01: User registration (always role = 'user', Argon2id password, AES-256-GCM phone)
  router.post('/register', limitAuth, validateBody(registerSchema), async (req, res, next) => {
    try {
      const { email, name, password, phone } = req.validatedBody;
      const db = await getDb();

      const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: 'CONFLICT',
          message: 'No fue posible completar el registro con los datos proporcionados.',
        });
      }

      const id = randomUUID();
      const now = new Date().toISOString();
      const passwordHash = await hashPassword(password);

      let phoneEncrypted = null;
      let phoneKeyVersion = config.activeEncryptionKeyVersion;
      if (phone && phone.trim() !== '') {
        const enc = encrypt(phone.trim());
        phoneEncrypted = enc.payload;
        phoneKeyVersion = enc.keyVersion;
      }

      await db.query(
        `INSERT INTO users
           (id, email, name, password_hash, role, phone_encrypted, phone_key_version, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'user', $5, $6, $7, $8)`,
        [id, email, name, passwordHash, phoneEncrypted, phoneKeyVersion, now, now]
      );

      await recordSecurityEvent({
        eventType: 'REGISTER',
        severity: 'info',
        actorUserId: id,
        ipAddress: req.ip,
        details: { role: 'user' },
      });

      const { csrfToken } = await issueFreshSession(req, res, id);

      return res.status(201).json({
        user: {
          id,
          email,
          name,
          role: 'user',
          mfaEnabled: false,
          phoneMasked: phone && phone.trim() !== '' ? maskSensitiveValue(phone.trim()) : null,
        },
        csrfToken,
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-02 + A07: Login with progressive lockout, generic errors, session regeneration, optional MFA
  router.post('/login', limitAuth, validateBody(loginSchema), async (req, res, next) => {
    try {
      const { email, password } = req.validatedBody;
      const db = await getDb();

      const result = await db.query(
        `SELECT id, email, name, password_hash, role, phone_encrypted, phone_key_version,
                mfa_enabled, failed_login_attempts, locked_until
         FROM users
         WHERE email = $1`,
        [email]
      );

      const user = result.rows[0];
      if (!user) {
        // Equalize timing even when email does not exist
        await verifyPassword(await getDummyHash(), password);
        await recordSecurityEvent({
          eventType: 'LOGIN_FAILED',
          severity: 'warn',
          ipAddress: req.ip,
          details: { reason: 'invalid_credentials' },
        });
        await checkConsecutiveFailuresAndAlert(req.ip, email);
        return res.status(401).json({
          error: 'INVALID_CREDENTIALS',
          message: 'Correo o contraseña inválidos.',
        });
      }

      // Check progressive account lockout
      if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
        await recordSecurityEvent({
          eventType: 'LOGIN_LOCKED',
          severity: 'warn',
          actorUserId: user.id,
          ipAddress: req.ip,
          details: { lockedUntil: user.locked_until },
        });
        return res.status(429).json({
          error: 'ACCOUNT_LOCKED',
          message: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intenta más tarde.',
        });
      }

      const valid = await verifyPassword(user.password_hash, password);
      if (!valid) {
        const attempts = Number(user.failed_login_attempts || 0) + 1;
        const shouldLock = attempts >= config.accountLockoutThreshold;
        const lockedUntil = shouldLock
          ? new Date(Date.now() + config.accountLockoutMinutes * 60_000).toISOString()
          : null;

        await db.query(
          `UPDATE users
           SET failed_login_attempts = $1, locked_until = $2, updated_at = $3
           WHERE id = $4`,
          [attempts, lockedUntil, new Date().toISOString(), user.id]
        );

        await recordSecurityEvent({
          eventType: shouldLock ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILED',
          severity: shouldLock ? 'critical' : 'warn',
          actorUserId: user.id,
          ipAddress: req.ip,
          details: { attempts, locked: shouldLock },
        });
        await checkConsecutiveFailuresAndAlert(req.ip, user.email);

        return res.status(shouldLock ? 429 : 401).json({
          error: shouldLock ? 'ACCOUNT_LOCKED' : 'INVALID_CREDENTIALS',
          message: shouldLock
            ? 'Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intenta más tarde.'
            : 'Correo o contraseña inválidos.',
        });
      }

      // Reset failure counter on valid password
      await db.query(
        `UPDATE users
         SET failed_login_attempts = 0, locked_until = NULL, updated_at = $1
         WHERE id = $2`,
        [new Date().toISOString(), user.id]
      );

      // If MFA TOTP is enabled, issue a short-lived HS256 challenge cookie (5 min)
      if (user.mfa_enabled) {
        const challengeJwt = signShortJwt({ sub: user.id, purpose: 'mfa_login' }, 300);
        res.cookie(MFA_CHALLENGE_COOKIE_NAME, challengeJwt, {
          httpOnly: true,
          secure: config.cookieSecure,
          sameSite: 'strict',
          path: '/',
          maxAge: 300_000,
        });
        return res.status(200).json({
          mfaRequired: true,
          message: 'Ingresa el código de 6 dígitos de tu aplicación autenticadora.',
        });
      }

      const { csrfToken } = await issueFreshSession(req, res, user.id);

      await recordSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        severity: 'info',
        actorUserId: user.id,
        ipAddress: req.ip,
        details: { mfa: false },
      });

      const phoneMasked = user.phone_encrypted
        ? maskSensitiveValue(decrypt(user.phone_encrypted, user.phone_key_version))
        : null;

      return res.status(200).json({
        mfaRequired: false,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          mfaEnabled: false,
          phoneMasked,
        },
        csrfToken,
      });
    } catch (err) {
      return next(err);
    }
  });

  // Bonus: Complete login with 6-digit TOTP code
  router.post('/mfa/login', limitAuth, validateBody(mfaCodeSchema), async (req, res, next) => {
    try {
      const challengeCookie = req.cookies?.[MFA_CHALLENGE_COOKIE_NAME];
      const payload = verifyShortJwt(challengeCookie);
      if (!payload || payload.purpose !== 'mfa_login' || !payload.sub) {
        return res.status(401).json({
          error: 'MFA_CHALLENGE_INVALID',
          message: 'Desafío MFA inválido o expirado. Inicia sesión nuevamente.',
        });
      }

      const db = await getDb();
      const result = await db.query(
        `SELECT id, email, name, role, phone_encrypted, phone_key_version,
                mfa_secret_encrypted, mfa_key_version, mfa_enabled
         FROM users WHERE id = $1`,
        [payload.sub]
      );
      const user = result.rows[0];
      if (!user || !user.mfa_enabled || !user.mfa_secret_encrypted) {
        return res.status(401).json({
          error: 'MFA_CHALLENGE_INVALID',
          message: 'No fue posible validar el segundo factor.',
        });
      }

      const secret = decrypt(user.mfa_secret_encrypted, user.mfa_key_version);
      if (!verifyTotpCode(secret, req.validatedBody.code)) {
        await recordSecurityEvent({
          eventType: 'MFA_FAILED',
          severity: 'warn',
          actorUserId: user.id,
          ipAddress: req.ip,
          details: { stage: 'login' },
        });
        return res.status(401).json({
          error: 'INVALID_MFA_CODE',
          message: 'Código de verificación incorrecto o expirado.',
        });
      }

      const { csrfToken } = await issueFreshSession(req, res, user.id);

      await recordSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        severity: 'info',
        actorUserId: user.id,
        ipAddress: req.ip,
        details: { mfa: true },
      });

      const phoneMasked = user.phone_encrypted
        ? maskSensitiveValue(decrypt(user.phone_encrypted, user.phone_key_version))
        : null;

      return res.status(200).json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          mfaEnabled: true,
          phoneMasked,
        },
        csrfToken,
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-02: Logout (invalidates server session immediately)
  router.post('/logout', requireAuth, requireCsrf, async (req, res, next) => {
    try {
      await recordSecurityEvent({
        eventType: 'LOGOUT',
        severity: 'info',
        actorUserId: req.user.id,
        ipAddress: req.ip,
        details: {},
      });
      await revokeCurrentSession(req, res);
      return res.status(200).json({ ok: true, message: 'Sesión cerrada correctamente.' });
    } catch (err) {
      return next(err);
    }
  });

  // Current session state
  router.get('/me', requireAuth, (req, res) => {
    const phoneMasked = req.user.phoneEncrypted
      ? maskSensitiveValue(decrypt(req.user.phoneEncrypted, req.user.phoneKeyVersion))
      : null;

    return res.status(200).json({
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        role: req.user.role,
        mfaEnabled: req.user.mfaEnabled,
        phoneMasked,
        createdAt: req.user.createdAt,
      },
      csrfToken: req.cookies?.[CSRF_COOKIE_NAME] || null,
      sessionExpiresAt: req.session.expiresAt,
    });
  });

  // RF-06: Request password recovery (32 random bytes, SHA-256 hash in DB, 15m TTL, single-use)
  router.post(
    '/forgot-password',
    limitAuth,
    validateBody(forgotPasswordSchema),
    async (req, res, next) => {
      try {
        const { email } = req.validatedBody;
        const db = await getDb();
        const result = await db.query('SELECT id, email FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (user) {
          const rawToken = generateOpaqueToken(32); // 256-bit cryptographically secure random token
          const tokenHash = sha256Hex(rawToken);
          const now = new Date();
          const expiresAt = new Date(now.getTime() + 15 * 60_000).toISOString();

          // Invalidate previous unused tokens for this user
          await db.query(
            'DELETE FROM password_reset_tokens WHERE user_id = $1 AND used_at IS NULL',
            [user.id]
          );

          await db.query(
            `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
             VALUES ($1, $2, $3, $4, NULL, $5)`,
            [randomUUID(), user.id, tokenHash, expiresAt, now.toISOString()]
          );

          await recordSecurityEvent({
            eventType: 'PASSWORD_RESET_REQUESTED',
            severity: 'info',
            actorUserId: user.id,
            ipAddress: req.ip,
            details: { expiresInMinutes: 15 }, // NEVER log the raw token!
          });

          if (typeof passwordResetCallback === 'function') {
            await passwordResetCallback({ email: user.email, token: rawToken, expiresAt });
          }
        }

        // Always return generic 200 to prevent account enumeration
        return res.status(200).json({
          ok: true,
          message:
            'Si el correo está registrado, recibirás instrucciones de recuperación válidas por 15 minutos.',
        });
      } catch (err) {
        return next(err);
      }
    }
  );

  // RF-06: Complete password recovery (verifies SHA-256 hash, expiry, single-use, revokes sessions)
  router.post(
    '/reset-password',
    limitAuth,
    validateBody(resetPasswordSchema),
    async (req, res, next) => {
      try {
        const { token, newPassword } = req.validatedBody;
        const tokenHash = sha256Hex(token);
        const db = await getDb();

        const resToken = await db.query(
          `SELECT id, user_id, expires_at, used_at
           FROM password_reset_tokens
           WHERE token_hash = $1`,
          [tokenHash]
        );
        const row = resToken.rows[0];

        if (!row || row.used_at || new Date(row.expires_at).getTime() <= Date.now()) {
          return res.status(400).json({
            error: 'INVALID_RESET_TOKEN',
            message: 'El token de recuperación es inválido, ya fue utilizado o expiró.',
          });
        }

        const newHash = await hashPassword(newPassword);
        const now = new Date().toISOString();

        await db.transaction(async (tx) => {
          await tx.query('UPDATE password_reset_tokens SET used_at = $1 WHERE id = $2', [
            now,
            row.id,
          ]);
          await tx.query(
            `UPDATE users
             SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL, updated_at = $2
             WHERE id = $3`,
            [newHash, now, row.user_id]
          );
          await tx.query('DELETE FROM sessions WHERE user_id = $1', [row.user_id]);
        });

        await recordSecurityEvent({
          eventType: 'PASSWORD_RESET_COMPLETED',
          severity: 'info',
          actorUserId: row.user_id,
          ipAddress: req.ip,
          details: { sessionsRevoked: true },
        });

        return res.status(200).json({
          ok: true,
          message: 'Contraseña actualizada correctamente. Inicia sesión con tu nueva contraseña.',
        });
      } catch (err) {
        return next(err);
      }
    }
  );

  // Bonus: MFA TOTP setup (generates secret, stores encrypted pending verification)
  router.post('/mfa/setup', requireAuth, requireCsrf, async (req, res, next) => {
    try {
      const secret = generateTotpSecret();
      const encrypted = encrypt(secret);
      const db = await getDb();

      await db.query(
        `UPDATE users
         SET mfa_secret_encrypted = $1, mfa_key_version = $2, mfa_enabled = 0, updated_at = $3
         WHERE id = $4`,
        [encrypted.payload, encrypted.keyVersion, new Date().toISOString(), req.user.id]
      );

      const otpauthUri = buildOtpAuthUri({ secret, email: req.user.email });
      return res.status(200).json({
        secret,
        otpauthUri,
        message: 'Registra esta clave en tu app autenticadora y confirma con un código de 6 dígitos.',
      });
    } catch (err) {
      return next(err);
    }
  });

  // Bonus: Confirm and enable MFA TOTP
  router.post(
    '/mfa/enable',
    requireAuth,
    requireCsrf,
    validateBody(mfaCodeSchema),
    async (req, res, next) => {
      try {
        const db = await getDb();
        const result = await db.query(
          'SELECT mfa_secret_encrypted, mfa_key_version FROM users WHERE id = $1',
          [req.user.id]
        );
        const row = result.rows[0];
        if (!row?.mfa_secret_encrypted) {
          return res.status(400).json({
            error: 'MFA_NOT_INITIALIZED',
            message: 'Primero genera una clave TOTP desde configuración.',
          });
        }

        const secret = decrypt(row.mfa_secret_encrypted, row.mfa_key_version);
        if (!verifyTotpCode(secret, req.validatedBody.code)) {
          await recordSecurityEvent({
            eventType: 'MFA_FAILED',
            severity: 'warn',
            actorUserId: req.user.id,
            ipAddress: req.ip,
            details: { stage: 'enable' },
          });
          return res.status(400).json({
            error: 'INVALID_MFA_CODE',
            message: 'Código TOTP inválido. Verifica la hora de tu dispositivo e intenta otra vez.',
          });
        }

        await db.query('UPDATE users SET mfa_enabled = 1, updated_at = $1 WHERE id = $2', [
          new Date().toISOString(),
          req.user.id,
        ]);

        await recordSecurityEvent({
          eventType: 'MFA_ENABLED',
          severity: 'info',
          actorUserId: req.user.id,
          ipAddress: req.ip,
          details: {},
        });

        return res.status(200).json({ ok: true, mfaEnabled: true });
      } catch (err) {
        return next(err);
      }
    }
  );

  // Bonus: Disable MFA TOTP (requires valid TOTP code + revokes other sessions)
  router.post(
    '/mfa/disable',
    requireAuth,
    requireCsrf,
    validateBody(mfaCodeSchema),
    async (req, res, next) => {
      try {
        const db = await getDb();
        const result = await db.query(
          'SELECT mfa_secret_encrypted, mfa_key_version, mfa_enabled FROM users WHERE id = $1',
          [req.user.id]
        );
        const row = result.rows[0];
        if (!row?.mfa_enabled || !row.mfa_secret_encrypted) {
          return res.status(400).json({
            error: 'MFA_NOT_ENABLED',
            message: 'La verificación en dos pasos no está activa.',
          });
        }

        const secret = decrypt(row.mfa_secret_encrypted, row.mfa_key_version);
        if (!verifyTotpCode(secret, req.validatedBody.code)) {
          return res.status(400).json({
            error: 'INVALID_MFA_CODE',
            message: 'Código TOTP incorrecto.',
          });
        }

        await db.query(
          `UPDATE users
           SET mfa_enabled = 0, mfa_secret_encrypted = NULL, updated_at = $1
           WHERE id = $2`,
          [new Date().toISOString(), req.user.id]
        );

        await recordSecurityEvent({
          eventType: 'MFA_DISABLED',
          severity: 'warn',
          actorUserId: req.user.id,
          ipAddress: req.ip,
          details: {},
        });

        return res.status(200).json({ ok: true, mfaEnabled: false });
      } catch (err) {
        return next(err);
      }
    }
  );

  return router;
}
