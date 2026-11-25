import { Router } from 'express';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import { decrypt, maskSensitiveValue } from '../crypto/index.js';
import { roleUpdateSchema, validateBody } from '../utils/validation.js';
import { requireAuth, requireRole, requireCsrf } from '../middleware/auth.js';
import { recordSecurityEvent } from '../services/audit.js';
import { rotateAllEncryptedData } from '../services/keyRotation.js';

export function createAdminRouter() {
  const router = Router();
  // RF-03 + RF-07 + A01: Every admin route enforces authentication and server-side 'admin' role
  router.use(requireAuth, requireRole('admin'));

  // List users (never exposes password hashes or plaintext sensitive fields)
  router.get('/users', async (_req, res, next) => {
    try {
      const db = await getDb();
      const result = await db.query(
        `SELECT id, email, name, role, phone_encrypted, phone_key_version,
                mfa_enabled, failed_login_attempts, locked_until, created_at
         FROM users
         ORDER BY created_at DESC`
      );

      const users = result.rows.map((u) => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        mfaEnabled: Boolean(u.mfa_enabled),
        phoneMasked: u.phone_encrypted
          ? maskSensitiveValue(decrypt(u.phone_encrypted, u.phone_key_version))
          : null,
        failedLoginAttempts: Number(u.failed_login_attempts || 0),
        lockedUntil: u.locked_until,
        createdAt: u.created_at,
      }));

      return res.status(200).json({
        users,
        activeEncryptionKeyVersion: config.activeEncryptionKeyVersion,
        loadedKeyVersions: Array.from(config.encryptionKeys.keys()).sort((a, b) => a - b),
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-03 + RF-07: Change user role with audit logging and last-admin safeguard
  router.patch(
    '/users/:id/role',
    requireCsrf,
    validateBody(roleUpdateSchema),
    async (req, res, next) => {
      try {
        const targetId = req.params.id;
        const { role: nextRole } = req.validatedBody;
        const db = await getDb();

        const targetRes = await db.query('SELECT id, email, role FROM users WHERE id = $1', [
          targetId,
        ]);
        const target = targetRes.rows[0];
        if (!target) {
          return res.status(404).json({ error: 'NOT_FOUND', message: 'Usuario no encontrado.' });
        }

        if (target.role === 'admin' && nextRole === 'user') {
          const adminsRes = await db.query("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");
          if (Number(adminsRes.rows[0]?.count || 0) <= 1) {
            return res.status(400).json({
              error: 'LAST_ADMIN',
              message: 'No puedes degradar al último administrador del sistema.',
            });
          }
        }

        await db.query('UPDATE users SET role = $1, updated_at = $2 WHERE id = $3', [
          nextRole,
          new Date().toISOString(),
          targetId,
        ]);

        await recordSecurityEvent({
          eventType: 'ROLE_CHANGED',
          severity: 'warn',
          actorUserId: req.user.id,
          targetUserId: targetId,
          ipAddress: req.ip,
          details: { previousRole: target.role, newRole: nextRole },
        });

        return res.status(200).json({
          ok: true,
          user: { id: target.id, email: target.email, role: nextRole },
        });
      } catch (err) {
        return next(err);
      }
    }
  );

  // RF-07 + A09: Security audit log
  router.get('/audit-logs', async (req, res, next) => {
    try {
      const db = await getDb();
      const rawLimit = Number.parseInt(String(req.query.limit || '100'), 10);
      const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 250) : 100;
      const eventType = typeof req.query.eventType === 'string' ? req.query.eventType.trim() : '';

      let result;
      if (eventType) {
        result = await db.query(
          `SELECT e.id, e.event_type, e.severity, e.actor_user_id, e.target_user_id,
                  e.ip_address, e.details_json, e.created_at, u.email AS actor_email
           FROM security_events e
           LEFT JOIN users u ON u.id = e.actor_user_id
           WHERE e.event_type = $1
           ORDER BY e.created_at DESC
           LIMIT $2`,
          [eventType, limit]
        );
      } else {
        result = await db.query(
          `SELECT e.id, e.event_type, e.severity, e.actor_user_id, e.target_user_id,
                  e.ip_address, e.details_json, e.created_at, u.email AS actor_email
           FROM security_events e
           LEFT JOIN users u ON u.id = e.actor_user_id
           ORDER BY e.created_at DESC
           LIMIT $1`,
          [limit]
        );
      }

      const events = result.rows.map((e) => ({
        id: e.id,
        eventType: e.event_type,
        severity: e.severity,
        actorUserId: e.actor_user_id,
        actorEmail: e.actor_email || null,
        targetUserId: e.target_user_id,
        ipAddress: e.ip_address,
        details: JSON.parse(e.details_json || '{}'),
        createdAt: e.created_at,
      }));

      return res.status(200).json({ events });
    } catch (err) {
      return next(err);
    }
  });

  // A09: Security alerts panel
  router.get('/alerts', async (_req, res, next) => {
    try {
      const db = await getDb();
      const result = await db.query(
        `SELECT id, alert_type, severity, summary, ip_address, status, created_at
         FROM security_alerts
         ORDER BY created_at DESC
         LIMIT 50`
      );

      return res.status(200).json({
        alerts: result.rows.map((a) => ({
          id: a.id,
          alertType: a.alert_type,
          severity: a.severity,
          summary: a.summary,
          ipAddress: a.ip_address,
          status: a.status,
          createdAt: a.created_at,
        })),
      });
    } catch (err) {
      return next(err);
    }
  });

  router.patch('/alerts/:id/ack', requireCsrf, async (req, res, next) => {
    try {
      const db = await getDb();
      const result = await db.query(
        "UPDATE security_alerts SET status = 'acknowledged' WHERE id = $1",
        [req.params.id]
      );
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Alerta no encontrada.' });
      }
      return res.status(200).json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  // Bonus: On-demand cryptographic key rotation to ACTIVE_ENCRYPTION_KEY_VERSION
  router.post('/rotate-keys', requireCsrf, async (req, res, next) => {
    try {
      const summary = await rotateAllEncryptedData({
        actorUserId: req.user.id,
        ipAddress: req.ip,
      });
      return res.status(200).json({ ok: true, summary });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}
