import { randomUUID } from 'node:crypto';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { safeOutboundPost } from '../utils/ssrf.js';

const FORBIDDEN_DETAIL_KEYS = new Set([
  'password',
  'passwordHash',
  'password_hash',
  'token',
  'resetToken',
  'sessionToken',
  'content',
  'content_encrypted',
  'phone',
  'phone_encrypted',
  'mfaSecret',
  'secret',
]);

function sanitizeDetails(details = {}) {
  const safe = {};
  for (const [k, v] of Object.entries(details)) {
    if (FORBIDDEN_DETAIL_KEYS.has(k)) continue;
    safe[k] = v;
  }
  return safe;
}

export async function recordSecurityEvent({
  eventType,
  severity = 'info',
  actorUserId = null,
  targetUserId = null,
  ipAddress = null,
  details = {},
}) {
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  const safeDetails = sanitizeDetails(details);

  const logEntry = {
    eventId: id,
    eventType,
    severity,
    actorUserId,
    targetUserId,
    ipAddress,
    details: safeDetails,
  };

  if (severity === 'critical') {
    logger.error(logEntry, `Security event: ${eventType}`);
  } else if (severity === 'warn') {
    logger.warn(logEntry, `Security event: ${eventType}`);
  } else {
    logger.info(logEntry, `Security event: ${eventType}`);
  }

  try {
    const db = await getDb();
    await db.query(
      `INSERT INTO security_events
         (id, event_type, severity, actor_user_id, target_user_id, ip_address, details_json, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, eventType, severity, actorUserId, targetUserId, ipAddress, JSON.stringify(safeDetails), createdAt]
    );
  } catch (err) {
    logger.error({ err: { message: err.message } }, 'Failed to persist security event');
  }

  return id;
}

export async function triggerSecurityAlert({ alertType, severity = 'warn', summary, ipAddress = null }) {
  const id = randomUUID();
  const createdAt = new Date().toISOString();

  logger.warn({ alertId: id, alertType, severity, summary, ipAddress }, 'SECURITY ALERT TRIGGERED');

  try {
    const db = await getDb();
    await db.query(
      `INSERT INTO security_alerts (id, alert_type, severity, summary, ip_address, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 'open', $6)`,
      [id, alertType, severity, summary, ipAddress, createdAt]
    );
  } catch (err) {
    logger.error({ err: { message: err.message } }, 'Failed to persist security alert');
  }

  if (config.alertWebhookUrl) {
    try {
      await safeOutboundPost(config.alertWebhookUrl, {
        text: `[SecureVault ${severity.toUpperCase()}] ${alertType}: ${summary} (IP: ${ipAddress || 'unknown'})`,
        alertId: id,
        alertType,
        severity,
        timestamp: createdAt,
      });
    } catch (err) {
      logger.warn(
        { alertId: id, reason: err.message },
        'External alert webhook dispatch blocked or failed'
      );
    }
  }

  return id;
}

export async function checkConsecutiveFailuresAndAlert(ipAddress, emailHint) {
  const db = await getDb();
  const cutoff = new Date(Date.now() - 15 * 60_000).toISOString();
  const res = await db.query(
    `SELECT COUNT(*) AS count
     FROM security_events
     WHERE event_type = 'LOGIN_FAILED'
       AND ip_address = $1
       AND created_at >= $2`,
    [ipAddress || 'unknown', cutoff]
  );
  const count = Number(res.rows[0]?.count || 0);
  if (count >= config.alertFailedLoginThreshold && count % config.alertFailedLoginThreshold === 0) {
    await triggerSecurityAlert({
      alertType: 'BRUTE_FORCE_DETECTED',
      severity: 'critical',
      summary: `${count} intentos fallidos de inicio de sesión en 15 min desde IP ${ipAddress || 'desconocida'} (objetivo: ${emailHint || 'varios'})`,
      ipAddress,
    });
  }
}
