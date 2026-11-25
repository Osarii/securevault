import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import { encrypt, decrypt, hmacSign } from '../crypto/index.js';
import { noteCreateSchema, noteUpdateSchema, validateBody } from '../utils/validation.js';
import { requireAuth, requireCsrf } from '../middleware/auth.js';
import { recordSecurityEvent } from '../services/audit.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function serializeNote(row) {
  const content = decrypt(row.content_encrypted, row.key_version);
  return {
    id: row.id,
    title: row.title,
    content,
    keyVersion: row.key_version,
    integrityMac: hmacSign(`${row.id}:${row.owner_id}:${row.updated_at}`),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function createNotesRouter() {
  const router = Router();
  router.use(requireAuth);

  // RF-04: List ONLY the authenticated user's notes (WHERE owner_id = $1)
  router.get('/', async (req, res, next) => {
    try {
      const db = await getDb();
      const result = await db.query(
        `SELECT id, owner_id, title, content_encrypted, key_version, created_at, updated_at
         FROM notes
         WHERE owner_id = $1
         ORDER BY updated_at DESC`,
        [req.user.id]
      );

      return res.status(200).json({
        notes: result.rows.map(serializeNote),
        limits: {
          maxNotes: config.maxNotesPerUser,
          maxTitleLength: config.maxNoteTitleLength,
          maxContentLength: config.maxNoteContentLength,
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-04 + A01: Read single note with strict ownership check (prevents IDOR)
  router.get('/:id', async (req, res, next) => {
    try {
      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      const db = await getDb();
      const result = await db.query(
        `SELECT id, owner_id, title, content_encrypted, key_version, created_at, updated_at
         FROM notes
         WHERE id = $1 AND owner_id = $2`,
        [id, req.user.id]
      );

      if (result.rows.length === 0) {
        // Check silently if the note exists for another owner purely to log IDOR attempt (without revealing it to caller!)
        const existsCheck = await db.query('SELECT id FROM notes WHERE id = $1', [id]);
        if (existsCheck.rows.length > 0) {
          await recordSecurityEvent({
            eventType: 'IDOR_ATTEMPT',
            severity: 'critical',
            actorUserId: req.user.id,
            ipAddress: req.ip,
            details: { resource: 'note', noteId: id, action: 'read' },
          });
        }
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      return res.status(200).json({ note: serializeNote(result.rows[0]) });
    } catch (err) {
      return next(err);
    }
  });

  // RF-04 + A04 + A06: Create encrypted note enforcing business limits
  router.post('/', requireCsrf, validateBody(noteCreateSchema), async (req, res, next) => {
    try {
      const db = await getDb();
      const countRes = await db.query('SELECT COUNT(*) AS count FROM notes WHERE owner_id = $1', [
        req.user.id,
      ]);
      const currentCount = Number(countRes.rows[0]?.count || 0);

      if (currentCount >= config.maxNotesPerUser) {
        return res.status(422).json({
          error: 'BUSINESS_LIMIT_EXCEEDED',
          message: `Alcanzaste el límite máximo de ${config.maxNotesPerUser} notas privadas.`,
        });
      }

      const id = randomUUID();
      const now = new Date().toISOString();
      const { title, content } = req.validatedBody;
      const encrypted = encrypt(content);

      await db.query(
        `INSERT INTO notes (id, owner_id, title, content_encrypted, key_version, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, req.user.id, title, encrypted.payload, encrypted.keyVersion, now, now]
      );

      return res.status(201).json({
        note: {
          id,
          title,
          content,
          keyVersion: encrypted.keyVersion,
          integrityMac: hmacSign(`${id}:${req.user.id}:${now}`),
          createdAt: now,
          updatedAt: now,
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-04 + A01 + A04: Update ONLY owned note (re-encrypts with fresh random 12-byte IV)
  router.patch('/:id', requireCsrf, validateBody(noteUpdateSchema), async (req, res, next) => {
    try {
      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      const db = await getDb();
      const existingRes = await db.query(
        `SELECT id, owner_id, title, content_encrypted, key_version, created_at
         FROM notes
         WHERE id = $1 AND owner_id = $2`,
        [id, req.user.id]
      );

      if (existingRes.rows.length === 0) {
        const existsCheck = await db.query('SELECT id FROM notes WHERE id = $1', [id]);
        if (existsCheck.rows.length > 0) {
          await recordSecurityEvent({
            eventType: 'IDOR_ATTEMPT',
            severity: 'critical',
            actorUserId: req.user.id,
            ipAddress: req.ip,
            details: { resource: 'note', noteId: id, action: 'update' },
          });
        }
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      const existing = existingRes.rows[0];
      const nextTitle = req.validatedBody.title ?? existing.title;
      const nextPlainContent =
        req.validatedBody.content ?? decrypt(existing.content_encrypted, existing.key_version);
      // Always generate a fresh unique IV on update (and upgrade to active key version)
      const encrypted = encrypt(nextPlainContent);
      const updatedAt = new Date().toISOString();

      await db.query(
        `UPDATE notes
         SET title = $1, content_encrypted = $2, key_version = $3, updated_at = $4
         WHERE id = $5 AND owner_id = $6`,
        [nextTitle, encrypted.payload, encrypted.keyVersion, updatedAt, id, req.user.id]
      );

      return res.status(200).json({
        note: {
          id,
          title: nextTitle,
          content: nextPlainContent,
          keyVersion: encrypted.keyVersion,
          integrityMac: hmacSign(`${id}:${req.user.id}:${updatedAt}`),
          createdAt: existing.created_at,
          updatedAt,
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-04 + A01: Delete ONLY owned note
  router.delete('/:id', requireCsrf, async (req, res, next) => {
    try {
      const { id } = req.params;
      if (!UUID_REGEX.test(id)) {
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      const db = await getDb();
      const del = await db.query('DELETE FROM notes WHERE id = $1 AND owner_id = $2', [
        id,
        req.user.id,
      ]);

      if (del.rowCount === 0) {
        const existsCheck = await db.query('SELECT id FROM notes WHERE id = $1', [id]);
        if (existsCheck.rows.length > 0) {
          await recordSecurityEvent({
            eventType: 'IDOR_ATTEMPT',
            severity: 'critical',
            actorUserId: req.user.id,
            ipAddress: req.ip,
            details: { resource: 'note', noteId: id, action: 'delete' },
          });
        }
        return res.status(404).json({ error: 'NOT_FOUND', message: 'Nota no encontrada.' });
      }

      return res.status(200).json({ ok: true, deletedId: id });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}
