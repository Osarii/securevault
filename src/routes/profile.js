import { Router } from 'express';
import { getDb } from '../db/index.js';
import { encrypt, decrypt, maskSensitiveValue } from '../crypto/index.js';
import { profileUpdateSchema, validateBody } from '../utils/validation.js';
import { requireAuth, requireCsrf } from '../middleware/auth.js';
import { recordSecurityEvent } from '../services/audit.js';

export function createProfileRouter() {
  const router = Router();
  router.use(requireAuth);

  // RF-05: Return profile with sensitive field masked (***-***-1234)
  router.get('/', (req, res) => {
    const decryptedPhone = req.user.phoneEncrypted
      ? decrypt(req.user.phoneEncrypted, req.user.phoneKeyVersion)
      : null;

    return res.status(200).json({
      profile: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        role: req.user.role,
        mfaEnabled: req.user.mfaEnabled,
        phoneMasked: maskSensitiveValue(decryptedPhone),
        hasSensitiveData: Boolean(decryptedPhone),
        phoneKeyVersion: req.user.phoneEncrypted ? req.user.phoneKeyVersion : null,
        createdAt: req.user.createdAt,
      },
    });
  });

  // RF-05: Update name or sensitive phone/document (encrypted with AES-256-GCM)
  router.patch('/', requireCsrf, validateBody(profileUpdateSchema), async (req, res, next) => {
    try {
      const db = await getDb();
      const nextName = req.validatedBody.name ?? req.user.name;
      let nextPhoneEncrypted = req.user.phoneEncrypted;
      let nextPhoneKeyVersion = req.user.phoneKeyVersion || 1;
      let masked = null;

      if (req.validatedBody.phone !== undefined) {
        if (req.validatedBody.phone === '') {
          nextPhoneEncrypted = null;
        } else {
          const enc = encrypt(req.validatedBody.phone);
          nextPhoneEncrypted = enc.payload;
          nextPhoneKeyVersion = enc.keyVersion;
          masked = maskSensitiveValue(req.validatedBody.phone);
        }
      } else if (nextPhoneEncrypted) {
        masked = maskSensitiveValue(decrypt(nextPhoneEncrypted, nextPhoneKeyVersion));
      }

      await db.query(
        `UPDATE users
         SET name = $1, phone_encrypted = $2, phone_key_version = $3, updated_at = $4
         WHERE id = $5`,
        [nextName, nextPhoneEncrypted, nextPhoneKeyVersion, new Date().toISOString(), req.user.id]
      );

      return res.status(200).json({
        profile: {
          id: req.user.id,
          email: req.user.email,
          name: nextName,
          role: req.user.role,
          mfaEnabled: req.user.mfaEnabled,
          phoneMasked: masked,
          hasSensitiveData: Boolean(nextPhoneEncrypted),
          phoneKeyVersion: nextPhoneEncrypted ? nextPhoneKeyVersion : null,
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  // RF-05: Audited reveal of the owner's own decrypted sensitive field
  router.post('/reveal', requireCsrf, async (req, res, next) => {
    try {
      if (!req.user.phoneEncrypted) {
        return res.status(404).json({
          error: 'NO_SENSITIVE_DATA',
          message: 'No tienes un dato sensible registrado en tu perfil.',
        });
      }

      const value = decrypt(req.user.phoneEncrypted, req.user.phoneKeyVersion);
      await recordSecurityEvent({
        eventType: 'SENSITIVE_DATA_REVEALED',
        severity: 'info',
        actorUserId: req.user.id,
        ipAddress: req.ip,
        details: { field: 'phone' }, // Never log the value itself!
      });

      return res.status(200).json({ phone: value });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}
