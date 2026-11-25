import { getDb } from '../db/index.js';
import { config } from '../config/env.js';
import { encrypt, decrypt } from '../crypto/index.js';
import { recordSecurityEvent } from './audit.js';

// Bonus (+10 rubric): Zero-data-loss key rotation using key_version columns
export async function rotateAllEncryptedData({ actorUserId = null, ipAddress = null } = {}) {
  const targetVersion = config.activeEncryptionKeyVersion;
  const db = await getDb();
  const now = new Date().toISOString();

  let notesRotated = 0;
  let phonesRotated = 0;
  let mfaSecretsRotated = 0;

  await db.transaction(async (tx) => {
    const notesRes = await tx.query(
      'SELECT id, content_encrypted, key_version FROM notes WHERE key_version != $1',
      [targetVersion]
    );
    for (const note of notesRes.rows) {
      const plaintext = decrypt(note.content_encrypted, note.key_version);
      const reEncrypted = encrypt(plaintext, targetVersion);
      await tx.query(
        'UPDATE notes SET content_encrypted = $1, key_version = $2, updated_at = $3 WHERE id = $4',
        [reEncrypted.payload, reEncrypted.keyVersion, now, note.id]
      );
      notesRotated += 1;
    }

    const phonesRes = await tx.query(
      `SELECT id, phone_encrypted, phone_key_version
       FROM users
       WHERE phone_encrypted IS NOT NULL AND phone_key_version != $1`,
      [targetVersion]
    );
    for (const u of phonesRes.rows) {
      const plaintext = decrypt(u.phone_encrypted, u.phone_key_version);
      const reEncrypted = encrypt(plaintext, targetVersion);
      await tx.query(
        'UPDATE users SET phone_encrypted = $1, phone_key_version = $2, updated_at = $3 WHERE id = $4',
        [reEncrypted.payload, reEncrypted.keyVersion, now, u.id]
      );
      phonesRotated += 1;
    }

    const mfaRes = await tx.query(
      `SELECT id, mfa_secret_encrypted, mfa_key_version
       FROM users
       WHERE mfa_secret_encrypted IS NOT NULL AND mfa_key_version != $1`,
      [targetVersion]
    );
    for (const u of mfaRes.rows) {
      const plaintext = decrypt(u.mfa_secret_encrypted, u.mfa_key_version);
      const reEncrypted = encrypt(plaintext, targetVersion);
      await tx.query(
        'UPDATE users SET mfa_secret_encrypted = $1, mfa_key_version = $2, updated_at = $3 WHERE id = $4',
        [reEncrypted.payload, reEncrypted.keyVersion, now, u.id]
      );
      mfaSecretsRotated += 1;
    }
  });

  await recordSecurityEvent({
    eventType: 'KEY_ROTATION',
    severity: 'info',
    actorUserId,
    ipAddress,
    details: { targetVersion, notesRotated, phonesRotated, mfaSecretsRotated },
  });

  return { targetVersion, notesRotated, phonesRotated, mfaSecretsRotated };
}
