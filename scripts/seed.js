import { randomUUID, randomBytes } from 'node:crypto';
import { getDb } from '../src/db/index.js';
import { runMigrations } from '../src/db/schema.js';
import { hashPassword, encrypt } from '../src/crypto/index.js';
import { config } from '../src/config/env.js';

function randomStrongPassword() {
  return `Sv!${randomBytes(9).toString('base64url')}9A`;
}

async function upsertSeedUser(db, { email, name, password, role, phone }) {
  const existing = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (existing.rows.length > 0) {
    return { created: false, id: existing.rows[0].id };
  }

  const id = randomUUID();
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(password);
  const encPhone = phone ? encrypt(phone) : null;

  await db.query(
    `INSERT INTO users
       (id, email, name, password_hash, role, phone_encrypted, phone_key_version, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      id,
      email.toLowerCase(),
      name,
      passwordHash,
      role,
      encPhone ? encPhone.payload : null,
      encPhone ? encPhone.keyVersion : config.activeEncryptionKeyVersion,
      now,
      now,
    ]
  );

  return { created: true, id };
}

async function main() {
  const db = await getDb();
  await runMigrations(db);

  const adminEmail = process.env.SEED_ADMIN_EMAIL || 'admin@securevault.local';
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || randomStrongPassword();
  const userEmail = process.env.SEED_USER_EMAIL || 'usuario@securevault.local';
  const userPassword = process.env.SEED_USER_PASSWORD || randomStrongPassword();

  const adminRes = await upsertSeedUser(db, {
    email: adminEmail,
    name: 'Administradora de Seguridad',
    password: adminPassword,
    role: 'admin',
    phone: '+52-555-842-9104',
  });

  const userRes = await upsertSeedUser(db, {
    email: userEmail,
    name: 'Elena Morales',
    password: userPassword,
    role: 'user',
    phone: '+52-555-319-4482',
  });

  if (userRes.created) {
    const now = new Date().toISOString();
    const encNote = encrypt(
      'Llaves de respaldo de recuperación física guardadas en caja fuerte institucional. Revisar rotación semestral.'
    );
    await db.query(
      `INSERT INTO notes (id, owner_id, title, content_encrypted, key_version, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        randomUUID(),
        userRes.id,
        'Protocolo de respaldo personal',
        encNote.payload,
        encNote.keyVersion,
        now,
        now,
      ]
    );
  }

  console.log('Seed completado.');
  if (!config.isProduction) {
    if (adminRes.created) {
      console.log(`Admin creado -> email: ${adminEmail} | password: ${adminPassword}`);
    } else {
      console.log(`Admin ya existía -> email: ${adminEmail}`);
    }
    if (userRes.created) {
      console.log(`Usuario creado -> email: ${userEmail} | password: ${userPassword}`);
    } else {
      console.log(`Usuario ya existía -> email: ${userEmail}`);
    }
  }

  await db.close();
}

main().catch((err) => {
  console.error('Error al ejecutar seed:', err.message);
  process.exit(1);
});
