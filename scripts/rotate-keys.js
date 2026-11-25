import { getDb } from '../src/db/index.js';
import { runMigrations } from '../src/db/schema.js';
import { rotateAllEncryptedData } from '../src/services/keyRotation.js';

async function main() {
  const db = await getDb();
  await runMigrations(db);
  const summary = await rotateAllEncryptedData({ actorUserId: null, ipAddress: 'cli' });
  console.log('Rotación de llaves completada:', JSON.stringify(summary));
  await db.close();
}

main().catch((err) => {
  console.error('Error en rotación de llaves:', err.message);
  process.exit(1);
});
