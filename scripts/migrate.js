import { getDb } from '../src/db/index.js';
import { runMigrations } from '../src/db/schema.js';
import { logger } from '../src/utils/logger.js';

async function main() {
  const db = await getDb();
  await runMigrations(db);
  logger.info({ dialect: db.dialect }, 'Database schema migrations applied successfully');
  await db.close();
}

main().catch((err) => {
  logger.error({ err: { message: err.message } }, 'Migration failed');
  process.exit(1);
});
