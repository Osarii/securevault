import http from 'node:http';
import { config } from './config/env.js';
import { getDb } from './db/index.js';
import { runMigrations } from './db/schema.js';
import { createApp } from './app.js';
import { logger } from './utils/logger.js';

let server = null;

async function shutdown(signal, exitCode = 0) {
  logger.info({ signal }, 'Shutting down SecureVault gracefully');
  if (server) {
    await new Promise((resolve) => server.close(() => resolve()));
  }
  try {
    const db = await getDb();
    await db.close();
  } catch (err) {
    logger.error({ err: { message: err.message } }, 'Error closing database connection');
  }
  process.exit(exitCode);
}

// OWASP A10: Handle unhandledRejection and uncaughtException deterministically (fail closed)
process.on('unhandledRejection', (reason) => {
  logger.fatal(
    { err: reason instanceof Error ? { message: reason.message, stack: reason.stack } : { reason } },
    'Unhandled Promise Rejection — exiting cleanly for restart'
  );
  shutdown('unhandledRejection', 1);
});

process.on('uncaughtException', (err) => {
  logger.fatal({ err: { message: err.message, stack: err.stack } }, 'Uncaught Exception — exiting cleanly');
  shutdown('uncaughtException', 1);
});

process.on('SIGTERM', () => shutdown('SIGTERM', 0));
process.on('SIGINT', () => shutdown('SIGINT', 0));

async function main() {
  const db = await getDb();
  await runMigrations(db);

  const app = createApp();
  server = http.createServer(app);

  // Harden HTTP server timeouts (mitigate Slowloris / hanging sockets - OWASP A10)
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;

  server.listen(config.port, () => {
    logger.info(
      {
        env: config.nodeEnv,
        port: config.port,
        dbDialect: db.dialect,
        activeKeyVersion: config.activeEncryptionKeyVersion,
      },
      'SecureVault server listening'
    );
  });
}

main().catch((err) => {
  logger.fatal({ err: { message: err.message, stack: err.stack } }, 'Fatal startup failure');
  process.exit(1);
});
