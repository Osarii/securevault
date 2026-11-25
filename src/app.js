import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config/env.js';
import { getDb } from './db/index.js';
import {
  requestIdMiddleware,
  enforceHttpsInProduction,
  buildHelmetMiddleware,
  permissionsPolicyMiddleware,
  buildCorsMiddleware,
  buildApiRateLimiter,
  buildAuthRateLimiter,
  globalErrorHandler,
} from './middleware/security.js';
import { createAuthRouter } from './routes/auth.js';
import { createNotesRouter } from './routes/notes.js';
import { createProfileRouter } from './routes/profile.js';
import { createAdminRouter } from './routes/admin.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');

export function createApp(options = {}) {
  const app = express();

  // OWASP A02: Disable X-Powered-By header and configure trust proxy accurately
  app.disable('x-powered-by');
  if (config.trustProxy > 0) {
    app.set('trust proxy', config.trustProxy);
  }

  app.use(requestIdMiddleware);
  app.use(enforceHttpsInProduction);
  app.use(buildHelmetMiddleware());
  app.use(permissionsPolicyMiddleware);
  app.use(buildCorsMiddleware());
  app.use(express.json({ limit: '32kb', strict: true }));
  app.use(cookieParser());

  // RF-08: Health endpoint — responds with status ONLY, zero versions or internal data
  app.get('/health', async (_req, res) => {
    try {
      const db = await getDb();
      await Promise.race([
        db.ping(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('DB_HEALTH_TIMEOUT')), config.dbQueryTimeoutMs)
        ),
      ]);
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json({ status: 'ok' });
    } catch {
      res.setHeader('Cache-Control', 'no-store');
      return res.status(503).json({ status: 'degraded' });
    }
  });

  // Prevent browser/proxy caching of sensitive API responses
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next();
  });

  const apiLimiter = options.apiRateLimiter || buildApiRateLimiter();
  const authLimiter = options.authRateLimiter || buildAuthRateLimiter();

  app.use('/api', apiLimiter);
  app.use(
    '/api/auth',
    createAuthRouter({
      authRateLimiter: authLimiter,
      passwordResetCallback: options.passwordResetCallback || null,
    })
  );
  app.use('/api/notes', createNotesRouter());
  app.use('/api/profile', createProfileRouter());
  app.use('/api/admin', createAdminRouter());

  // Optional test-only hook (never mounted outside NODE_ENV=test)
  if (options.enableErrorTestRoute && config.isTest) {
    app.get('/api/_test/boom', () => {
      throw new Error('SENSITIVE_DB_CONNECTION_STRING_SHOULD_NOT_LEAK');
    });
  }

  // Static frontend assets
  app.use(
    express.static(PUBLIC_DIR, {
      etag: true,
      maxAge: config.isProduction ? '1h' : 0,
      dotfiles: 'ignore',
    })
  );

  // Explicit 404 for unknown /api routes (deny by default)
  app.use('/api', (_req, res) => {
    return res.status(404).json({
      error: 'NOT_FOUND',
      message: 'Recurso no encontrado.',
    });
  });

  // SPA fallback to index.html for frontend routes
  app.get('*', (_req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  });

  // OWASP A10: Global fail-closed error handler
  app.use(globalErrorHandler);

  return app;
}
