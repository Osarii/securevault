import { randomUUID } from 'node:crypto';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { recordSecurityEvent } from '../services/audit.js';

export function requestIdMiddleware(req, res, next) {
  req.requestId = randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
}

export function enforceHttpsInProduction(req, res, next) {
  if (!config.isProduction) return next();
  // Allow platform health probes over internal HTTP
  if (req.path === '/health') return next();
  const proto = req.get('x-forwarded-proto');
  if (req.secure || proto === 'https') return next();
  const host = req.get('host');
  if (!host) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'Solicitud inválida' });
  }
  return res.redirect(301, `https://${host}${req.originalUrl}`);
}

export function buildHelmetMiddleware() {
  const directives = {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    workerSrc: ["'none'"],
    manifestSrc: ["'self'"],
  };

  if (config.isProduction) {
    directives.upgradeInsecureRequests = [];
  } else {
    directives.upgradeInsecureRequests = null;
  }

  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives,
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    frameguard: { action: 'deny' },
    hsts: config.isProduction
      ? { maxAge: 31536000, includeSubDomains: true, preload: true }
      : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true,
    xPoweredBy: false,
  });
}

export function permissionsPolicyMiddleware(_req, res, next) {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'
  );
  next();
}

export function buildCorsMiddleware() {
  return cors({
    origin(origin, callback) {
      // Allow same-origin / server-to-server requests with no Origin header
      if (!origin) return callback(null, true);
      if (config.corsAllowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      const err = new Error('CORS_NOT_ALLOWED');
      err.status = 403;
      err.publicCode = 'CORS_FORBIDDEN';
      err.publicMessage = 'Origen no autorizado';
      return callback(err);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    maxAge: 600,
  });
}

export function buildApiRateLimiter(overrides = {}) {
  return rateLimit({
    windowMs: 15 * 60_000,
    max: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: {
      error: 'TOO_MANY_REQUESTS',
      message: 'Demasiadas solicitudes. Intenta nuevamente en unos minutos.',
    },
    ...overrides,
  });
}

export function buildAuthRateLimiter(overrides = {}) {
  return rateLimit({
    windowMs: config.loginRateLimitWindowMin * 60_000,
    max: config.loginRateLimitMax,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: async (req, res) => {
      await recordSecurityEvent({
        eventType: 'RATE_LIMIT_EXCEEDED',
        severity: 'warn',
        ipAddress: req.ip,
        details: { path: req.originalUrl, method: req.method },
      });
      res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: 'Demasiados intentos de autenticación. Espera antes de volver a intentarlo.',
      });
    },
    ...overrides,
  });
}

// OWASP A10: Fail-closed global error handler — never leaks stack traces or internal details
export function globalErrorHandler(err, req, res, _next) {
  const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
  const isClientError = status < 500;

  // Handle malformed JSON body cleanly
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: 'INVALID_JSON',
      message: 'El cuerpo de la solicitud no es JSON válido.',
      requestId: req.requestId,
    });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'PAYLOAD_TOO_LARGE',
      message: 'El tamaño de la solicitud excede el límite permitido.',
      requestId: req.requestId,
    });
  }

  logger.error(
    {
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status,
      err: {
        name: err.name,
        message: err.message,
        code: err.code,
        stack: err.stack,
      },
    },
    'Unhandled request error'
  );

  if (!isClientError) {
    recordSecurityEvent({
      eventType: 'SERVER_ERROR',
      severity: 'warn',
      actorUserId: req.user?.id || null,
      ipAddress: req.ip,
      details: { requestId: req.requestId, path: req.originalUrl },
    }).catch(() => {});
  }

  return res.status(status).json({
    error: isClientError && err.publicCode ? err.publicCode : 'INTERNAL_ERROR',
    message:
      isClientError && err.publicMessage
        ? err.publicMessage
        : 'No fue posible procesar tu solicitud. Intenta nuevamente.',
    requestId: req.requestId,
  });
}
