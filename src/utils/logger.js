import pino from 'pino';
import { config } from '../config/env.js';

// OWASP A09: Structured JSON logging with strict redaction of sensitive fields
export const logger = pino({
  level: config.isTest ? 'silent' : process.env.LOG_LEVEL || 'info',
  base: { service: 'securevault' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'password',
      'newPassword',
      'currentPassword',
      'token',
      'resetToken',
      'sessionToken',
      'authorization',
      'cookie',
      'phone',
      'content',
      'content_encrypted',
      'phone_encrypted',
      'mfaSecret',
      'req.headers.authorization',
      'req.headers.cookie',
      '*.password',
      '*.token',
      '*.secret',
    ],
    censor: '[REDACTED]',
  },
});
