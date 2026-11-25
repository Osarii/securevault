import { z } from 'zod';
import { config } from '../config/env.js';

export const passwordSchema = z
  .string()
  .min(12, 'La contraseña debe tener al menos 12 caracteres')
  .max(128, 'La contraseña no puede superar 128 caracteres')
  .regex(/[A-Z]/, 'Debe incluir al menos una letra mayúscula')
  .regex(/[a-z]/, 'Debe incluir al menos una letra minúscula')
  .regex(/[0-9]/, 'Debe incluir al menos un número')
  .regex(/[^A-Za-z0-9]/, 'Debe incluir al menos un carácter especial');

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('Correo electrónico no válido')
  .max(254, 'Correo electrónico demasiado largo');

export const phoneSchema = z
  .string()
  .trim()
  .min(7, 'El dato sensible debe tener al menos 7 caracteres')
  .max(32, 'El dato sensible no puede superar 32 caracteres')
  .regex(/^[A-Za-z0-9+\-\s()]+$/, 'Solo se permiten letras, dígitos, +, -, paréntesis y espacios');

export const registerSchema = z
  .object({
    email: emailSchema,
    name: z
      .string()
      .trim()
      .min(2, 'El nombre debe tener al menos 2 caracteres')
      .max(80, 'El nombre no puede superar 80 caracteres'),
    password: passwordSchema,
    phone: phoneSchema.optional().or(z.literal('')),
  })
  .strict(); // Rejects mass assignment fields like { role: "admin" }!

export const loginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1, 'Contraseña requerida').max(128),
  })
  .strict();

export const mfaCodeSchema = z
  .object({
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, 'El código TOTP debe tener exactamente 6 dígitos'),
  })
  .strict();

export const noteCreateSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, 'El título es obligatorio')
      .max(config.maxNoteTitleLength, `El título no puede superar ${config.maxNoteTitleLength} caracteres`),
    content: z
      .string()
      .min(1, 'El contenido es obligatorio')
      .max(
        config.maxNoteContentLength,
        `El contenido no puede superar ${config.maxNoteContentLength} caracteres`
      ),
  })
  .strict();

export const noteUpdateSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, 'El título es obligatorio')
      .max(config.maxNoteTitleLength, `El título no puede superar ${config.maxNoteTitleLength} caracteres`)
      .optional(),
    content: z
      .string()
      .min(1, 'El contenido es obligatorio')
      .max(
        config.maxNoteContentLength,
        `El contenido no puede superar ${config.maxNoteContentLength} caracteres`
      )
      .optional(),
  })
  .strict()
  .refine((data) => data.title !== undefined || data.content !== undefined, {
    message: 'Debes enviar al menos título o contenido para actualizar',
  });

export const profileUpdateSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'El nombre debe tener al menos 2 caracteres')
      .max(80, 'El nombre no puede superar 80 caracteres')
      .optional(),
    phone: phoneSchema.optional().or(z.literal('')),
  })
  .strict();

export const forgotPasswordSchema = z
  .object({
    email: emailSchema,
  })
  .strict();

export const resetPasswordSchema = z
  .object({
    token: z
      .string()
      .trim()
      .regex(/^[a-f0-9]{64}$/i, 'Token de recuperación con formato inválido'),
    newPassword: passwordSchema,
  })
  .strict();

export const roleUpdateSchema = z
  .object({
    role: z.enum(['user', 'admin'], { message: 'Rol inválido (solo user o admin)' }),
  })
  .strict();

export function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({
        field: i.path.join('.') || 'body',
        message: i.message,
      }));
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: issues[0]?.message || 'Datos de entrada inválidos',
        details: issues,
      });
    }
    req.validatedBody = parsed.data;
    return next();
  };
}
