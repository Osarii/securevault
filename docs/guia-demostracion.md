# Guión de Demostración en Vivo (10 minutos) — SecureVault

Este guión cubre el recorrido completo de **SecureVault** en producción (o entorno local) y la demostración verificable de **cinco ataques bloqueados en vivo**.

---

## Minuto 0:00 – 1:30 | Arquitectura, HTTPS y Salud del Servicio (RF-08 / A02)
1. Abrir la URL pública HTTPS de **SecureVault** (`https://<tu-app>.onrender.com`).
2. Mostrar en el navegador el candado TLS 1.3 y verificar en terminal que HTTP redirige a HTTPS (`301`) y `/health` responde únicamente `{"status":"ok"}` sin `X-Powered-By`:
   ```bash
   curl -i https://<tu-app>.onrender.com/health
   ```
3. Destacar en las cabeceras de respuesta: `Content-Security-Policy` (sin `unsafe-inline`), `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y `Permissions-Policy`.

## Minuto 1:30 – 3:30 | Flujo Funcional Completo (RF-01 a RF-06 + Bonus MFA)
1. Registrar un nuevo usuario desde la pestaña **Crear cuenta** mostrando la validación en vivo de política de complejidad de contraseña (12+ chars, mayúscula, minúscula, número, símbolo) y el campo sensible de teléfono.
2. Crear una nota privada en **Notas privadas**, editarla y verificar en **Perfil y seguridad** que el teléfono aparece enmascarado (`***-***-1234`); pulsar **Revelar** para mostrar la revelación temporal (15 s) auditada.
3. Activar **MFA TOTP (RFC 6238)** desde el sheet deslizable, mostrar el secreto Base32 / URI `otpauth://` y explicar que se guarda cifrado con AES-256-GCM.
4. Inspeccionar en la consola de base de datos (Neon/SQLite) que:
   - `password_hash` inicia con `$argon2id$`.
   - `content_encrypted` y `phone_encrypted` son ilegibles (`<iv>.<tag>.<ciphertext>` en base64).

## Minuto 3:30 – 7:30 | Demostración de 5 Ataques Bloqueados en Vivo

### Ataque 1 — IDOR Horizontal (OWASP A01)
- Con sesión del **Usuario A**, intentar leer y borrar la nota de **Usuario B** usando su UUID:
  ```bash
  curl -i -b cookies_userA.txt https://<tu-app>.onrender.com/api/notes/<UUID_NOTA_USER_B>
  ```
- **Resultado esperado:** HTTP `404 Not Found` (sin revelar existencia) y registro automático del evento crítico `IDOR_ATTEMPT` en la bitácora.

### Ataque 2 — Escalación de Privilegios / Mass Assignment y RBAC (OWASP A01)
- Intentar registrarse enviando `"role": "admin"` en el cuerpo JSON:
  ```bash
  curl -i -X POST https://<tu-app>.onrender.com/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"name":"Atacante","email":"atk@test.com","password":"Atk!Password2026","role":"admin"}'
  ```
- **Resultado esperado:** HTTP `400 Bad Request` (esquema Zod `.strict()` rechaza campos no permitidos).
- Con sesión de usuario estándar, intentar acceder a `GET /api/admin/users` → HTTP `403 Forbidden` + evento `ACCESS_DENIED`.

### Ataque 3 — Inyección SQL y XSS Almacenado (OWASP A05)
- Enviar payload SQLi al endpoint de login:
  ```bash
  curl -i -X POST https://<tu-app>.onrender.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"'\'' OR 1=1 --","password":"x"}'
  ```
- **Resultado esperado:** HTTP `400 Bad Request` (rechazado por validación Zod; además todas las consultas usan parámetros `$1, $2`).
- Crear una nota con contenido `<script>alert('XSS')</script><img src=x onerror=alert(1)>`: mostrar en el navegador que se renderiza como texto literal inofensivo (sin ejecución), protegido por `textContent`, DOMPurify con SRI y CSP estricta.

### Ataque 4 — Fuerza Bruta en Login (OWASP A07 + A09)
- Enviar múltiples intentos fallidos consecutivos contra `/api/auth/login`:
  ```bash
  for i in $(seq 1 12); do
    curl -s -o /dev/null -w "Intento $i -> HTTP %{http_code}\n" \
      -X POST https://<tu-app>.onrender.com/api/auth/login \
      -H "Content-Type: application/json" \
      -d '{"email":"usuario@ejemplo.com","password":"WrongPassword!123"}'
  done
  ```
- **Resultado esperado:** Los primeros intentos devuelven `401` con mensaje genérico; al alcanzar el umbral, la cuenta se bloquea y el rate limiter responde **HTTP `429 Too Many Requests`**, disparando una alerta crítica `BRUTE_FORCE_DETECTED`.

### Ataque 5 — Falsificación de Petición sin CSRF (OWASP A01/A08)
- Intentar crear una nota con la cookie de sesión válida pero omitiendo la cabecera `X-CSRF-Token`:
  ```bash
  curl -i -b cookies_userA.txt -X POST https://<tu-app>.onrender.com/api/notes \
    -H "Content-Type: application/json" \
    -d '{"title":"CSRF","content":"Intento sin token"}'
  ```
- **Resultado esperado:** HTTP `403 Forbidden` (`CSRF_INVALID`).

## Minuto 7:30 – 9:00 | Panel de Administración, Bitácora y Rotación de Llaves (RF-07 / A09 / Bonus)
1. Iniciar sesión con la cuenta **Administrador** (entregada al docente por canal privado).
2. Abrir **Administración → Bitácora**: mostrar en vivo todos los eventos generados durante los ataques (`IDOR_ATTEMPT`, `ACCESS_DENIED`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `RATE_LIMIT_EXCEEDED`), comprobando que ningún evento contiene contraseñas, tokens ni texto plano de notas.
3. Abrir **Alertas y llaves**: mostrar la alerta `BRUTE_FORCE_DETECTED` y el control de rotación de llaves cifradas (`key_version`).

## Minuto 9:00 – 10:00 | Cadena de Suministro, CI/CD y Cierre (A03 / A08)
1. Mostrar `.github/workflows/ci.yml` (Gitleaks + `npm ci` + `npm audit` + `npm test` + deploy), `.github/dependabot.yml` y el resultado de `npm audit` con **0 vulnerabilidades**.
2. Responder preguntas del docente sobre decisiones criptográficas y riesgos residuales.
