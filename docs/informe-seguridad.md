# Fase 4 — Informe de Seguridad: SecureVault (OWASP Top 10:2025)

**Sistema:** SecureVault (Node.js 22 LTS + Express + PostgreSQL / SQLite local)  
**Estándar de referencia:** OWASP Top 10:2025  
**Fecha de verificación local:** 2026-11-25

---

## 1. Matriz de Cumplimiento OWASP Top 10:2025

| Categoría OWASP Top 10:2025 | Mitigaciones implementadas en SecureVault | Ubicación en código | Evidencia verificable |
|---|---|---|---|
| **A01:2025 Broken Access Control (incluye SSRF)** | Middleware `requireAuth` (sesión en BD) y `requireRole('admin')` con denegación por defecto; verificación estricta de propiedad en cada consulta SQL (`WHERE id = $1 AND owner_id = $2`); esquemas Zod `.strict()` que impiden *mass assignment* de `role`; protección CSRF con firma HMAC-SHA256; guardia SSRF (`validateOutboundUrl`) con HTTPS obligatorio, allowlist de dominios, resolución DNS y bloqueo de rangos privados/loopback/metadata (`169.254.169.254`, `127.0.0.1`, RFC1918, IPv6 ULA). | `src/middleware/auth.js`, `src/routes/notes.js`, `src/routes/admin.js`, `src/utils/ssrf.js` | Prueba automatizada `RF-01...A01 (IDOR & RBAC)` PASSED: usuario A recibe `404` al leer/editar/borrar nota de usuario B y se registran 3 eventos `IDOR_ATTEMPT`; acceso a `/api/admin/users` por rol `user` devuelve `403`; registro con `role: "admin"` rechazado con `400`; prueba `A01 SSRF Guard` PASSED bloqueando HTTP, IP literal, `169.254.169.254` y dominios no permitidos. |
| **A02:2025 Security Misconfiguration** | `helmet` con CSP estricta (`default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; object-src 'none'; frame-ancestors 'none'`), `app.disable('x-powered-by')`, `Permissions-Policy`, `Referrer-Policy`, `X-Frame-Options: DENY`, HSTS (`max-age=31536000; includeSubDomains; preload`) y redirección HTTP→HTTPS en producción, CORS restringido por lista blanca, `NODE_ENV=production`, `trust proxy = 1`, sin rutas de depuración y `Cache-Control: no-store` en `/api` y `/health`. | `src/middleware/security.js`, `src/app.js`, `render.yaml` | Salida real de cabeceras HTTP en Sección 3.2 (`x-powered-by: null`, CSP sin `unsafe-inline`, `x-frame-options: DENY`, `x-content-type-options: nosniff`). Lista para validación pública en `securityheaders.com` (objetivo calificación A/A+). |
| **A03:2025 Software Supply Chain Failures** | `package-lock.json` versionado en Git; instalación reproducible con `npm ci` en CI y despliegue; conjunto mínimo de 10 dependencias directas sin dependencias de desarrollo pesadas (se usa `node:test` nativo); `.github/dependabot.yml` configurado para alertas semanales en `npm` y `github-actions`; puerta obligatoria `npm audit --audit-level=high` en CI. | `package.json`, `package-lock.json`, `.github/dependabot.yml`, `.github/workflows/ci.yml` | Salida real de `npm audit --audit-level=high`: **`found 0 vulnerabilities`** (ver Sección 3.1; se detectó y corrigió `zod <4.6.6` actualizando a `zod@^4.6.7`). |
| **A04:2025 Cryptographic Failures** | **Argon2id** (`m=19456`, `t=2`, `p=1`) para contraseñas; **AES-256-GCM** con IV aleatorio de 12 bytes único por operación y tag de autenticación de 16 bytes para notas, teléfonos y secretos MFA; rotación de llaves con columna `key_version`; **SHA-256** para tokens de sesión y recuperación de 32 bytes aleatorios; llaves cargadas únicamente desde variables de entorno (fail-closed en producción); TLS obligatorio en BD (`sslmode=require`) y cookies `HttpOnly`, `Secure`, `SameSite=Strict`. | `src/crypto/index.js`, `src/config/env.js`, `src/services/keyRotation.js`, `src/db/index.js` | Inspección real de BD en Sección 3.3: `password_hash` inicia con `$argon2id$v=19$m=19456,t=2,p=1$...`; `content_encrypted` y `phone_encrypted` almacenados como `<iv>.<tag>.<data>` base64; prueba `A04 Cryptographic Primitives` PASSED verificando IV único y rechazo por alteración del ciphertext. |
| **A05:2025 Injection (incluye XSS)** | 100 % consultas SQL parametrizadas (`$1, $2` en PostgreSQL y `?` en adaptador SQLite); validación estricta de entrada con esquemas **Zod v4**; renderizado seguro del frontend usando exclusivamente `textContent` + sanitización en profundidad con **DOMPurify**; cero scripts inline y CSP que bloquea scripts inline. | `src/db/index.js`, `src/utils/validation.js`, `public/assets/app.js`, `src/middleware/security.js` | Prueba `A05 (SQLi & XSS)` PASSED: intento `' OR 1=1 --` en `/api/auth/login` rechazado con HTTP `400`; contenido con `<script>alert(1)</script>` almacenado cifrado y renderizado como texto literal inofensivo sin ejecución. |
| **A06:2025 Insecure Design** | Modelo de amenazas **STRIDE** + diagramas de arquitectura, ER y flujo de autenticación documentados; límites de negocio explícitos (`MAX_NOTES_PER_USER=50`, `MAX_NOTE_TITLE_LENGTH=150`, `MAX_NOTE_CONTENT_LENGTH=10000`, cuerpo JSON máximo `32kb`); respuestas anti-enumeración en login y recuperación de contraseña; igualación de tiempo en login con hash dummy Argon2id. | `docs/threat-model.md`, `src/routes/notes.js`, `src/routes/auth.js` | Documento completo en `docs/threat-model.md` (11 amenazas STRIDE + 4 casos de abuso) y prueba automatizada de cuota excedida devolviendo HTTP `422 BUSINESS_LIMIT_EXCEEDED`. |
| **A07:2025 Authentication Failures** | Rate limiting en `/api/auth/*` (`express-rate-limit`) devolviendo HTTP `429`; bloqueo progresivo por cuenta (`ACCOUNT_LOCKOUT_THRESHOLD=5` → bloqueo 15 min); mensajes de error genéricos; **regeneración de ID de sesión** en cada login; expiración corta de sesión (2 h); política de complejidad de contraseña (≥12 chars, mayús/minús/número/símbolo); **bonificación MFA TOTP (RFC 6238)** completa. | `src/routes/auth.js`, `src/middleware/auth.js`, `src/middleware/security.js`, `src/crypto/totp.js` | Pruebas `A07 Brute-force lockout (HTTP 429)`, `RF-06` (regeneración de sesión confirmada comparando cookies) y `Bonus MFA TOTP` PASSED. |
| **A08:2025 Software or Data Integrity Failures** | Sin deserialización insegura de objetos ni `eval`; verificación estricta de firma **JWT con algoritmo fijo `HS256`** (`verifyShortJwt` rechaza `alg: "none"` y cualquier otro algoritmo) usando `timingSafeEqual`; integridad HMAC-SHA256 en CSRF y metadatos de notas; atributo **SRI (`integrity="sha384-..."`)** verificado en el script externo de CDN (`DOMPurify`); pipeline CI en GitHub Actions con **Gitleaks**, `npm ci`, `npm audit` y `npm test` antes del despliegue. | `src/crypto/index.js`, `public/index.html`, `.github/workflows/ci.yml` | Prueba `A04/A08` PASSED verificando rechazo de JWT con `alg: "none"`; verificación en `public/index.html` de `integrity="sha384-eEu5CTj3qGvu9PdJuS+YlkNi7d2XxQROAFYOr59zgObtlcux1ae1Il3u7jvdCSWu"`; workflow CI completo en `.github/workflows/ci.yml`. |
| **A09:2025 Security Logging and Alerting Failures** | Logs estructurados en **JSON** con `pino` y redacción automática (`redact`) de contraseñas, tokens, cookies, teléfonos y contenido cifrado; filtro defensivo `FORBIDDEN_DETAIL_KEYS` antes de persistir en `security_events`; bitácora consultable y filtrable en el panel de administración; alerta automática `BRUTE_FORCE_DETECTED` tras `N` fallos consecutivos desde una IP + envío opcional a webhook externo (con guardia SSRF). | `src/utils/logger.js`, `src/services/audit.js`, `src/routes/admin.js` | Muestra real de log JSON en Sección 3.4 comprobando que la clave `password` inyectada en prueba fue eliminada automáticamente; eventos y alertas visibles en `/api/admin/audit-logs` y `/api/admin/alerts`. |
| **A10:2025 Mishandling of Exceptional Conditions** | Manejador global de errores (`globalErrorHandler`) con respuestas genéricas (`INTERNAL_ERROR` + `requestId`) sin exponer stack traces ni detalles internos; diseño *fail-closed* (falla al arrancar en producción si faltan llaves criptográficas; falla cerrado si expira sesión o falla validación); manejo de `unhandledRejection` y `uncaughtException` con apagado ordenado (`SIGTERM`/`SIGINT`); timeouts explícitos en BD (`statement_timeout`, `connectionTimeoutMillis`), HTTP server (`requestTimeout`, `headersTimeout`) y peticiones salientes (`AbortController`). | `src/middleware/security.js`, `src/server.js`, `src/db/index.js`, `src/config/env.js` | Prueba `A10 Generic error` PASSED: error forzado con cadena sensible devuelve HTTP `500` con `{ "error": "INTERNAL_ERROR", "requestId": "..." }` sin filtrar stack trace ni secretos, registrando el detalle internamente. |

---

## 2. Decisiones Criptográficas y Análisis de Gestión de Llaves

### 2.1 Matriz de algoritmos aplicados (Hash vs. Cifrado)

| Dato | Técnica | Algoritmo y parámetros | Justificación |
|---|---|---|---|
| Contraseña de usuario | Hash lento con sal | **Argon2id** (`memoryCost: 19456` [19 MiB], `timeCost: 2`, `parallelism: 1`) | Irreversible; resistente a ataques con GPU/ASIC y tablas arcoíris. Nunca se descifra, solo se verifica. |
| Contenido de notas privadas | Cifrado autenticado | **AES-256-GCM**, IV aleatorio único de 12 bytes (`randomBytes(12)`), auth tag de 16 bytes | Reversible para el dueño legítimo; GCM aporta confidencialidad + integridad/autenticidad (detecta manipulación en BD). |
| Teléfono / documento sensible y secreto TOTP | Cifrado autenticado | **AES-256-GCM** (misma utilidad con IV único y `key_version`) | Permite mostrar versión enmascarada (`***-***-1234`), revelación auditada al dueño y validación RFC 6238 en servidor. |
| Token de sesión y token de recuperación | Hash rápido | **SHA-256** de 32 bytes aleatorios (`randomBytes(32)`) | 256 bits de entropía hacen inviable la fuerza bruta sin requerir hash lento; si se filtra la BD, los hashes no sirven para autenticar. |
| Integridad de tokens CSRF, JWT corto y notas | Firma simétrica (MAC) | **HMAC-SHA256** con `timingSafeEqual` y algoritmo fijo `HS256` | Previene falsificación y ataques de tiempo o confusión de algoritmo (`alg: none`). |
| Datos en tránsito | Transporte seguro | **TLS 1.2 / 1.3** (HTTPS + HSTS en producción; `sslmode=require` hacia PostgreSQL) | Protege credenciales, cookies y payloads frente a interceptación en red. |

*Se verificó la ausencia total de algoritmos prohibidos: cero uso de MD5/SHA-1/SHA-256 para contraseñas, cero AES-ECB, cero `crypto.createCipher()`, cero reutilización de IV, cero `Math.random()` para tokens y cero llaves en el código fuente o repositorio.*

### 2.2 Preguntas de análisis (Sección 4 del laboratorio)

#### ¿Qué ocurre con los datos si se pierde la llave `DATA_ENCRYPTION_KEY`?
Si se pierde de forma definitiva la llave simétrica AES-256-GCM sin existir un respaldo cifrado seguro (p. ej. en un gestor de secretos o bóveda corporativa con custodia dividida), **todos los datos cifrados con esa llave —notas privadas, teléfonos/documentos sensibles y secretos TOTP de los usuarios— quedan criptográficamente irrecuperables de forma permanente**. Con 256 bits de entropía, ningún ataque de fuerza bruta es computacionalmente viable. Las contraseñas (almacenadas como hash Argon2id, no cifradas con esa llave) seguirían permitiendo iniciar sesión, pero cualquier intento de descifrar notas o perfiles fallaría en el servidor (*fail-closed*). Por ello, en producción la llave maestra debe respaldarse en un gestor de secretos redundante con control de acceso y política de recuperación ante desastres (KMS / Secrets Manager).

#### ¿Cómo rotarían la llave sin perder la información existente? *(Implementado en SecureVault)*
SecureVault implementa **rotación de llaves sin pérdida de datos ni tiempo de inactividad** mediante **versionado de llaves por registro** (`key_version`, `phone_key_version`, `mfa_key_version`):
1. **Generación y carga paralela:** se genera una nueva llave de 32 bytes (`npm run keygen`) y se configura en el gestor de secretos mediante `DATA_ENCRYPTION_KEYS="1:<llave_v1>,2:<llave_v2>"`, manteniendo `ACTIVE_ENCRYPTION_KEY_VERSION=1` inicialmente para validar despliegue.
2. **Activación para nuevas escrituras:** se cambia `ACTIVE_ENCRYPTION_KEY_VERSION=2`. A partir de ese instante, toda nota nueva o editada se cifra con `v2`, mientras los registros antiguos (`key_version = 1`) continúan descifrándose transparentemente con `v1`.
3. **Re-cifrado por lotes en transacción:** un administrador ejecuta `POST /api/admin/rotate-keys` (desde el panel de Administración) o `npm run rotate-keys` (`src/services/keyRotation.js`), que lee cada registro con `key_version != 2`, descifra con su versión histórica, re-cifra con `v2` generando un **nuevo IV aleatorio de 12 bytes**, actualiza el campo `key_version = 2` dentro de una transacción atómica y audita el evento `KEY_ROTATION`.
4. **Retiro seguro de la llave antigua:** una vez confirmado que no quedan filas con `key_version = 1` en `notes` ni `users`, se retira `v1` del gestor de secretos.

---

## 3. Evidencias Verificables Capturadas

### 3.1 Resultado de `npm test` y `npm audit --audit-level=high`

```text
> securevault@1.0.0 test
> node --test tests/*.test.js

✔ A04 Cryptographic Primitives: Argon2id, AES-256-GCM unique IV + tamper detection, HS256 JWT (91.75ms)
✔ A01 SSRF Guard blocks private IPs, metadata endpoints, HTTP, and non-allowlisted hosts (1.97ms)
✔ RF-08 & A02: /health hides internals and Helmet security headers are active (22.67ms)
✔ RF-01, RF-02, RF-04, RF-05, A01 (IDOR & RBAC), A05 (SQLi & XSS), A06 (Limits) (151.67ms)
✔ RF-06 Password recovery: SHA-256 hashed single-use token, expiry, and session revocation (103.66ms)
✔ Bonus MFA TOTP enrollment, login challenge, and Key Rotation (v1 -> v2) (81.39ms)
✔ A07 Brute-force lockout (HTTP 429) & Rate limiting + A09 Alert triggered + A10 Generic error (95.66ms)
ℹ tests 7 | pass 7 | fail 0

$ npm audit --audit-level=high
found 0 vulnerabilities
```

### 3.2 Verificación de `/health` y Cabeceras HTTP de Seguridad (A02 / RF-08)

```text
Status: 200 Body: {"status":"ok"}
content-security-policy: default-src 'self';script-src 'self' https://cdnjs.cloudflare.com;style-src 'self';img-src 'self' data:;font-src 'self';connect-src 'self';object-src 'none';frame-src 'none';frame-ancestors 'none';base-uri 'self';form-action 'self';worker-src 'none';manifest-src 'self'
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
x-powered-by: null
```
*(En producción con `NODE_ENV=production`, Helmet agrega automáticamente `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` y `upgrade-insecure-requests` en CSP.)*

### 3.3 Inspección de Base de Datos: Hashes Argon2id y Datos Cifrados AES-256-GCM (A04)

```json
// Fila en tabla `users` (contraseña hasheada con Argon2id y teléfono cifrado con AES-256-GCM)
{
  "email": "demo@securevault.local",
  "role": "user",
  "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$n/Sv//yZbMQgwRJPPqGavw$FQBAHgn96B4IKnrekhVGoiuoj9f7DnPaUwYnCi8kySw",
  "phone_encrypted": "0E+8msbXANL0ljPr.tCRtdsX101Xy46qjwyJIXQ==.rbVyfzAgT59IYhnHmH9YXw==",
  "phone_key_version": 1
}

// Fila en tabla `notes` (contenido ilegible: iv_12B_b64.authTag_16B_b64.ciphertext_b64)
{
  "id": "n-demo-1",
  "title": "Respaldo",
  "content_encrypted": "6nsKXtSA3f+CRQ8i.yUondsDLypEByZgdIMidOg==.WEL9zPz67AkA5ESV6XeT5zohQtyzhrExrjXmXxLA9cFm729xmx6dBRTis34=",
  "key_version": 1
}
```

### 3.4 Muestra de Log Estructurado JSON con Redacción de Secretos (A09)

Al registrar un evento `LOGIN_FAILED` que incluía intencionalmente una clave prohibida (`password`), el servicio eliminó el campo antes de emitir y persistir el evento:

```json
{"level":40,"time":"2026-11-25T16:45:41.876Z","service":"securevault","eventId":"6a199cca-74b7-49e1-b8f8-4d8757d4d5f3","eventType":"LOGIN_FAILED","severity":"warn","actorUserId":"u-demo-1","targetUserId":null,"ipAddress":"127.0.0.1","details":{"attempts":3},"msg":"Security event: LOGIN_FAILED"}
```

---

## 4. Verificaciones en la URL Pública de Producción

**URL pública de producción (Vercel + Proxy same-origin → Render → Supabase PostgreSQL TLS):**  
- **Aplicación:** https://securevault-gamma.vercel.app  
- **Backend API (Render):** https://securevault-api-zo4v.onrender.com  
- **Repositorio GitHub:** https://github.com/Osarii/securevault

### 4.1 Evidencia real ejecutada contra producción (`TARGET_URL=https://securevault-gamma.vercel.app`)

```text
=== SecureVault Post-Deploy Security Check ===
Target: https://securevault-gamma.vercel.app

[RF-08] GET /health -> 200 {"status":"ok"}

[A02] Cabeceras HTTP de seguridad:
  content-security-policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; worker-src 'none'; manifest-src 'self'; upgrade-insecure-requests
  strict-transport-security: max-age=31536000; includeSubDomains; preload
  x-content-type-options: nosniff
  x-frame-options: DENY
  referrer-policy: strict-origin-when-cross-origin
  permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
  x-powered-by: (ausente)

[A05] Intento SQLi en /api/auth/login -> 400 {"error":"VALIDATION_ERROR","message":"Correo electrónico no válido"}
[A01] Acceso anónimo a /api/admin/users -> 401 {"error":"UNAUTHENTICATED","message":"Debes iniciar sesión."}
[A08] Atributo integrity (SRI SHA-384) presente en HTML -> true
```

### 4.2 Escaneos externos recomendados para adjuntar captura en el informe final

| Herramienta | Enlace directo sobre producción | Meta esperada |
|---|---|---|
| **Security Headers** | https://securityheaders.com/?q=https%3A%2F%2Fsecurevault-gamma.vercel.app&followRedirects=on | Calificación **A / A+** |
| **Qualys SSL Labs** | https://www.ssllabs.com/ssltest/analyze.html?d=securevault-gamma.vercel.app | Calificación **A / A+** (TLS 1.2/1.3) |
| **OWASP ZAP Baseline** | Ejecutar ZAP contra `https://securevault-gamma.vercel.app` | 0 alertas High/Critical |

---

## 5. Riesgos Residuales

1. **Rate limiting en memoria en múltiples réplicas:** `express-rate-limit` utiliza almacenamiento en memoria por defecto. En una instancia única (plan Free/Starter de Render) funciona correctamente; si se escala horizontalmente a múltiples instancias, se debe migrar el store a **Redis** compartido.
2. **Títulos de notas en texto plano para búsqueda:** El contenido de las notas está cifrado con AES-256-GCM, mientras que el campo `title` se almacena en texto plano para permitir búsqueda rápida. Se advierte al usuario que coloque la información confidencial dentro del cuerpo de la nota; como mejora futura puede implementarse cifrado del título con índice ciego (*blind index* HMAC).
3. **Almacenamiento del token de recuperación sin servidor SMTP configurado:** Cuando no se configura un proveedor de correo en producción, la generación y verificación por hash SHA-256 funciona de extremo a extremo, pero la entrega por correo requiere configurar un proveedor transaccional HTTPS (p. ej. Resend) en la lista blanca saliente.
4. **Ausencia de KMS gestionado dedicado:** Aunque la llave reside en el gestor de secretos de la plataforma fuera del repositorio y cuenta con rotación versionada, en entornos empresariales regulados se recomienda *envelope encryption* con AWS KMS / GCP KMS y rotación automática programada.

---

## 6. Checklist Previo a la Entrega (Sección 10)

- [x] El archivo `.env` no aparece en ningún commit del historial (`.gitignore` + Gitleaks en CI).
- [x] `npm audit --audit-level=high` no reporta vulnerabilidades altas ni críticas (`0 vulnerabilities`).
- [x] Un usuario no puede ver, editar ni borrar notas de otro usuario (verificado por pruebas automatizadas IDOR).
- [x] Las contraseñas en la BD comienzan con `$argon2id$`.
- [x] El contenido de las notas en la BD es ilegible (`iv.tag.data` en base64).
- [x] La app fuerza HTTPS y cookies `HttpOnly`, `Secure` y `SameSite=Strict` en `NODE_ENV=production`.
- [x] Los errores muestran un mensaje genérico con `requestId`; el detalle y stack trace solo quedan en los logs internos.
- [x] El login devuelve `429` después de varios intentos fallidos (rate limit + bloqueo progresivo).
- [x] Los logs en JSON no contienen contraseñas, tokens ni datos sensibles.
- [x] El `README.md` explica cómo instalar localmente y reproducir el despliegue en producción sin exponer secretos.
