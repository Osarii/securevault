# SecureVault

Aplicación web segura en **Node.js (22 LTS) + Express** para almacenar notas privadas cifradas y datos personales sensibles, diseñada para cumplir de forma demostrable las diez categorías del **OWASP Top 10:2025**, el uso correcto de **hash y cifrado** (Argon2id, AES-256-GCM, SHA-256, HMAC-SHA256) y el despliegue reproducible a producción con **HTTPS**.

## Características implementadas

### Requisitos funcionales (RF-01 a RF-08)
- **RF-01 Registro de usuario:** correo normalizado, nombre y contraseña con política de complejidad validada con Zod; contraseña almacenada únicamente como hash **Argon2id** (`$argon2id$`, 19 MiB, 2 iteraciones, paralelismo 1).
- **RF-02 Inicio y cierre de sesión:** cookie de sesión segura (`HttpOnly`, `Secure` en producción, `SameSite=Strict`), expiración corta configurable, **regeneración de ID de sesión** al autenticar e invalidación inmediata en base de datos al cerrar sesión. Protección CSRF con token firmado con **HMAC-SHA256**.
- **RF-03 Roles:** `user` y `admin`, verificados siempre contra la base de datos en cada solicitud protegida (principio de denegar por defecto).
- **RF-04 CRUD de notas privadas:** aislamiento estricto por propietario (`WHERE id = $1 AND owner_id = $2`), detección y registro de intentos IDOR, contenido cifrado con **AES-256-GCM** e IV aleatorio único de 12 bytes por operación.
- **RF-05 Dato sensible de perfil:** teléfono o documento almacenado cifrado con **AES-256-GCM**, mostrado enmascarado (`***-***-1234`) por defecto, con revelación temporal auditada (15 s).
- **RF-06 Recuperación de contraseña:** token aleatorio de 32 bytes (`crypto.randomBytes(32)`), expiración de 15 minutos, un solo uso; en BD se guarda únicamente su hash **SHA-256**.
- **RF-07 Panel de administración:** gestión de usuarios y roles, bitácora de eventos de seguridad filtrable, panel de alertas automáticas y rotación de llaves cifradas.
- **RF-08 Endpoint de salud:** `GET /health` responde únicamente `{ "status": "ok" }` (200) o `{ "status": "degraded" }` (503) sin revelar versiones ni detalles internos.

### Bonificaciones implementadas (+10 pts)
- **MFA con TOTP (RFC 6238):** enrollamiento, desafío en login con JWT firmado de algoritmo fijo (`HS256`) y desactivación verificada, implementado con `node:crypto` sin dependencias externas.
- **Rotación de llaves sin pérdida de datos:** columna `key_version` por registro, soporte multillave (`DATA_ENCRYPTION_KEYS`), endpoint `POST /api/admin/rotate-keys` y script `npm run rotate-keys`.
- **Escaneo de secretos en CI y alertas externas:** flujo en `.github/workflows/ci.yml` con **Gitleaks**, `npm audit --audit-level=high`, pruebas automatizadas y alertas enviables a webhook externo protegido contra SSRF.

---

## Instalación local

### Requisitos previos
- Node.js **22 LTS** o superior (`node -v`).
- Base de datos: en desarrollo local, si `DATABASE_URL` no está definida, SecureVault utiliza automáticamente SQLite integrado de Node 22 en `./data/securevault.db` con el mismo esquema parametrizado. En producción utiliza **PostgreSQL gestionado** (Neon/Render) vía `DATABASE_URL`.

### Pasos
1. Instalar dependencias reproducibles desde `package-lock.json`:
   ```bash
   npm ci
   ```
2. Crear el archivo `.env` a partir de `.env.example` (nunca subir `.env` a Git):
   ```bash
   cp .env.example .env
   ```
3. Generar las llaves criptográficas locales y pegarlas en `.env`:
   ```bash
   npm run keygen   # Copiar resultado en DATA_ENCRYPTION_KEY
   npm run keygen   # Copiar resultado en HMAC_SECRET
   ```
4. Ejecutar migraciones y (opcionalmente) poblar cuentas locales de demostración:
   ```bash
   npm run migrate
   npm run seed
   ```
5. Iniciar la aplicación:
   ```bash
   npm start
   ```
   Abrir `http://localhost:3000`.

### Pruebas y auditoría local
```bash
npm test
npm audit --audit-level=high
TARGET_URL=http://localhost:3000 npm run verify:security
```

---

## Variables de entorno requeridas (solo nombres, sin valores)

> **Importante:** Nunca almacenar valores reales ni credenciales de prueba en este `README` ni en el repositorio Git. Configurar los valores en `.env` (solo local) o en el panel de secretos de la plataforma de despliegue.

| Variable | Obligatoria en prod | Descripción |
|---|---|---|
| `NODE_ENV` | Sí (`production`) | Entorno de ejecución (`development`, `test`, `production`). |
| `PORT` | No (def. `3000`) | Puerto HTTP asignado por la plataforma. |
| `TRUST_PROXY` | Sí (`1`) | Número de proxies inversos delante de Express (`app.set('trust proxy', 1)`). |
| `CORS_ALLOWED_ORIGINS` | Sí | Lista de orígenes HTTPS permitidos separados por coma (sin `*`). |
| `DATABASE_URL` | Sí | Cadena de conexión PostgreSQL con TLS (`?sslmode=require`). |
| `SQLITE_PATH` | Solo local | Ruta del archivo SQLite cuando no se define `DATABASE_URL`. |
| `DB_SSL_REJECT_UNAUTHORIZED` | Sí (`true`) | Valida el certificado TLS del servidor PostgreSQL. |
| `DB_QUERY_TIMEOUT_MS` | No (def. `5000`) | Timeout máximo en milisegundos para consultas y conexión a BD. |
| `DATA_ENCRYPTION_KEY` | Sí* | Llave simétrica AES-256-GCM de 32 bytes en base64 (versión 1). |
| `DATA_ENCRYPTION_KEYS` | Opcional* | Mapa multillave para rotación (`1:<b64>,2:<b64>`). (*Requiere al menos una de las dos). |
| `ACTIVE_ENCRYPTION_KEY_VERSION` | Sí (`1`) | Versión activa usada al cifrar nuevos registros o rotar llaves. |
| `HMAC_SECRET` | Sí | Secreto de 32+ bytes en base64 para CSRF, HMAC y desafío JWT `HS256`. |
| `SESSION_TTL_MINUTES` | No (def. `120`) | Expiración de sesión en minutos. |
| `COOKIE_SECURE` | Sí (`true`) | Obliga envío de cookies únicamente sobre HTTPS. |
| `MAX_NOTES_PER_USER` | No (def. `50`) | Límite de negocio de notas por cuenta (OWASP A06). |
| `MAX_NOTE_TITLE_LENGTH` | No (def. `150`) | Longitud máxima del título de nota. |
| `MAX_NOTE_CONTENT_LENGTH` | No (def. `10000`) | Longitud máxima del contenido de nota. |
| `LOGIN_RATE_LIMIT_MAX` | No (def. `10`) | Máximo de intentos de autenticación por IP y ventana. |
| `LOGIN_RATE_LIMIT_WINDOW_MIN` | No (def. `15`) | Ventana de rate limiting en minutos. |
| `ACCOUNT_LOCKOUT_THRESHOLD` | No (def. `5`) | Fallos consecutivos para bloquear temporalmente una cuenta. |
| `ACCOUNT_LOCKOUT_MINUTES` | No (def. `15`) | Duración del bloqueo temporal de cuenta. |
| `ALERT_FAILED_LOGIN_THRESHOLD` | No (def. `5`) | Umbral de fallos por IP que genera una alerta de seguridad. |
| `ALERT_WEBHOOK_URL` | Opcional | Webhook HTTPS externo para envío de alertas (validado con allowlist SSRF). |
| `ALLOWED_WEBHOOK_HOSTS` | No | Lista blanca de dominios permitidos para peticiones salientes. |
| `OUTBOUND_TIMEOUT_MS` | No (def. `4000`) | Timeout para peticiones salientes. |
| `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` | Solo al ejecutar `seed` | Credenciales del administrador inicial (entregar al docente por canal privado). |
| `SEED_USER_EMAIL` / `SEED_USER_PASSWORD` | Solo al ejecutar `seed` | Credenciales del usuario estándar de prueba (entregar al docente por canal privado). |

---

## Despliegue reproducible a producción (Render + Neon PostgreSQL)

El proyecto incluye Blueprint declarativo (`render.yaml`) para Node.js nativo (sin requerir Docker) y pipeline CI/CD (`.github/workflows/ci.yml`).

### 1. Crear base de datos PostgreSQL gestionada en Neon
1. Crear un proyecto en [Neon](https://neon.tech) en la región más cercana al servicio web (p. ej. `aws-us-west-2` Oregon).
2. Copiar la cadena de conexión con TLS obligatorio (`postgresql://...?sslmode=require`).
3. (Recomendado) Crear un rol PostgreSQL de aplicación con permisos mínimos (`SELECT, INSERT, UPDATE, DELETE` sobre tablas de aplicación, sin `SUPERUSER`).

### 2. Publicar el servicio web en Render
1. Conectar el repositorio Git en [Render](https://render.com) eligiendo **Blueprint** (`render.yaml`) o **Web Service** con:
   - **Runtime:** Node 22
   - **Build Command:** `npm ci`
   - **Start Command:** `npm start`
   - **Health Check Path:** `/health`
2. En **Environment / Secret Files** de Render, configurar los secretos obligatorios:
   - `NODE_ENV=production`
   - `TRUST_PROXY=1`
   - `COOKIE_SECURE=true`
   - `DATABASE_URL` (URL de Neon con `sslmode=require`)
   - `DATA_ENCRYPTION_KEY` (generada con `npm run keygen`)
   - `HMAC_SECRET` (generada con `npm run keygen`)
   - `CORS_ALLOWED_ORIGINS=https://<tu-servicio>.onrender.com`
3. Ejecutar una única vez la creación de cuentas de prueba desde el Shell seguro de Render usando variables temporales (`SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_USER_EMAIL`, `SEED_USER_PASSWORD`) y entregar dichas credenciales al docente por **canal privado**.

### 3. Activar despliegue continuo desde GitHub Actions
1. Copiar el **Deploy Hook URL** de Render.
2. En GitHub: **Settings → Secrets and variables → Actions → New repository secret**, crear `RENDER_DEPLOY_HOOK_URL`.
3. Cada `push` a `main` ejecutará automáticamente: **Gitleaks** → `npm ci` → `npm audit --audit-level=high` → `npm test` → disparo del despliegue en producción.

### 4. Verificación posterior al despliegue
```bash
TARGET_URL=https://<tu-servicio>.onrender.com npm run verify:security
```
Complementar con los escaneos públicos documentados en [docs/informe-seguridad.md](docs/informe-seguridad.md) (`securityheaders.com`, Qualys SSL Labs y OWASP ZAP baseline scan).

---

## Documentación del laboratorio
- [Informe de Deep Research — Despliegue a Producción (Fase 0)](docs/deep-research-despliegue.md)
- [Diseño de Arquitectura y Modelo de Amenazas STRIDE (Fase 1 / A06)](docs/threat-model.md)
- [Informe de Seguridad OWASP Top 10:2025 y Evidencias (Fase 4)](docs/informe-seguridad.md)
- [Guión de Demostración en Vivo (10 minutos)](docs/guia-demostracion.md)
