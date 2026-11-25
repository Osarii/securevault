// Script de verificación de seguridad post-despliegue (local o producción HTTPS)
// Uso: TARGET_URL=https://tu-app.onrender.com node scripts/verify-security.js

const target = (process.env.TARGET_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');

async function run() {
  console.log(`\n=== SecureVault Post-Deploy Security Check ===\nTarget: ${target}\n`);

  const healthRes = await fetch(`${target}/health`);
  const healthJson = await healthRes.json();
  console.log('[RF-08] GET /health ->', healthRes.status, JSON.stringify(healthJson));

  const headersToInspect = [
    'content-security-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
    'x-powered-by',
  ];
  console.log('\n[A02] Cabeceras HTTP de seguridad:');
  for (const h of headersToInspect) {
    console.log(`  ${h}: ${healthRes.headers.get(h) ?? '(ausente)'}`);
  }

  // A05 SQLi check against login
  const sqliRes = await fetch(`${target}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: "' OR 1=1 --", password: 'x' }),
  });
  console.log('\n[A05] Intento SQLi en /api/auth/login ->', sqliRes.status, await sqliRes.text());

  // A01 Unauthenticated access to admin panel
  const adminRes = await fetch(`${target}/api/admin/users`);
  console.log('[A01] Acceso anónimo a /api/admin/users ->', adminRes.status, await adminRes.text());

  // A08 SRI verification in index.html
  const html = await (await fetch(`${target}/`)).text();
  const hasSri = /integrity="sha384-[A-Za-z0-9+/=]+"/.test(html);
  console.log('[A08] Atributo integrity (SRI SHA-384) presente en HTML ->', hasSri);

  console.log('\nVerificación completada.');
}

run().catch((err) => {
  console.error('Error ejecutando verificación:', err.message);
  process.exit(1);
});
