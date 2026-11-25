import dns from 'node:dns/promises';
import net from 'node:net';
import { config } from '../config/env.js';

function isPrivateOrReservedIpv4(ip) {
  const parts = ip.split('.').map((n) => Number.parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isPrivateOrReservedIpv6(ip) {
  const normalized = ip.toLowerCase();
  if (normalized === '::1' || normalized === '::') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // ULA fc00::/7
  if (normalized.startsWith('fe80')) return true; // Link-local fe80::/10
  if (normalized.startsWith('::ffff:')) {
    const v4 = normalized.slice('::ffff:'.length);
    if (net.isIPv4(v4)) return isPrivateOrReservedIpv4(v4);
  }
  return false;
}

export function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateOrReservedIpv4(ip);
  if (version === 6) return isPrivateOrReservedIpv6(ip);
  return true; // Fail closed on unparseable IP
}

// OWASP A01 (SSRF) + A10 (Timeout): validate outbound URL against allowlist and block private IPs
export async function validateOutboundUrl(rawUrl, allowedHosts = config.allowedWebhookHosts) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('SSRF_BLOCKED: Invalid URL syntax');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('SSRF_BLOCKED: Only HTTPS outbound requests are permitted');
  }

  if (parsed.username || parsed.password) {
    throw new Error('SSRF_BLOCKED: Credentials in outbound URL are forbidden');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (net.isIP(hostname) !== 0) {
    throw new Error('SSRF_BLOCKED: Direct IP literal URLs are forbidden');
  }

  const hostAllowed = allowedHosts.some(
    (allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`)
  );
  if (!hostAllowed) {
    throw new Error(`SSRF_BLOCKED: Host "${hostname}" is not in the outbound allowlist`);
  }

  // Resolve DNS to prevent DNS rebinding to internal/metadata networks
  const records = await dns.lookup(hostname, { all: true });
  if (!records.length) {
    throw new Error('SSRF_BLOCKED: Hostname failed DNS resolution');
  }
  for (const record of records) {
    if (isPrivateIp(record.address)) {
      throw new Error('SSRF_BLOCKED: Target resolved to private or reserved IP range');
    }
  }

  return parsed.toString();
}

export async function safeOutboundPost(rawUrl, body, allowedHosts = config.allowedWebhookHosts) {
  const safeUrl = await validateOutboundUrl(rawUrl, allowedHosts);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.outboundTimeoutMs);

  try {
    const response = await fetch(safeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error', // Prevent redirect-based SSRF bypasses
      signal: controller.signal,
    });
    return { ok: response.ok, status: response.status };
  } finally {
    clearTimeout(timeout);
  }
}
