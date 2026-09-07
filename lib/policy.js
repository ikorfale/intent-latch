import { isIP, BlockList } from 'node:net';

export const VERSION = 1;
export const TTL_MS = 120_000;
export const PUBLIC_ORIGIN = 'https://intent-latch.vercel.app';
export const DEMO_PATH = '/api/v1/demo-target';
export const ALLOWED_METHODS = new Set(['POST', 'PUT', 'PATCH']);
export const DEMO_FIELDS = new Set(['message', 'request_id']);
const DENIED_KEY = /^(?:authorization|cookie|cookies|credential|credentials|password|passwd|secret|secrets|token|tokens|apikey|apikeys|session|sessions|jwt|jwts|signature|signatures)$/;

const blocked4 = new BlockList();
const blocked6 = new BlockList();
for (const [ip, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) blocked4.addSubnet(ip, prefix, 'ipv4');
for (const [ip, prefix] of [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['2620:4f:8000::', 48],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
]) blocked6.addSubnet(ip, prefix, 'ipv6');

export function isGlobalAddress(address) {
  const family = isIP(address);
  return family !== 0 && !address.includes('%') && !(family === 4 ? blocked4.check(address, 'ipv4') : blocked6.check(address, 'ipv6'));
}

export function normalizeOrigin(raw) {
  if (typeof raw !== 'string' || raw.length > 255) throw new Error('invalid_origin');
  let url;
  try { url = new URL(raw); } catch { throw new Error('invalid_origin'); }
  if (url.protocol !== 'https:' || url.port && url.port !== '443' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('invalid_origin');
  const bareHost = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(bareHost) && !isGlobalAddress(bareHost)) throw new Error('destination_not_global');
  return `https://${url.hostname.toLowerCase()}`;
}

export function normalizePath(raw) {
  if (typeof raw !== 'string' || raw.length < 1 || raw.length > 256 || !raw.startsWith('/') || raw.includes('?') || raw.includes('#') || raw.includes('\\') || /%(?:2f|5c|2e)/i.test(raw) || /[\u0000-\u001f\u007f]/.test(raw)) throw new Error('invalid_path');
  let decoded;
  try { decoded = decodeURI(raw); } catch { throw new Error('invalid_path'); }
  if (decoded !== raw || raw.includes('//') || raw.split('/').some((x) => x === '.' || x === '..')) throw new Error('invalid_path');
  return raw;
}

export function validateBody(body, requestId) {
  if (!body || Array.isArray(body) || Object.getPrototypeOf(body) !== Object.prototype) throw new Error('invalid_body');
  const walk = (value) => {
    if (Array.isArray(value)) return value.forEach(walk);
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      const folded = key.normalize('NFKC').toLowerCase().replace(/[-_]/g, '');
      if (DENIED_KEY.test(folded)) throw new Error('sensitive_field_name');
      walk(child);
    }
  };
  walk(body);
  if (Object.keys(body).some((k) => !DEMO_FIELDS.has(k)) || typeof body.message !== 'string' || body.message.length < 1 || body.message.length > 280 || body.request_id !== requestId) throw new Error('schema_rejected');
  return body;
}

export function validateHostedTarget(origin, path) {
  if (origin !== PUBLIC_ORIGIN || path !== DEMO_PATH) throw new Error('destination_not_allowed');
}

export function validateUuidV4(value) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value || '')) throw new Error('invalid_request_id');
  return value.toLowerCase();
}
