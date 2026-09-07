export const SECURITY_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, max-age=0',
  'CDN-Cache-Control': 'no-store',
  'Vercel-CDN-Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'Content-Disposition': 'attachment',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive'
});

export function sendJson(res, status, value, extra = {}) {
  const payload = JSON.stringify(value);
  res.statusCode = status;
  for (const [name, val] of Object.entries({ ...SECURITY_HEADERS, ...extra })) res.setHeader(name, val);
  res.setHeader('Content-Length', Buffer.byteLength(payload));
  res.end(payload);
}

export function errorJson(res, status, code) {
  sendJson(res, status, { error: code });
}

export function methodGuard(req, res, allowed) {
  if (req.method === 'HEAD' || req.method === 'OPTIONS') {
    res.setHeader('Allow', allowed.join(', '));
    errorJson(res, 405, 'method_not_allowed');
    return false;
  }
  if (!allowed.includes(req.method)) {
    res.setHeader('Allow', allowed.join(', '));
    errorJson(res, 405, 'method_not_allowed');
    return false;
  }
  return true;
}

export function isPrefetch(req) {
  for (const name of ['purpose', 'sec-purpose', 'x-purpose']) {
    const value = req.headers?.[name];
    if (typeof value === 'string' && /(?:prefetch|prerender)/i.test(value)) return true;
  }
  return false;
}

export async function readStrictBody(req, maxBytes) {
  const type = String(req.headers?.['content-type'] || '').toLowerCase();
  if (type !== 'application/json') throw new HttpError(415, 'unsupported_content_type');
  const declared = req.headers?.['content-length'];
  if (declared && (!/^\d+$/.test(String(declared)) || Number(declared) > maxBytes)) throw new HttpError(413, 'request_too_large');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'request_too_large');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new HttpError(400, 'invalid_json'); }
}

export class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
