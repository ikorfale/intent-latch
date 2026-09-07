import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalJson, decodeBase64urlJson, parseStrictJson } from './strict-json.js';
import { ALLOWED_METHODS, DEMO_PATH, PUBLIC_ORIGIN, TTL_MS, VERSION, normalizeOrigin, normalizePath, validateBody, validateHostedTarget, validateUuidV4 } from './policy.js';
import { HttpError } from './http.js';

const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const MAP = {
  invalid_origin: [400, 'invalid_origin'], destination_not_global: [403, 'destination_not_global'], invalid_path: [400, 'invalid_path'],
  invalid_request_id: [400, 'invalid_request_id'], invalid_body: [400, 'invalid_body'], sensitive_field_name: [400, 'sensitive_field_name'],
  schema_rejected: [400, 'schema_rejected'], destination_not_allowed: [403, 'destination_not_allowed']
};
const mapError = (error) => {
  if (error instanceof HttpError) return error;
  const [status, code] = MAP[error.message] || [400, 'invalid_request'];
  return new HttpError(status, code);
};

export function parsePrepareQuery(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 8192) throw new HttpError(414, 'uri_too_long');
  const q = rawUrl.indexOf('?');
  const raw = q < 0 ? '' : rawUrl.slice(q + 1);
  const entries = raw === '' ? [] : raw.split('&').map((part) => {
    const split = part.indexOf('=');
    if (split < 0) throw new HttpError(400, 'invalid_query');
    try { return [decodeURIComponent(part.slice(0, split).replace(/\+/g, ' ')), decodeURIComponent(part.slice(split + 1).replace(/\+/g, ' '))]; }
    catch { throw new HttpError(400, 'invalid_query'); }
  });
  const expected = new Set(['origin', 'path', 'method', 'request_id', 'body']);
  const params = {};
  for (const [key, value] of entries) {
    if (!expected.has(key)) throw new HttpError(400, 'unknown_parameter');
    if (Object.hasOwn(params, key)) throw new HttpError(400, 'duplicate_parameter');
    params[key] = value;
  }
  if (Object.keys(params).length !== expected.size) throw new HttpError(400, 'missing_parameter');
  return params;
}

export function prepare(rawUrl, { now = Date.now(), publicOrigin = PUBLIC_ORIGIN } = {}) {
  try {
    const params = parsePrepareQuery(rawUrl);
    const origin = normalizeOrigin(params.origin);
    const path = normalizePath(params.path);
    const method = params.method;
    if (!ALLOWED_METHODS.has(method)) throw new HttpError(400, 'method_not_allowed');
    const requestId = validateUuidV4(params.request_id);
    validateHostedTarget(origin, path);
    const decoded = decodeBase64urlJson(params.body, 4096);
    const body = validateBody(decoded.value, requestId);
    const canonicalBody = canonicalJson(body);
    if (Buffer.byteLength(canonicalBody) > 4096) throw new HttpError(413, 'body_too_large');
    const intent = {
      version: VERSION,
      origin,
      path,
      method,
      request_id: requestId,
      body,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + TTL_MS).toISOString(),
      policy: 'hosted-demo-v1'
    };
    const requestDigest = sha256(canonicalJson(intent));
    return {
      intent,
      request_digest: requestDigest,
      expires_at: intent.expires_at,
      review: {
        dispatch_performed: false,
        input_confidential: false,
        warning: 'Prepare URL input is public and may appear in browser, CDN, or Vercel logs. Never include secrets or personal data.',
        idempotency_limit: 'The deterministic key only helps when the destination enforces it. A timeout means outcome unknown.'
      },
      commit_template: {
        method: 'POST',
        url: `${publicOrigin}/api/v1/commit`,
        headers: { 'Content-Type': 'application/json' },
        body: { intent, confirmation: requestDigest }
      }
    };
  } catch (error) { throw mapError(error); }
}

export function validateCommitText(text, { now = Date.now() } = {}) {
  let parsed;
  try { parsed = parseStrictJson(text); } catch { throw new HttpError(400, 'invalid_json'); }
  if (!parsed || Array.isArray(parsed) || Object.keys(parsed).sort().join(',') !== 'confirmation,intent' || typeof parsed.confirmation !== 'string') throw new HttpError(400, 'invalid_commit');
  const intent = parsed.intent;
  if (!intent || Array.isArray(intent) || Object.keys(intent).sort().join(',') !== 'body,expires_at,issued_at,method,origin,path,policy,request_id,version') throw new HttpError(400, 'invalid_intent');
  let origin, path, requestId;
  try {
    if (intent.version !== VERSION || intent.policy !== 'hosted-demo-v1') throw new Error('invalid_intent');
    origin = normalizeOrigin(intent.origin); path = normalizePath(intent.path); requestId = validateUuidV4(intent.request_id);
    if (!ALLOWED_METHODS.has(intent.method)) throw new Error('invalid_intent');
    validateHostedTarget(origin, path); validateBody(intent.body, requestId);
  } catch (error) { throw mapError(error); }
  const issued = Date.parse(intent.issued_at), expires = Date.parse(intent.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires - issued !== TTL_MS || issued > now + 5_000 || expires <= now) throw new HttpError(400, 'intent_expired');
  const digest = sha256(canonicalJson(intent));
  const a = Buffer.from(digest), b = Buffer.from(parsed.confirmation);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new HttpError(400, 'digest_mismatch');
  return { intent: { ...intent, origin, path, request_id: requestId }, digest };
}

export function demoTarget(origin = PUBLIC_ORIGIN) {
  return { origin, path: DEMO_PATH };
}
