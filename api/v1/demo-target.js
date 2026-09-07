import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalJson, parseStrictJson } from '../../lib/strict-json.js';
import { validateBody, validateUuidV4 } from '../../lib/policy.js';
import { errorJson, methodGuard, readStrictBody, sendJson } from '../../lib/http.js';

export default async function handler(req, res) {
  if (!methodGuard(req, res, ['POST', 'PUT', 'PATCH'])) return;
  try {
    if (req.headers?.['x-intentlatch-hop'] !== '1') return errorJson(res, 403, 'relay_required');
    const digest = String(req.headers?.['x-intentlatch-request-digest'] || '');
    const key = String(req.headers?.['idempotency-key'] || '');
    if (!/^[a-f0-9]{64}$/.test(digest)) return errorJson(res, 400, 'invalid_request_digest');
    const a = Buffer.from(digest), b = Buffer.from(key);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return errorJson(res, 400, 'idempotency_mismatch');
    const text = await readStrictBody(req, 4096);
    let body;
    try { body = parseStrictJson(text); } catch { return errorJson(res, 400, 'invalid_json'); }
    const requestId = validateUuidV4(body?.request_id);
    validateBody(body, requestId);
    const receipt = createHash('sha256').update(`intent-latch-demo-v1\n${digest}\n${canonicalJson(body)}`).digest('hex');
    sendJson(res, 200, { accepted: true, harmless: true, request_id: requestId, request_digest: digest, receipt, echo: { message: body.message } });
  } catch (error) { errorJson(res, error.status || 400, error.code || error.message || 'invalid_request'); }
}
