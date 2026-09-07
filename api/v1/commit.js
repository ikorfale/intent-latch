import { validateCommitText } from '../../lib/core.js';
import { dispatch, DispatchError } from '../../lib/transport.js';
import { errorJson, isPrefetch, methodGuard, readStrictBody, sendJson } from '../../lib/http.js';

export default async function handler(req, res) {
  if (!methodGuard(req, res, ['POST'])) return;
  if (req.headers?.['x-intentlatch-hop']) return errorJson(res, 508, 'relay_recursion_rejected');
  if (isPrefetch(req)) return errorJson(res, 400, 'prefetch_rejected');
  try {
    const text = await readStrictBody(req, 12288);
    const { intent, digest } = validateCommitText(text);
    const result = await dispatch(intent, digest);
    sendJson(res, 200, result);
  } catch (error) {
    if (error instanceof DispatchError) {
      return sendJson(res, error.outcome === 'outcome_unknown' ? 504 : 502, { error: error.code, relay_state: error.outcome });
    }
    errorJson(res, error.status || 400, error.code || 'invalid_request');
  }
}
