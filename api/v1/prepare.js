import { prepare } from '../../lib/core.js';
import { errorJson, methodGuard, sendJson } from '../../lib/http.js';

export default function handler(req, res) {
  if (!methodGuard(req, res, ['GET'])) return;
  try { sendJson(res, 200, prepare(req.url)); }
  catch (error) { errorJson(res, error.status || 400, error.code || 'invalid_request'); }
}
