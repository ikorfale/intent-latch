import https from 'node:https';
import dns from 'node:dns/promises';
import { isGlobalAddress } from './policy.js';

export class DispatchError extends Error {
  constructor(code, outcome = 'failed_before_send') { super(code); this.code = code; this.outcome = outcome; }
}

export async function resolveVetted(hostname, resolver = defaultResolver) {
  let answers;
  try { answers = await resolver(hostname); } catch { throw new DispatchError('dns_failed'); }
  if (!Array.isArray(answers) || answers.length === 0 || answers.some((a) => !a || ![4, 6].includes(a.family) || !isGlobalAddress(a.address))) throw new DispatchError('destination_not_global');
  return answers[0];
}

export async function dispatch(intent, digest, {
  resolver = defaultResolver,
  requester = nodeRequester,
  timeoutMs = 5000,
  maxResponseBytes = 65536
} = {}) {
  const started = Date.now();
  const hostname = new URL(intent.origin).hostname;
  let timer;
  const vetted = await Promise.race([
    resolveVetted(hostname, resolver),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new DispatchError('deadline_exceeded')), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
  const remainingMs = timeoutMs - (Date.now() - started);
  if (remainingMs <= 0) throw new DispatchError('deadline_exceeded');
  const body = Buffer.from(JSON.stringify(intent.body));
  const headers = Object.freeze({
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Accept-Encoding': 'identity',
    'User-Agent': 'IntentLatch/1.0 (+https://intent-latch.vercel.app/security)',
    'Content-Length': String(body.length),
    'Idempotency-Key': digest,
    'X-IntentLatch-Request-Digest': digest,
    'X-IntentLatch-Hop': '1'
  });
  const options = Object.freeze({
    protocol: 'https:', hostname, port: 443, path: intent.path, method: intent.method,
    servername: hostname, rejectUnauthorized: true, agent: false, headers,
    lookup(_host, _opts, callback) { callback(null, vetted.address, vetted.family); }
  });
  try {
    const result = await requester(options, body, { timeoutMs: remainingMs, maxResponseBytes });
    return {
      relay_state: 'completed',
      upstream_status: result.status,
      body_encoding: 'base64',
      body: Buffer.from(result.body).toString('base64'),
      request_digest: digest,
      idempotency_note: 'Destination enforcement is required; this relay has no durable one-use store.'
    };
  } catch (error) {
    if (error instanceof DispatchError) throw error;
    throw new DispatchError('outcome_unknown', 'outcome_unknown');
  }
}

async function defaultResolver(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

function nodeRequester(options, body, { timeoutMs, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    let wrote = false;
    const req = https.request(options);
    const timer = setTimeout(() => {
      req.destroy();
      reject(new DispatchError('outcome_unknown', wrote ? 'outcome_unknown' : 'failed_before_send'));
    }, timeoutMs);
    const done = (fn, value) => { clearTimeout(timer); fn(value); };
    req.once('upgrade', (_res, socket) => {
      socket.destroy(); req.destroy(); done(reject, new DispatchError('upgrade_rejected', 'outcome_unknown'));
    });
    req.once('response', (res) => {
      if (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') {
        res.destroy(); return done(reject, new DispatchError('compressed_response_rejected', 'outcome_unknown'));
      }
      const chunks = []; let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxResponseBytes) {
          res.destroy(); req.destroy(); done(reject, new DispatchError('response_too_large', 'outcome_unknown'));
        } else chunks.push(chunk);
      });
      res.once('end', () => done(resolve, { status: res.statusCode, body: Buffer.concat(chunks) }));
      res.once('error', () => done(reject, new DispatchError('outcome_unknown', 'outcome_unknown')));
    });
    req.once('error', () => done(reject, new DispatchError('outcome_unknown', wrote ? 'outcome_unknown' : 'failed_before_send')));
    wrote = true;
    req.end(body);
  });
}
