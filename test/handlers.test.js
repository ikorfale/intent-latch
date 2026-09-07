import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import prepareHandler from '../api/v1/prepare.js';
import commitHandler from '../api/v1/commit.js';
import demoHandler from '../api/v1/demo-target.js';
import { SECURITY_HEADERS } from '../lib/http.js';

function request(method, url = '/', body = '', headers = {}) {
  const req = Readable.from(body ? [Buffer.from(body)] : []); req.method = method; req.url = url; req.headers = headers; return req;
}
function response() {
  return { statusCode: 200, headers: {}, chunks: [], setHeader(k,v){ this.headers[k.toLowerCase()] = String(v); }, end(x=''){ this.chunks.push(Buffer.from(x)); this.body = Buffer.concat(this.chunks).toString(); this.ended = true; } };
}
async function invoke(handler, req) { const res = response(); await handler(req, res); return res; }
const assertSafe = (res) => {
  for (const name of Object.keys(SECURITY_HEADERS)) assert.ok(res.headers[name.toLowerCase()], `missing ${name}`);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
};

test('prepare GET returns safe JSON headers', async () => {
  const id = '550e8400-e29b-41d4-a716-446655440000'; const body = Buffer.from(JSON.stringify({ message: 'hi', request_id: id })).toString('base64url');
  const url = `/api/v1/prepare?origin=https%3A%2F%2Fintent-latch-two.vercel.app&path=%2Fapi%2Fv1%2Fdemo-target&method=POST&request_id=${id}&body=${body}`;
  const res = await invoke(prepareHandler, request('GET', url)); assert.equal(res.statusCode, 200); assertSafe(res); assert.equal(JSON.parse(res.body).review.dispatch_performed, false);
});
for (const method of ['POST','PUT','DELETE','HEAD','OPTIONS']) test(`prepare ${method} does not run and returns 405`, async () => { const res = await invoke(prepareHandler, request(method)); assert.equal(res.statusCode, 405); assertSafe(res); });
for (const method of ['GET','HEAD','OPTIONS','DELETE','TRACE','CONNECT']) test(`commit ${method} is absent/rejected without body dispatch`, async () => { const res = await invoke(commitHandler, request(method)); assert.equal(res.statusCode, 405); assertSafe(res); });
test('commit declared prefetch rejects before body parsing', async () => { const res = await invoke(commitHandler, request('POST', '/', '', { purpose: 'prefetch', 'content-type': 'text/plain' })); assert.equal(res.statusCode, 400); assert.equal(JSON.parse(res.body).error, 'prefetch_rejected'); assertSafe(res); });
test('commit prerender via sec-purpose rejects', async () => { const res = await invoke(commitHandler, request('POST', '/', '', { 'sec-purpose': 'prerender' })); assert.equal(JSON.parse(res.body).error, 'prefetch_rejected'); });
test('commit relay recursion rejects', async () => { const res = await invoke(commitHandler, request('POST', '/', '', { 'x-intentlatch-hop': '1' })); assert.equal(res.statusCode, 508); assert.equal(JSON.parse(res.body).error, 'relay_recursion_rejected'); });
test('commit requires exact application/json', async () => { const res = await invoke(commitHandler, request('POST', '/', '{}', { 'content-type': 'application/json; charset=utf-8' })); assert.equal(res.statusCode, 415); assertSafe(res); });
test('commit rejects declared oversized body', async () => { const res = await invoke(commitHandler, request('POST', '/', '{}', { 'content-type': 'application/json', 'content-length': '13000' })); assert.equal(res.statusCode, 413); });
test('commit rejects streaming oversized body', async () => { const res = await invoke(commitHandler, request('POST', '/', 'x'.repeat(13000), { 'content-type': 'application/json' })); assert.equal(res.statusCode, 413); });
test('commit rejects malformed JSON without outbound', async () => { const res = await invoke(commitHandler, request('POST', '/', '{', { 'content-type': 'application/json' })); assert.equal(res.statusCode, 400); assert.equal(JSON.parse(res.body).error, 'invalid_json'); });
for (const method of ['GET','HEAD','OPTIONS','DELETE']) test(`demo direct ${method} never acts`, async () => { const res = await invoke(demoHandler, request(method)); assert.equal(res.statusCode, 405); assertSafe(res); });
test('demo direct POST requires relay marker', async () => { const res = await invoke(demoHandler, request('POST', '/', '{}', { 'content-type': 'application/json' })); assert.equal(res.statusCode, 403); assert.equal(JSON.parse(res.body).error, 'relay_required'); });
test('demo rejects mismatched deterministic idempotency key', async () => { const res = await invoke(demoHandler, request('POST', '/', '{}', { 'content-type': 'application/json', 'x-intentlatch-hop': '1', 'x-intentlatch-request-digest': 'a'.repeat(64), 'idempotency-key': 'b'.repeat(64) })); assert.equal(res.statusCode, 400); assert.equal(JSON.parse(res.body).error, 'idempotency_mismatch'); });
test('demo returns bounded harmless deterministic receipt', async () => {
  const id = '550e8400-e29b-41d4-a716-446655440000', digest = 'a'.repeat(64), text = JSON.stringify({ message: 'hello', request_id: id });
  const headers = { 'content-type': 'application/json', 'x-intentlatch-hop': '1', 'x-intentlatch-request-digest': digest, 'idempotency-key': digest };
  const first = await invoke(demoHandler, request('POST', '/', text, headers)); const second = await invoke(demoHandler, request('POST', '/', text, headers));
  assert.equal(first.statusCode, 200); assertSafe(first); const a = JSON.parse(first.body), b = JSON.parse(second.body); assert.equal(a.harmless, true); assert.equal(a.receipt, b.receipt); assert.deepEqual(a.echo, { message: 'hello' });
});
