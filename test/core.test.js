import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, decodeBase64urlJson, parseStrictJson } from '../lib/strict-json.js';
import { prepare, validateCommitText } from '../lib/core.js';
import { PUBLIC_ORIGIN, DEMO_PATH, isGlobalAddress, normalizeOrigin, normalizePath } from '../lib/policy.js';

const id = '550e8400-e29b-41d4-a716-446655440000';
const now = Date.parse('2026-09-07T05:00:00.000Z');
const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const url = (overrides = {}) => {
  const p = { origin: PUBLIC_ORIGIN, path: DEMO_PATH, method: 'POST', request_id: id, body: b64({ message: 'hello', request_id: id }), ...overrides };
  return `/api/v1/prepare?${Object.entries(p).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`;
};
const prepared = () => prepare(url(), { now });
const commit = (p = prepared()) => JSON.stringify(p.commit_template.body);

for (const [name, text] of [
  ['duplicate object keys', '{"a":1,"a":2}'], ['trailing data', '{"a":1}x'], ['invalid number', '{"a":01}'],
  ['non-finite number', '{"a":1e999}'], ['lone escaped surrogate', '{"a":"\\ud800"}'], ['raw control', '{"a":"\u0001"}']
]) test(`strict JSON rejects ${name}`, () => assert.throws(() => parseStrictJson(text)));

test('strict JSON accepts nested object and canonicalizes sorted keys', () => assert.equal(canonicalJson(parseStrictJson('{"z":2,"a":{"b":1}}')), '{"a":{"b":1},"z":2}'));
test('strict JSON rejects excessive depth', () => assert.throws(() => parseStrictJson('['.repeat(14) + '0' + ']'.repeat(14))));
test('strict JSON treats __proto__ as inert own data', () => { const value = parseStrictJson('{"__proto__":{"polluted":true}}'); assert.equal(Object.getPrototypeOf(value), Object.prototype); assert.equal(value.polluted, undefined); assert.equal(Object.hasOwn(value, '__proto__'), true); });
test('base64url rejects malformed alphabet', () => assert.throws(() => decodeBase64urlJson('***')));
test('base64url rejects noncanonical padding', () => assert.throws(() => decodeBase64urlJson('e30=')));
test('base64url rejects malformed UTF-8', () => assert.throws(() => decodeBase64urlJson(Buffer.from([0xc3, 0x28]).toString('base64url'))));
test('base64url enforces decoded size', () => assert.throws(() => decodeBase64urlJson(Buffer.alloc(4097, 65).toString('base64url'))));

test('prepare returns canonical review and exact POST template without dispatch URL', () => {
  const p = prepared();
  assert.equal(p.intent.origin, PUBLIC_ORIGIN); assert.equal(p.intent.path, DEMO_PATH); assert.equal(p.request_digest.length, 64);
  assert.equal(p.review.dispatch_performed, false); assert.equal(p.commit_template.method, 'POST'); assert.equal(p.commit_template.body.confirmation, p.request_digest);
  assert.match(p.review.authority_limit, /does not authenticate or authorize the caller/);
  assert.equal(JSON.stringify(p).includes('/api/v1/commit?'), false);
});
test('prepare expiry is exactly two minutes', () => assert.equal(Date.parse(prepared().expires_at) - now, 120000));
test('prepare rejects missing parameter', () => assert.throws(() => prepare('/api/v1/prepare?origin=x'), { code: 'missing_parameter' }));
test('prepare rejects duplicate parameter', () => assert.throws(() => prepare(`${url()}&method=POST`), { code: 'duplicate_parameter' }));
test('prepare rejects unknown parameter', () => assert.throws(() => prepare(`${url()}&headers=x`), { code: 'unknown_parameter' }));
test('prepare rejects malformed query Unicode escape', () => assert.throws(() => prepare('/api/v1/prepare?origin=%zz'), { code: 'invalid_query' }));
test('prepare rejects oversized URL', () => assert.throws(() => prepare('/api/v1/prepare?' + 'a'.repeat(9000)), { code: 'uri_too_long' }));
for (const method of ['GET','HEAD','DELETE','OPTIONS','TRACE','CONNECT','post','CUSTOM']) test(`prepare blocks method ${method}`, () => assert.throws(() => prepare(url({ method })), { code: 'method_not_allowed' }));
for (const origin of ['https://127.1','https://2130706433','https://0x7f000001','https://[::1]','https://[::ffff:127.0.0.1]','http://intent-latch.vercel.app','https://user@intent-latch.vercel.app','https://intent-latch-two.vercel.app:444','https://intent-latch-two.vercel.app/?x=1','https://intent-latch-two.vercel.app/#x']) test(`prepare rejects origin ${origin}`, () => assert.throws(() => prepare(url({ origin }))));
for (const path of ['/api/v1/demo-target?x=1','//api/v1/demo-target','/api/../demo-target','/api/%2e%2e/demo-target','/api/%2Fdemo','/api\\demo']) test(`prepare rejects path ${path}`, () => assert.throws(() => prepare(url({ path }))));
test('prepare fails closed for arbitrary destination', () => assert.throws(() => prepare(url({ origin: 'https://example.com' })), { code: 'destination_not_allowed' }));
test('prepare fails closed for same-origin non-demo path', () => assert.throws(() => prepare(url({ path: '/api/v1/commit' })), { code: 'destination_not_allowed' }));
test('prepare rejects non-v4 UUID', () => assert.throws(() => prepare(url({ request_id: '550e8400-e29b-11d4-a716-446655440000', body: b64({ message: 'x', request_id: '550e8400-e29b-11d4-a716-446655440000' }) })), { code: 'invalid_request_id' }));
test('prepare rejects request-id body mismatch', () => assert.throws(() => prepare(url({ body: b64({ message: 'x', request_id: '2c1f8df0-99b5-4bd9-a998-53536e220001' }) })), { code: 'schema_rejected' }));
test('prepare rejects body arrays', () => assert.throws(() => prepare(url({ body: b64([]) })), { code: 'invalid_body' }));
test('prepare rejects unknown schema fields', () => assert.throws(() => prepare(url({ body: b64({ message: 'x', request_id: id, extra: 1 }) })), { code: 'schema_rejected' }));
for (const key of ['token','API_key','Pass-Word','session','jwt','signatures','Cookie']) test(`prepare rejects sensitive key variant ${key}`, () => assert.throws(() => prepare(url({ body: b64({ message: 'x', request_id: id, nested: { [key]: 'x' } }) })), { code: 'sensitive_field_name' }));
test('secret hygiene does not claim value detection', () => assert.doesNotThrow(() => prepare(url({ body: b64({ message: 'ordinary-looking values cannot be classified reliably', request_id: id }) }))));
test('duplicate body JSON keys rejected', () => assert.throws(() => prepare(url({ body: b64(`{"message":"a","message":"b","request_id":"${id}"}`) }))));

test('commit validates exact prepared intent', () => assert.equal(validateCommitText(commit(), { now: now + 1000 }).digest, prepared().request_digest));
test('deterministic confirmation authenticates bytes, not the caller', () => {
  const firstCallerResponse = prepared();
  const copiedByUnrelatedCaller = JSON.stringify(firstCallerResponse.commit_template.body);
  assert.equal(validateCommitText(copiedByUnrelatedCaller, { now: now + 1000 }).digest, firstCallerResponse.request_digest);
});
test('commit rejects digest tampering', () => { const x = prepared().commit_template.body; x.confirmation = '0'.repeat(64); assert.throws(() => validateCommitText(JSON.stringify(x), { now }), { code: 'digest_mismatch' }); });
test('commit rejects intent tampering', () => { const x = prepared().commit_template.body; x.intent.body.message = 'changed'; assert.throws(() => validateCommitText(JSON.stringify(x), { now }), { code: 'digest_mismatch' }); });
test('commit rejects expiry', () => assert.throws(() => validateCommitText(commit(), { now: now + 120001 }), { code: 'intent_expired' }));
test('commit rejects not-yet-issued intent', () => assert.throws(() => validateCommitText(commit(), { now: now - 6000 }), { code: 'intent_expired' }));
test('commit rejects wrong confirmation type', () => { const x = prepared().commit_template.body; x.confirmation = 1; assert.throws(() => validateCommitText(JSON.stringify(x), { now })); });
test('commit rejects duplicate JSON keys', () => assert.throws(() => validateCommitText('{"intent":{},"confirmation":"x","confirmation":"y"}', { now }), { code: 'invalid_json' }));
test('commit rejects unknown envelope field', () => { const x = prepared().commit_template.body; x.extra = 1; assert.throws(() => validateCommitText(JSON.stringify(x), { now }), { code: 'invalid_commit' }); });

for (const ip of ['127.0.0.1','10.0.0.1','100.64.0.1','169.254.169.254','192.168.1.1','198.51.100.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1']) test(`special-use address rejected: ${ip}`, () => assert.equal(isGlobalAddress(ip), false));
for (const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) test(`global address accepted: ${ip}`, () => assert.equal(isGlobalAddress(ip), true));
test('origin canonicalizes default port and host case', () => assert.equal(normalizeOrigin('https://INTENT-LATCH-TWO.VERCEL.APP:443'), PUBLIC_ORIGIN));
test('path normalization rejects encoded slash', () => assert.throws(() => normalizePath('/a%2fb')));
