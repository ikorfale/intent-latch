import test from 'node:test';
import assert from 'node:assert/strict';
import { dispatch, DispatchError, resolveVetted } from '../lib/transport.js';
import { prepare } from '../lib/core.js';
import { PUBLIC_ORIGIN, DEMO_PATH } from '../lib/policy.js';

const id = '550e8400-e29b-41d4-a716-446655440000';
const now = Date.parse('2026-09-07T05:00:00Z');
const body = Buffer.from(JSON.stringify({ message: 'hello', request_id: id })).toString('base64url');
const p = prepare(`/api/v1/prepare?origin=${encodeURIComponent(PUBLIC_ORIGIN)}&path=${encodeURIComponent(DEMO_PATH)}&method=POST&request_id=${id}&body=${body}`, { now });
const intent = p.intent, digest = p.request_digest;
const publicResolver = async () => [{ address: '8.8.8.8', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }];

test('resolver accepts all-global answer set', async () => assert.deepEqual(await resolveVetted('example.com', publicResolver), { address: '8.8.8.8', family: 4 }));
test('resolver rejects private answer', async () => await assert.rejects(resolveVetted('example.com', async () => [{ address: '10.0.0.1', family: 4 }]), { code: 'destination_not_global' }));
test('resolver rejects mixed public/private DNS', async () => await assert.rejects(resolveVetted('example.com', async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]), { code: 'destination_not_global' }));
test('resolver rejects empty DNS', async () => await assert.rejects(resolveVetted('example.com', async () => []), { code: 'destination_not_global' }));
test('resolver rejects malformed family', async () => await assert.rejects(resolveVetted('example.com', async () => [{ address: '8.8.8.8', family: 5 }]), { code: 'destination_not_global' }));
test('resolver failure is coarse', async () => await assert.rejects(resolveVetted('example.com', async () => { throw new Error('details'); }), { code: 'dns_failed' }));
test('overall deadline includes DNS and prevents transport', async () => {
  let calls = 0;
  await assert.rejects(dispatch(intent, digest, { timeoutMs: 10, resolver: () => new Promise(() => {}), requester: async () => { calls++; } }), { code: 'deadline_exceeded', outcome: 'failed_before_send' });
  assert.equal(calls, 0);
});

test('happy prepare to POST commit uses one injected controlled transport', async () => {
  const validated = (await import('../lib/core.js')).validateCommitText(JSON.stringify(p.commit_template.body), { now: now + 1000 });
  let calls = 0;
  const result = await dispatch(validated.intent, validated.digest, { resolver: publicResolver, requester: async () => { calls++; return { status: 200, body: Buffer.from('{"demo":true}') }; } });
  assert.equal(calls, 1); assert.equal(result.relay_state, 'completed'); assert.equal(Buffer.from(result.body, 'base64').toString(), '{"demo":true}');
});

test('dispatch pins vetted IP while preserving hostname, SNI, and TLS verification', async () => {
  let observed;
  const result = await dispatch(intent, digest, { resolver: publicResolver, requester: async (options, sentBody) => {
    observed = { options, sentBody }; let looked;
    options.lookup('ignored', {}, (_e, address, family) => { looked = { address, family }; });
    assert.deepEqual(looked, { address: '8.8.8.8', family: 4 });
    return { status: 200, body: Buffer.from('ok') };
  }});
  assert.equal(observed.options.hostname, 'intent-latch.vercel.app');
  assert.equal(observed.options.servername, 'intent-latch.vercel.app');
  assert.equal(observed.options.rejectUnauthorized, true); assert.equal(observed.options.agent, false); assert.equal(observed.options.port, 443);
  assert.equal(observed.options.path, DEMO_PATH); assert.equal(observed.options.method, 'POST');
  assert.deepEqual(JSON.parse(observed.sentBody), intent.body); assert.equal(result.body, 'b2s=');
});
test('dispatch emits only fixed headers and deterministic key', async () => {
  await dispatch(intent, digest, { resolver: publicResolver, requester: async (options) => {
    assert.deepEqual(Object.keys(options.headers).sort(), ['Accept','Accept-Encoding','Content-Length','Content-Type','Idempotency-Key','User-Agent','X-IntentLatch-Hop','X-IntentLatch-Request-Digest'].sort());
    assert.equal(options.headers['Idempotency-Key'], digest); assert.equal(options.headers['Accept-Encoding'], 'identity'); return { status: 204, body: Buffer.alloc(0) };
  }});
});
test('redirect is terminal data and never followed', async () => {
  let calls = 0; const result = await dispatch(intent, digest, { resolver: publicResolver, requester: async () => { calls++; return { status: 302, body: Buffer.from('moved') }; } });
  assert.equal(calls, 1); assert.equal(result.upstream_status, 302); assert.equal(Buffer.from(result.body, 'base64').toString(), 'moved');
});
test('response envelope copies no upstream headers', async () => {
  const result = await dispatch(intent, digest, { resolver: publicResolver, requester: async () => ({ status: 200, body: Buffer.from('<script>x</script>'), headers: { location: 'https://evil.invalid', 'set-cookie': 'x=1', 'access-control-allow-origin': '*' } }) });
  assert.deepEqual(Object.keys(result).sort(), ['body','body_encoding','idempotency_note','relay_state','request_digest','upstream_status'].sort());
  assert.equal(Buffer.from(result.body, 'base64').toString(), '<script>x</script>');
});
test('transport exception produces outcome_unknown and no retry', async () => {
  let calls = 0;
  await assert.rejects(dispatch(intent, digest, { resolver: publicResolver, requester: async () => { calls++; throw new Error('timeout'); } }), (e) => e instanceof DispatchError && e.code === 'outcome_unknown' && e.outcome === 'outcome_unknown');
  assert.equal(calls, 1);
});
test('DNS rebinding at commit fails closed before transport', async () => {
  let calls = 0;
  await assert.rejects(dispatch(intent, digest, { resolver: async () => [{ address: '169.254.169.254', family: 4 }], requester: async () => { calls++; } }), { code: 'destination_not_global' });
  assert.equal(calls, 0);
});
test('injected response bytes are base64 including binary', async () => {
  const bytes = Buffer.from([0, 255, 1, 2]);
  const result = await dispatch(intent, digest, { resolver: publicResolver, requester: async () => ({ status: 418, body: bytes }) });
  assert.deepEqual(Buffer.from(result.body, 'base64'), bytes);
});
test('resolver runs once and requester cannot trigger second DNS lookup', async () => {
  let resolutions = 0;
  await dispatch(intent, digest, { resolver: async () => { resolutions++; return [{ address: '8.8.8.8', family: 4 }]; }, requester: async (options) => { options.lookup('x', {}, () => {}); options.lookup('x', {}, () => {}); return { status: 200, body: Buffer.alloc(0) }; } });
  assert.equal(resolutions, 1);
});
