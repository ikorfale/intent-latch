import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const docs = ['README.md','SECURITY.md','public/index.html','public/docs.html','public/security.html','public/llms.txt'];
const impossibility = 'There is no generally safe, public, anonymous, arbitrary side-effecting GET relay.';
const timeout = 'A timeout means the outcome is unknown';

test('all publication surfaces state side-effecting GET impossibility', () => { for (const file of docs) assert.ok(read(file).includes(impossibility), file); });
test('all publication surfaces state timeout ambiguity', () => { for (const file of docs) assert.ok(read(file).includes(timeout), file); });
test('all publication surfaces avoid exactly-once claims', () => { for (const file of docs) assert.match(read(file), /no |does not|cannot|makes no|has no/i, file); });
test('landing has no JavaScript', () => assert.doesNotMatch(read('public/index.html'), /<script\b/i));
test('landing uses no external runtime assets', () => { const html = read('public/index.html'); assert.doesNotMatch(html, /<(?:script|img|link)[^>]+(?:src|href)=["']https?:/i); });
test('landing builder submits only to prepare GET', () => { const html = read('public/index.html'); assert.match(html, /<form action="\/api\/v1\/prepare" method="get">/); assert.doesNotMatch(html, /<form[^>]+commit/i); });
test('landing does not render executable commit link', () => assert.doesNotMatch(read('public/index.html'), /href=["'][^"']*\/api\/v1\/commit/i));
test('llms and OpenAPI expose no GET commit operation', () => { const spec = JSON.parse(read('public/openapi.json')); assert.deepEqual(Object.keys(spec.paths['/api/v1/commit']), ['post']); assert.doesNotMatch(read('public/llms.txt'), /GET \/api\/v1\/commit/); });
test('OpenAPI hosted allowlist is exact demo only', () => { const spec = JSON.parse(read('public/openapi.json')); const origin = spec.paths['/api/v1/prepare'].get.parameters.find((p) => p.name === 'origin'); const target = spec.paths['/api/v1/prepare'].get.parameters.find((p) => p.name === 'path'); assert.equal(origin.schema.const, 'https://intent-latch.vercel.app'); assert.equal(target.schema.const, '/api/v1/demo-target'); });
test('OpenAPI allows only POST PUT PATCH action methods', () => { const spec = JSON.parse(read('public/openapi.json')); const method = spec.paths['/api/v1/prepare'].get.parameters.find((p) => p.name === 'method'); assert.deepEqual(method.schema.enum, ['POST','PUT','PATCH']); });
test('README, llms, and OpenAPI share tagline', () => { for (const f of ['README.md','public/llms.txt','public/openapi.json']) assert.ok(read(f).includes('Prepare with GET. Commit with POST.'), f); });
test('application source has no logging calls', () => {
  for (const dir of ['api','lib']) for (const file of fs.readdirSync(path.join(root, dir), { recursive: true }).filter((x) => x.endsWith('.js'))) assert.doesNotMatch(read(path.join(dir, file)), /\bconsole\.|process\.stdout|process\.stderr|\.log\s*\(/, `${dir}/${file}`);
});
test('project has no runtime dependencies', () => { const pkg = JSON.parse(read('package.json')); assert.equal(pkg.dependencies, undefined); assert.equal(pkg.devDependencies, undefined); });
test('Vercel config selects Node 24', () => assert.equal(JSON.parse(read('vercel.json')).functions['api/v1/*.js'].runtime, 'nodejs24.x'));
test('API code contains no CORS response header', () => { for (const dir of ['api','lib']) for (const file of fs.readdirSync(path.join(root, dir), { recursive: true }).filter((x) => x.endsWith('.js'))) assert.doesNotMatch(read(path.join(dir, file)), /access-control-allow-origin/i); });
test('transport source rejects upgrades and compression', () => { const source = read('lib/transport.js'); assert.match(source, /once\('upgrade'/); assert.match(source, /compressed_response_rejected/); assert.match(source, /maxResponseBytes = 65536/); assert.match(source, /timeoutMs = 5000/); });
test('API headers include no-store, noindex, attachment, CSP, CORP, referrer and nosniff', () => { const source = read('lib/http.js'); for (const token of ['no-store','noindex','attachment','Content-Security-Policy','Cross-Origin-Resource-Policy','no-referrer','nosniff']) assert.ok(source.includes(token), token); });
test('license is MIT and reference code is not vendored', () => { assert.match(read('LICENSE'), /^MIT License/); assert.equal(fs.existsSync(path.join(root, '.tmp')), false); });
