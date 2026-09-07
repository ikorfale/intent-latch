import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import prepare from '../api/v1/prepare.js';
import commit from '../api/v1/commit.js';
import demo from '../api/v1/demo-target.js';

const routes = new Map([['/api/v1/prepare', prepare], ['/api/v1/commit', commit], ['/api/v1/demo-target', demo]]);
const staticMap = new Map([['/', 'index.html'], ['/docs', 'docs.html'], ['/security', 'security.html'], ['/style.css', 'style.css'], ['/llms.txt', 'llms.txt'], ['/openapi.json', 'openapi.json'], ['/robots.txt', 'robots.txt']]);
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (routes.has(pathname)) return routes.get(pathname)(req, res);
  const file = staticMap.get(pathname);
  if (!file) { res.statusCode = 404; return res.end('Not found'); }
  try {
    const body = await fs.readFile(path.join('public', file));
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.css') ? 'text/css; charset=utf-8' : file.endsWith('.json') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8';
    res.setHeader('Content-Type', type); res.setHeader('X-Content-Type-Options', 'nosniff'); res.end(body);
  } catch { res.statusCode = 500; res.end('Internal error'); }
});
server.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => process.stdout.write(`IntentLatch local server on http://0.0.0.0:${process.env.PORT || 3000}\n`));
