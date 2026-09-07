import fs from 'node:fs';
import path from 'node:path';

const required = ['public/index.html','public/docs.html','public/security.html','public/style.css','public/llms.txt','public/openapi.json','README.md','SECURITY.md','LICENSE','vercel.json'];
for (const file of required) if (!fs.statSync(file).isFile()) throw new Error(`Missing ${file}`);
for (const file of ['public/openapi.json','vercel.json','package.json']) JSON.parse(fs.readFileSync(file, 'utf8'));
const html = fs.readdirSync('public').filter((f) => f.endsWith('.html')).map((f) => fs.readFileSync(path.join('public', f), 'utf8')).join('\n');
if (/<script\b/i.test(html) || /https?:\/\/(?!github\.com)/i.test(html.replaceAll('https://intent-latch.vercel.app', ''))) throw new Error('Unexpected runtime script or external asset');
console.log(`build ok: ${required.length} release files validated`);
