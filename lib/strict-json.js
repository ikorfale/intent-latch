const MAX_DEPTH = 12;
const MAX_NODES = 256;

export function parseStrictJson(text, { maxDepth = MAX_DEPTH, maxNodes = MAX_NODES } = {}) {
  if (typeof text !== 'string') throw new SyntaxError('JSON input must be text');
  let i = 0;
  let nodes = 0;
  const fail = () => { throw new SyntaxError('Invalid JSON'); };
  const ws = () => { while (i < text.length && /[\x20\x09\x0a\x0d]/.test(text[i])) i++; };
  const value = (depth) => {
    if (depth > maxDepth || ++nodes > maxNodes) fail();
    ws();
    const c = text[i];
    if (c === '"') return string();
    if (c === '{') return object(depth + 1);
    if (c === '[') return array(depth + 1);
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    return number();
  };
  const string = () => {
    const start = i++;
    let escaped = false;
    while (i < text.length) {
      const code = text.charCodeAt(i);
      if (!escaped && code === 0x22) {
        i++;
        let out;
        try { out = JSON.parse(text.slice(start, i)); } catch { fail(); }
        for (let j = 0; j < out.length; j++) {
          const n = out.charCodeAt(j);
          if (n >= 0xd800 && n <= 0xdbff) {
            const next = out.charCodeAt(++j);
            if (!(next >= 0xdc00 && next <= 0xdfff)) fail();
          } else if (n >= 0xdc00 && n <= 0xdfff) fail();
        }
        return out;
      }
      if (!escaped && code < 0x20) fail();
      if (!escaped && code === 0x5c) escaped = true;
      else escaped = false;
      i++;
    }
    fail();
  };
  const object = (depth) => {
    i++; ws();
    const out = {};
    const keys = new Set();
    if (text[i] === '}') { i++; return out; }
    while (true) {
      if (text[i] !== '"') fail();
      const key = string();
      if (keys.has(key)) fail();
      keys.add(key); ws();
      if (text[i++] !== ':') fail();
      Object.defineProperty(out, key, { value: value(depth), enumerable: true, configurable: true, writable: true }); ws();
      if (text[i] === '}') { i++; return out; }
      if (text[i++] !== ',') fail();
      ws();
    }
  };
  const array = (depth) => {
    i++; ws();
    const out = [];
    if (text[i] === ']') { i++; return out; }
    while (true) {
      out.push(value(depth)); ws();
      if (text[i] === ']') { i++; return out; }
      if (text[i++] !== ',') fail();
      ws();
    }
  };
  const number = () => {
    const match = text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) fail();
    i += match[0].length;
    const n = Number(match[0]);
    if (!Number.isFinite(n)) fail();
    return n;
  };
  const result = value(0);
  ws();
  if (i !== text.length) fail();
  return result;
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError('Unsupported JSON value');
}

export function decodeBase64urlJson(encoded, maxBytes = 4096) {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new SyntaxError('Invalid body encoding');
  if (encoded.length > Math.ceil(maxBytes * 4 / 3) + 2) throw new RangeError('Body too large');
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== encoded) throw new RangeError('Invalid body encoding');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new SyntaxError('Invalid UTF-8'); }
  return { value: parseStrictJson(text), bytes };
}
