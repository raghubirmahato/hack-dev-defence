'use strict';
// Front-door mode: a request without the secret is handed to HDD (a stub here); the visitor's address does not change.
process.env.HDD_ORIGIN_SECRET = 'gate-test-secret-value'; // hdd-secret-scan:allow (test value)
process.env.SESSION_SECRET = 'unit-test-session-secret'; // hdd-secret-scan:allow (test value)
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

function stubHdd(handler) {
  return new Promise((resolve) => {
    const seen = [];
    const srv = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => { seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }); handler(req, res); });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, url: 'http://127.0.0.1:' + srv.address().port }));
  });
}
function load(env) {
  Object.assign(process.env, env);
  delete require.cache[require.resolve('../api/app')];
  return require('../api/app');
}
function call(app, method, url, { headers = {}, body = '' } = {}) {
  return new Promise((resolve) => {
    const chunks = body ? [Buffer.from(body)] : [];
    const req = { method, url, headers, readable: true, async *[Symbol.asyncIterator]() { for (const c of chunks) yield c; } };
    const res = {
      statusCode: 200, headers: {}, sent: false, chunks: [],
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      write(c) { this.chunks.push(Buffer.from(c)); return true; },
      end(c) { if (c) this.chunks.push(Buffer.from(c)); resolve({ status: this.statusCode, headers: this.headers, text: Buffer.concat(this.chunks).toString() }); },
      on() { return this; }, once() { return this; }, emit() { return true; }, removeListener() { return this; }, destroy() { resolve({ status: this.statusCode, headers: this.headers, text: 'destroyed' }); },
    };
    app(req, res);
  });
}

test('a request without the secret is passed to HDD with its own host, method, body and the real client address', async () => {
  const hdd = await stubHdd((req, res) => { res.statusCode = 201; res.setHeader('set-cookie', ['a=1; Path=/', 'b=2; Path=/']); res.setHeader('content-type', 'text/plain'); res.end('from-hdd'); });
  const app = load({ HDD_GATE_URL: hdd.url });
  const r = await call(app, 'POST', '/admin/login?x=1', { headers: { host: 'shop.example.test', 'content-type': 'application/x-www-form-urlencoded', 'x-vercel-forwarded-for': '203.0.113.9', 'x-hdd-origin-secret': 'forged' }, body: 'username=a&password=b' });
  assert.equal(r.status, 201);
  assert.equal(r.text, 'from-hdd');
  assert.deepEqual(r.headers['set-cookie'], ['a=1; Path=/', 'b=2; Path=/']);
  const s = hdd.seen[0];
  assert.equal(s.method, 'POST');
  assert.equal(s.url, '/admin/login?x=1');
  assert.equal(s.body, 'username=a&password=b');
  assert.equal(s.headers.host, new URL(hdd.url).host, 'the Host names HDD so a tunnel or router in front of it can route');
  assert.equal(s.headers['x-forwarded-host'], 'shop.example.test');
  assert.equal(s.headers['x-forwarded-for'], '203.0.113.9');
  assert.equal(s.headers['x-hdd-gate-hop'], '1');
  assert.equal(s.headers['x-hdd-origin-secret'], undefined, 'a client-supplied secret header is never forwarded');
  hdd.srv.close();
});

test('a request that carries the secret is served by the shop and never forwarded', async () => {
  const hdd = await stubHdd((req, res) => res.end('should-not-be-called'));
  const app = load({ HDD_GATE_URL: hdd.url });
  const r = await call(app, 'GET', '/healthz', { headers: { 'x-hdd-origin-secret': 'gate-test-secret-value' } });
  assert.equal(r.status, 200);
  assert.equal(hdd.seen.length, 0);
  hdd.srv.close();
});

test('a request that already went through the front door is refused, not looped', async () => {
  const hdd = await stubHdd((req, res) => res.end('x'));
  const app = load({ HDD_GATE_URL: hdd.url });
  const r = await call(app, 'GET', '/', { headers: { 'x-hdd-gate-hop': '1' } });
  assert.equal(r.status, 403);
  assert.equal(hdd.seen.length, 0);
  hdd.srv.close();
});

test('when HDD cannot be reached the request is refused with 503 and the shop is never served uninspected', async () => {
  const app = load({ HDD_GATE_URL: 'http://127.0.0.1:9' });
  const r = await call(app, 'GET', '/', { headers: { host: 'shop.example.test' } });
  assert.equal(r.status, 503);
  assert.match(r.text, /could not be reached/);
  assert.doesNotMatch(r.text, /CoreByte Hardware/);
});

test('without front-door mode a browser gets a readable 403 page (with a link when HDD_PUBLIC_URL is set), a script gets text', async () => {
  delete process.env.HDD_GATE_URL;
  const app = load({ HDD_PUBLIC_URL: 'https://hdd.example.test/' });
  const page = await call(app, 'GET', '/', { headers: { accept: 'text/html,application/xhtml+xml' } });
  assert.equal(page.status, 403);
  assert.match(page.text, /Open this shop through HDD/);
  assert.match(page.text, /href="https:\/\/hdd.example.test"/);
  const script = await call(app, 'GET', '/', { headers: { accept: '*/*' } });
  assert.equal(script.status, 403);
  assert.match(script.text, /Hack Dev Defence/);
  assert.doesNotMatch(script.text, /<html|<main/);
  delete process.env.HDD_PUBLIC_URL;
});

test('a GET is retried when the first connection to HDD is reset; a POST on a fresh connection is not replayed', async () => {
  let hits = 0;
  const hdd = await stubHdd((req, res) => { hits += 1; if (hits === 1) { req.socket.destroy(); return; } res.end('from-hdd'); });
  const app = load({ HDD_GATE_URL: hdd.url });
  const g = await call(app, 'GET', '/', { headers: { host: 'shop.example.test' } });
  assert.equal(g.status, 200);
  assert.equal(g.text, 'from-hdd');
  assert.equal(hits, 2, 'one reset, one retry');
  hits = 0;
  const reset = await stubHdd((req, res) => { hits += 1; req.socket.destroy(); });
  const app2 = load({ HDD_GATE_URL: reset.url });
  const p = await call(app2, 'POST', '/admin/login', { headers: { host: 'shop.example.test', 'content-type': 'application/x-www-form-urlencoded' }, body: 'a=b' });
  assert.equal(p.status, 503);
  assert.equal(hits, 1, 'a POST that may have reached HDD is never sent twice');
  hdd.srv.close(); reset.srv.close();
});
