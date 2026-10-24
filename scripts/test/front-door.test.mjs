// Executes the generated front-door block (docs/snippets/front-door.js) as the app's real module.
//
// The fixture is the paste block exactly as `snippets::node_front_door` emits it. A tiny stub app
// handler followed by the fixture text becomes a temporary CommonJS module, and that module is
// required fresh per case so the block re-reads HDD_ORIGIN_SECRET / HDD_GATE_URL. A local stub HDD
// server records what the front door forwards, so nothing leaves loopback.

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '..', '..', 'docs', 'snippets', 'front-door.js');
const fixture = readFileSync(FIXTURE, 'utf8');
const requireFromTest = createRequire(import.meta.url);
const workDir = mkdtempSync(join(tmpdir(), 'hdd-front-door-'));
let moduleCount = 0;

const SECRET = 'front-door-test-secret-value'; // hdd-secret-scan:allow (test value, never a real secret)
const APP_BODY = 'APP-RESPONDED';

// The stub app handler is what the wrapped file exported before the paste block wrapped it.
const STUB_APP = [
  "'use strict';",
  'module.exports = async function app(req, res) {',
  "  res.statusCode = 200;",
  "  res.setHeader('content-type', 'text/plain; charset=utf-8');",
  `  res.end(${JSON.stringify(APP_BODY)});`,
  '};',
  '',
].join('\n');

// A fresh CommonJS module = the stub app + the generated paste block, required with the given env.
function loadFrontDoor(env) {
  for (const name of ['HDD_ORIGIN_SECRET', 'HDD_GATE_URL', 'HDD_FAIL_OPEN', 'HDD_GATE_URL_FROM']) delete process.env[name];
  for (const [name, value] of Object.entries(env)) process.env[name] = value;
  const file = join(workDir, `app-${moduleCount++}.cjs`);
  writeFileSync(file, `${STUB_APP}${fixture}`, 'utf8');
  const resolved = requireFromTest.resolve(file);
  delete requireFromTest.cache[resolved];
  return requireFromTest(file);
}

function listen(handler) {
  return new Promise((resolveListen) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      resolveListen({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

function closeServer(server) {
  return new Promise((resolveClose) => {
    if (!server.listening) {
      resolveClose();
      return;
    }
    server.close(resolveClose);
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  });
}

// Stub HDD: records every request (method, path+query, headers, body) before answering.
function stubHdd(handler) {
  const seen = [];
  return listen((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const entry = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      };
      seen.push(entry);
      handler(req, res, entry);
    });
  }).then((started) => ({ ...started, seen }));
}

function startApp(wrapped) {
  return listen(wrapped);
}

// Raw http.request client: unlike fetch, it lets tests set the Host header the visitor used.
function call(app, { method = 'GET', path = '/', headers = {}, body = undefined } = {}) {
  const target = new URL(path, app.url);
  return new Promise((resolveCall, rejectCall) => {
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname + target.search,
        method,
        headers,
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolveCall({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() });
        });
      },
    );
    req.on('error', rejectCall);
    req.end(body);
  });
}

after(async () => {
  rmSync(workDir, { recursive: true, force: true });
  for (const name of ['HDD_ORIGIN_SECRET', 'HDD_GATE_URL', 'HDD_FAIL_OPEN', 'HDD_GATE_URL_FROM']) delete process.env[name];
});

test('a request without the secret is forwarded with its method, path, query, body and headers', async (t) => {
  const hdd = await stubHdd((req, res) => {
    res.statusCode = 201;
    res.setHeader('set-cookie', ['a=1; Path=/', 'b=2; Path=/']);
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.setHeader('x-hdd-inspected', 'yes');
    res.end('from-hdd');
  });
  t.after(() => closeServer(hdd.server));
  const app = await startApp(
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: hdd.url }),
  );
  t.after(() => closeServer(app.server));

  const response = await call(app, {
    method: 'POST',
    path: '/admin/login?x=1',
    headers: {
      host: 'shop.example.test',
      'content-type': 'application/x-www-form-urlencoded',
      'x-custom-kept': 'yes',
      'x-vercel-forwarded-for': '203.0.113.9, 10.0.0.1',
      'x-forwarded-for': '198.51.100.7',
      'x-hdd-origin-secret': 'forged-client-value', // hdd-secret-scan:allow (test value)
    },
    body: 'username=a&password=b',
  });

  assert.equal(response.status, 201, 'the HDD status is streamed back');
  assert.equal(response.text, 'from-hdd', 'the HDD body is streamed back, never the app');
  assert.deepEqual(response.headers['set-cookie'], ['a=1; Path=/', 'b=2; Path=/'], 'every set-cookie value is kept');
  assert.equal(response.headers['x-hdd-inspected'], 'yes');
  assert.doesNotMatch(response.text, /APP-RESPONDED/, 'the app is never served uninspected');

  assert.equal(hdd.seen.length, 1);
  const seen = hdd.seen[0];
  assert.equal(seen.method, 'POST');
  assert.equal(seen.url, '/admin/login?x=1');
  assert.equal(seen.body, 'username=a&password=b');
  assert.equal(seen.headers.host, new URL(hdd.url).host, 'the Host names HDD so a tunnel or router in front of it can route');
  assert.equal(seen.headers['x-hdd-gate-host'], 'shop.example.test', 'the original host reaches HDD');
  assert.equal(seen.headers['x-forwarded-host'], 'shop.example.test');
  assert.equal(seen.headers['x-forwarded-for'], '203.0.113.9', 'only the first forwarded-for value is sent');
  assert.equal(seen.headers['x-hdd-gate-hop'], '1');
  assert.equal(seen.headers['x-forwarded-proto'], 'https');
  assert.equal(seen.headers['accept-encoding'], 'identity');
  assert.equal(seen.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(seen.headers['x-custom-kept'], 'yes', 'ordinary client headers are forwarded');
  assert.equal(seen.headers['x-hdd-origin-secret'], undefined, 'a client-supplied secret header is never forwarded');
});

test('a request that carries the correct secret is served by the app and never forwarded', async (t) => {
  const hdd = await stubHdd((req, res) => res.end('hdd-was-called'));
  t.after(() => closeServer(hdd.server));
  const app = await startApp(
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: hdd.url }),
  );
  t.after(() => closeServer(app.server));

  const response = await call(app, {
    path: '/healthz',
    headers: { host: 'shop.example.test', 'x-hdd-origin-secret': SECRET }, // hdd-secret-scan:allow (test value)
  });
  assert.equal(response.status, 200);
  assert.equal(response.text, APP_BODY);
  assert.equal(hdd.seen.length, 0, 'the secret route never touches HDD');
});

test('a request that already went through the front door is refused, not looped', async (t) => {
  const hdd = await stubHdd((req, res) => res.end('hdd-was-called'));
  t.after(() => closeServer(hdd.server));
  const app = await startApp(
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: hdd.url }),
  );
  t.after(() => closeServer(app.server));

  const response = await call(app, { path: '/', headers: { host: 'shop.example.test', 'x-hdd-gate-hop': '1' } });
  assert.equal(response.status, 403);
  assert.equal(response.text, 'Forbidden: this site only answers through Hack Dev Defence (HDD).');
  assert.equal(hdd.seen.length, 0, 'a hop request is never forwarded again');
  assert.doesNotMatch(response.text, /APP-RESPONDED/);
});

test('an invalid HDD_GATE_URL fails closed with 403 instead of forwarding', async (t) => {
  const app = await startApp(
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: 'not-a-url' }),
  );
  t.after(() => closeServer(app.server));

  const response = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(response.status, 403);
  assert.equal(response.text, 'Forbidden: this site only answers through Hack Dev Defence (HDD).');
});

test('when HDD cannot be reached the answer is 503 and the app is never served uninspected', async (t) => {
  const app = await startApp(
    // A closed loopback port: nothing listens on 9, so every attempt is refused.
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: 'http://127.0.0.1:9' }),
  );
  t.after(() => closeServer(app.server));

  const response = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(response.status, 503);
  assert.match(response.text, /Protection is unavailable/);
  assert.match(response.text, /HDD could not be reached/);
  assert.doesNotMatch(response.text, /APP-RESPONDED/, 'a short HTML page answers, never the app');
});

test('a GET is retried after a reset; a POST is not replayed', async (t) => {
  let getHits = 0;
  const getHdd = await stubHdd((req, res) => {
    getHits += 1;
    if (getHits === 1) {
      req.socket.destroy();
      return;
    }
    res.end('from-hdd');
  });
  t.after(() => closeServer(getHdd.server));
  const getApp = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: getHdd.url }));
  t.after(() => closeServer(getApp.server));

  const get = await call(getApp, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(get.status, 200);
  assert.equal(get.text, 'from-hdd');
  assert.equal(getHits, 2, 'one reset, one retry for a replayable GET');

  let postHits = 0;
  const postHdd = await stubHdd((req, res) => {
    postHits += 1;
    req.socket.destroy();
  });
  t.after(() => closeServer(postHdd.server));
  const postApp = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: postHdd.url }));
  t.after(() => closeServer(postApp.server));

  const post = await call(postApp, {
    method: 'POST',
    path: '/admin/login',
    headers: { host: 'shop.example.test', 'content-type': 'application/x-www-form-urlencoded' },
    body: 'a=b',
  });
  assert.equal(post.status, 503);
  assert.equal(postHits, 1, 'a POST that may have reached HDD is never sent twice');
});

test('while HDD_ORIGIN_SECRET is unset the front door is off and the app answers everyone', async (t) => {
  const hdd = await stubHdd((req, res) => res.end('hdd-was-called'));
  t.after(() => closeServer(hdd.server));
  const app = await startApp(loadFrontDoor({ HDD_GATE_URL: hdd.url }));
  t.after(() => closeServer(app.server));

  const plain = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(plain.status, 200);
  assert.equal(plain.text, APP_BODY);
  const forged = await call(app, {
    path: '/',
    headers: { host: 'shop.example.test', 'x-hdd-origin-secret': 'anything' }, // hdd-secret-scan:allow (test value)
  });
  assert.equal(forged.status, 200);
  assert.equal(forged.text, APP_BODY);
  assert.equal(hdd.seen.length, 0, 'the off front door never forwards');
});

test('HDD_FAIL_OPEN=1 keeps the site usable when HDD is unreachable (opt-in; the request is not inspected)', async (t) => {
  const app = await startApp(
    loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: 'http://127.0.0.1:9', HDD_FAIL_OPEN: '1' }),
  );
  t.after(() => closeServer(app.server));
  const response = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(response.status, 200);
  assert.equal(response.text, APP_BODY);
});

test('HDD_FAIL_OPEN=1 without HDD_GATE_URL serves the app instead of 403', async (t) => {
  const app = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_FAIL_OPEN: 'true' }));
  t.after(() => closeServer(app.server));
  const response = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(response.status, 200);
  assert.equal(response.text, APP_BODY);
});

test('fail-open still hands a POST body to the app after HDD could not be reached', async (t) => {
  const echo = [
    "'use strict';",
    'module.exports = async function app(req, res) {',
    '  const chunks = []; for await (const c of req) chunks.push(c);',
    "  res.statusCode = 200; res.end('GOT:' + Buffer.concat(chunks).toString());",
    '};',
    '',
  ].join('\n');
  for (const name of ['HDD_ORIGIN_SECRET', 'HDD_GATE_URL', 'HDD_FAIL_OPEN', 'HDD_GATE_URL_FROM']) delete process.env[name];
  Object.assign(process.env, { HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: 'http://127.0.0.1:9', HDD_FAIL_OPEN: '1' });
  const file = join(workDir, `echo-${moduleCount++}.cjs`);
  writeFileSync(file, `${echo}${fixture}`, 'utf8');
  const app = await startApp(requireFromTest(file));
  t.after(() => closeServer(app.server));
  const response = await call(app, { method: 'POST', path: '/login', headers: { host: 'shop.example.test', 'content-type': 'application/x-www-form-urlencoded' }, body: 'username=a&password=b' });
  assert.equal(response.status, 200);
  assert.equal(response.text, 'GOT:username=a&password=b');
});

test('an answer without a Ray ID (a tunnel with no HDD behind it) counts as HDD unreachable', async (t) => {
  const tunnelOnly = await listen((req, res) => { res.statusCode = 502; res.end('no tunnel'); });
  t.after(() => closeServer(tunnelOnly.server));
  const closed = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: tunnelOnly.url }));
  t.after(() => closeServer(closed.server));
  const refused = await call(closed, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(refused.status, 503, 'fail closed by default');
  assert.doesNotMatch(refused.text, /no tunnel/);
  const open = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: tunnelOnly.url, HDD_FAIL_OPEN: '1' }));
  t.after(() => closeServer(open.server));
  const served = await call(open, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(served.status, 200);
  assert.equal(served.text, APP_BODY);
});

test('a 502 that carries a Ray ID is HDD talking (origin trouble) and is passed through', async (t) => {
  const hdd = await listen((req, res) => { res.statusCode = 502; res.setHeader('hdd-ray-id', '0123456789abcdef-HDD1'); res.end('origin unreachable'); });
  t.after(() => closeServer(hdd.server));
  const app = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: hdd.url, HDD_FAIL_OPEN: '1' }));
  t.after(() => closeServer(app.server));
  const response = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(response.status, 502);
  assert.equal(response.text, 'origin unreachable');
});

test('HDD_GATE_URL_FROM follows the current HDD address and heals when it changes', async (t) => {
  const hddA = await listen((req, res) => { res.setHeader('hdd-ray-id', '0123456789abcdef-HDD1'); res.end('from-A'); });
  const hddB = await listen((req, res) => { res.setHeader('hdd-ray-id', '0123456789abcdef-HDD1'); res.end('from-B'); });
  let current = hddA.url;
  const registry = await listen((req, res) => { res.end(current + '\n'); });
  t.after(() => { closeServer(hddA.server); closeServer(hddB.server); closeServer(registry.server); });
  const app = await startApp(loadFrontDoor({ HDD_ORIGIN_SECRET: SECRET, HDD_GATE_URL: 'http://127.0.0.1:9', HDD_GATE_URL_FROM: registry.url }));
  t.after(() => closeServer(app.server));
  const first = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(first.text, 'from-A');
  current = hddB.url;
  await closeServer(hddA.server); // the old address dies; the next request must re-read the registry
  const second = await call(app, { path: '/', headers: { host: 'shop.example.test' } });
  assert.equal(second.text, 'from-B');
});
