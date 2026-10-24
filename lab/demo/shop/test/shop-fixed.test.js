'use strict';
// Lab-only test (Addendum 6 demo plumbing): the same injection payload is refused when
// the shop runs with the parameterised login (SHOP_VULN=0) and acceped when it runs
// with the deliberately vulnerable concatenated login. It starts two real server.js
// children on free loopback ports so the env switch is exercised the same way
// `npm run dev` / `npm run demo:fixed` uses it.
//
// Run with: npm install (inside lab/demo/shop) then
//   node --test test/shop-fixed.test.js
// The repo root `npm run test:scripts` does not run this file because the shop has a
// lab-only sql.js dependency that is installed separately.

const test = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');

const SHOP_DIR = path.join(__dirname, '..');
const hasSqlJs = fs.existsSync(path.join(SHOP_DIR, 'node_modules', 'sql.js'));

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function post(port, route, form) {
  return new Promise((resolve, reject) => {
    const body = Object.entries(form).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const req = http.request(
      { host: '127.0.0.1', port, path: route, method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) } },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

function startShop(port, extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(SHOP_DIR, 'server.js')], {
      cwd: SHOP_DIR,
      env: { ...process.env, PORT: String(port), ADMIN_PASSWORD: 'admin', SESSION_SECRET: 'shop-fixed-test-secret', ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`shop did not start on ${port}: ${output}`));
    }, 15_000);
    const onLine = (chunk) => {
      output += chunk.toString();
      if (output.includes(`shop on http://127.0.0.1:${port}`)) {
        clearTimeout(timeout);
        resolve({ child, output });
      }
    };
    child.stdout.on('data', onLine);
    child.stderr.on('data', onLine);
    child.on('error', reject);
  });
}

async function withShop(extraEnv, run) {
  const port = await freePort();
  const shop = await startShop(port, extraEnv);
  try {
    return await run(port);
  } finally {
    shop.child.kill();
  }
}

test('SHOP_VULN=0 refuses the injection and still allows the real admin login', { skip: hasSqlJs ? false : 'sql.js not installed in lab/demo/shop (run npm install once)' }, async () => {
  await withShop({ SHOP_VULN: '0' }, async (port) => {
    const attacked = await post(port, '/admin/login', { username: "' OR 1=1--", password: 'x' });
    assert.equal(attacked.status, 401, 'fixed login must refuse the tautology payload; a 303 would be the vulnerable path');
    assert.doesNotMatch(attacked.body, /Demo data only/, 'fixed login must not render the admin dashboard');
    const real = await post(port, '/admin/login', { username: 'admin', password: 'admin' });
    assert.equal(real.status, 303, 'the real fake admin/admin credential still logs in when fixed');
    assert.equal(real.headers.location, '/admin');
  });
});

test('SHOP_VULN unset is the deliberately injectable demo login', { skip: hasSqlJs ? false : 'sql.js not installed in lab/demo/shop (run npm install once)' }, async () => {
  await withShop({}, async (port) => {
    const attacked = await post(port, '/admin/login', { username: "' OR 1=1--", password: 'x' });
    assert.equal(attacked.status, 303, 'vulnerable login must accept the tautology payload and redirect to /admin');
    assert.equal(attacked.headers.location, '/admin');
  });
});
