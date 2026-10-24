'use strict';
// The origin lock turns itself on when a secret is configured, and only a request that carries HDD's secret header gets in.
process.env.HDD_ORIGIN_SECRET = 'lock-test-secret-value'; // hdd-secret-scan:allow (test value)
process.env.ADMIN_PASSWORD = 'unit-test-password'; // hdd-secret-scan:allow (test value)
process.env.SESSION_SECRET = 'unit-test-session-secret'; // hdd-secret-scan:allow (test value)
delete process.env.ORIGIN_LOCKDOWN;
const test = require('node:test');
const assert = require('node:assert');
const app = require('../api/app');

function call(method, url, { headers = {} } = {}) {
  return new Promise((resolve) => {
    const req = { method, url, headers, async *[Symbol.asyncIterator]() {} };
    const res = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(t) { resolve({ status: this.statusCode, headers: this.headers, text: t || '' }); } };
    app(req, res);
  });
}

test('a direct request (no secret header) is refused with a clear message', async () => {
  const r = await call('GET', '/');
  assert.equal(r.status, 403);
  assert.match(r.text, /Hack Dev Defence/);
});
test('a request with the wrong secret is refused', async () => {
  const r = await call('GET', '/', { headers: { 'x-hdd-origin-secret': 'wrong' } });
  assert.equal(r.status, 403);
});
test('a request that carries HDD\'s secret header is served', async () => {
  const r = await call('GET', '/', { headers: { 'x-hdd-origin-secret': 'lock-test-secret-value' } });
  assert.equal(r.status, 200);
  assert.match(r.text, /CoreByte/);
});
test('the health check also needs the secret, so the lock has no side door', async () => {
  const direct = await call('GET', '/healthz');
  assert.equal(direct.status, 403);
  const viaHdd = await call('GET', '/healthz', { headers: { 'x-hdd-origin-secret': 'lock-test-secret-value' } });
  assert.equal(viaHdd.status, 200);
});

test('HDD_ORIGIN_SECRET wins over the older ORIGIN_SECRET_VALUE name', async () => {
  process.env.ORIGIN_SECRET_VALUE = 'old-name-value'; // hdd-secret-scan:allow (test value)
  delete require.cache[require.resolve('../api/app')];
  const fresh = require('../api/app');
  const r = await new Promise((resolve) => {
    const req = { method: 'GET', url: '/healthz', headers: { 'x-hdd-origin-secret': 'lock-test-secret-value' }, async *[Symbol.asyncIterator]() {} };
    const res = { statusCode: 200, headers: {}, setHeader() {}, end(x) { resolve({ status: this.statusCode, text: x || '' }); } };
    fresh(req, res);
  });
  assert.equal(r.status, 200);
  delete process.env.ORIGIN_SECRET_VALUE;
});
