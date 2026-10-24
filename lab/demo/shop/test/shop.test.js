'use strict';
const test = require('node:test');
const assert = require('node:assert');
process.env.ADMIN_PASSWORD = 'unit-test-password'; // hdd-secret-scan:allow (test value)
process.env.SESSION_SECRET = 'unit-test-session-secret'; // hdd-secret-scan:allow (test value)
const app = require('../api/app');

function call(method, url, { body, headers = {} } = {}) {
  return new Promise((resolve) => {
    const req = { method, url, headers, body, async *[Symbol.asyncIterator]() {} };
    const res = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(t) { resolve({ status: this.statusCode, headers: this.headers, text: t || '' }); } };
    app(req, res);
  });
}
const adminCookie = async () => {
  const r = await call('POST', '/admin/login', { body: { username: 'admin', password: 'unit-test-password' } }); // hdd-secret-scan:allow (test value)
  return r.headers['set-cookie'].split(';')[0];
};

test('the storefront lists computer hardware and filters by category and search', async () => {
  const all = await call('GET', '/');
  assert.equal(all.status, 200);
  assert.match(all.text, /Voltrix VX 4070 Ti/);
  assert.match(all.text, /CoreByte/);
  const gpu = await call('GET', '/?c=gpu');
  assert.match(gpu.text, /Voltrix VX 4060/);
  assert.doesNotMatch(gpu.text, /Helix NVMe/);
  const q = await call('GET', '/?q=nvme');
  assert.match(q.text, /Helix NVMe/);
  const inj = await call('GET', "/?q=' OR 1=1--");
  assert.match(inj.text, /0 products/);
});
test('a product page, the cart and checkout create an order the admin can see', async () => {
  const pg = await call('GET', '/product?id=3');
  assert.match(pg.text, /NovaCore N7-7800/);
  const add = await call('POST', '/cart/add', { body: { id: '3' } });
  assert.equal(add.status, 303);
  const cookie = add.headers['set-cookie'].split(';')[0];
  const cart = await call('GET', '/cart', { headers: { cookie } });
  assert.match(cart.text, /NovaCore N7-7800/);
  const co = await call('POST', '/checkout', { headers: { cookie }, body: { name: 'Test Buyer', email: 'buyer@example.test', address: '1 Test St' } });
  assert.equal(co.status, 200);
  assert.match(co.text, /Thank you, Test Buyer/);
  const a = await call('GET', '/admin/orders', { headers: { cookie: await adminCookie() } });
  assert.match(a.text, /Test Buyer/);
});
test('a wrong password does not reach the admin panel', async () => {
  const r = await call('POST', '/admin/login', { body: { username: 'admin', password: 'wrong' } });
  assert.equal(r.status, 401);
  assert.equal((await call('GET', '/admin')).status, 303);
  assert.equal((await call('GET', '/admin/orders')).status, 303);
});
test('the real admin password opens the dashboard, orders, products, customers and team pages', async () => {
  const cookie = await adminCookie();
  for (const [path, re] of [['/admin', /Revenue/], ['/admin/orders', /Order/], ['/admin/products', /SKU/], ['/admin/customers', /Customers/], ['/admin/team', /Username/]]) {
    const a = await call('GET', path, { headers: { cookie } });
    assert.equal(a.status, 200, path);
    assert.match(a.text, re, path);
  }
});
test('the deliberately injectable login is bypassed by a tautology and by a comment (the demo vulnerability)', async () => {
  for (const u of ["' OR 1=1--", "admin' --", "' or 1=1 LIMIT 1 --"]) {
    const r = await call('POST', '/admin/login', { body: { username: u, password: 'x' } });
    assert.equal(r.status, 303, u);
  }
});
test('a forged cookie is refused', async () => {
  const a = await call('GET', '/admin', { headers: { cookie: 'hddshop=admin%3Aadmin.deadbeef' } });
  assert.equal(a.status, 303);
});
test('a malformed cookie is treated as signed out, not as a server error', async () => {
  const a = await call('GET', '/admin', { headers: { cookie: 'hddshop=%E0%A4%A' } });
  assert.equal(a.status, 303);
});

test('no page of the shop may be kept by a browser or a shared cache', async () => {
  const app = require('../api/app');
  for (const url of ['/', '/product?id=1', '/cart', '/admin/login', '/healthz', '/nope']) {
    const r = await new Promise((resolve) => {
      const req = { method: 'GET', url, headers: {}, async *[Symbol.asyncIterator]() {} };
      const res = { statusCode: 200, h: {}, setHeader(k, v) { this.h[k.toLowerCase()] = String(v); }, end(t) { resolve({ status: this.statusCode, h: this.h }); } };
      app(req, res);
    });
    assert.match(r.h['cache-control'] || '', /no-store/, `${url} (${r.status})`);
  }
});
