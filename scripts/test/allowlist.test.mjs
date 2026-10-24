// Tests for the target allowlist rules (the same rules the attack scripts enforce).

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkTargetAllowed,
  classifyTarget,
  isLoopbackHost,
  normalizeHost,
  parseTargetsAllow,
} from '../lib/allowlist.mjs';

test('loopback hosts are recognised', () => {
  for (const host of ['127.0.0.1', '127.0.0.2', '127.1.2.3', 'localhost', 'LOCALHOST', '::1', '[::1]']) {
    assert.equal(isLoopbackHost(host), true, `${host} is loopback`);
  }
  for (const host of ['', '0.0.0.0', '10.0.0.1', '192.168.1.1', 'example.com', '127.0.0.256', '127.0.0', '::2']) {
    assert.equal(isLoopbackHost(host), false, `${host} is not loopback`);
  }
});

test('hostnames are normalised before comparison', () => {
  assert.equal(normalizeHost(' [::1] '), '::1');
  assert.equal(normalizeHost('Shop.Example.COM'), 'shop.example.com');
});

test('targets.allow parsing ignores comments, blank lines and CRLF', () => {
  const parsed = parseTargetsAllow(
    ['# operator-created allowlist', '', 'shop.example.com', '  staging.example.org   # staging', '127.0.0.1'].join('\r\n'),
  );
  assert.deepEqual(parsed, ['shop.example.com', 'staging.example.org', '127.0.0.1']);
  assert.deepEqual(parseTargetsAllow(''), []);
});

test('classifyTarget detects the local rehearsal ports and rejects unsafe URLs', () => {
  const direct = classifyTarget('http://127.0.0.1:8081/login');
  assert.equal(direct.valid, true);
  assert.equal(direct.kind, 'direct');
  assert.equal(direct.isLoopback, true);
  assert.equal(direct.port, 8081);

  const proxy = classifyTarget('http://127.0.0.1:8080/');
  assert.equal(proxy.kind, 'proxy');

  const live = classifyTarget('https://shop.example.com/login');
  assert.equal(live.valid, true);
  assert.equal(live.kind, 'target');
  assert.equal(live.isLoopback, false);
  assert.equal(live.port, 443);

  const ipv6 = classifyTarget('http://[::1]:8081/login');
  assert.equal(ipv6.valid, true);
  assert.equal(ipv6.kind, 'direct');
  assert.equal(ipv6.host, '::1');

  assert.equal(classifyTarget('not a url').valid, false);
  assert.equal(classifyTarget('ftp://127.0.0.1/').valid, false);
  assert.equal(classifyTarget('http://user:pass@127.0.0.1:8081/').valid, false); // hdd-secret-scan:allow (test vector: credential URL must be refused)
  assert.match(classifyTarget('http://user:pass@127.0.0.1:8081/').error, /credentials/); // hdd-secret-scan:allow (test vector: credential URL must be refused)
});

test('loopback targets are allowed without an allowlist file', () => {
  const gate = checkTargetAllowed({ targetUrl: 'http://127.0.0.1:8081/login', allowlistText: '' });
  assert.equal(gate.allowed, true);
  assert.match(gate.reason, /loopback/);
});

test('non-loopback targets are refused unless listed (case-insensitive)', () => {
  const refused = checkTargetAllowed({ targetUrl: 'https://shop.example.com/', allowlistText: '' });
  assert.equal(refused.allowed, false);
  assert.match(refused.reason, /not listed in lab\/demo\/targets\.allow/);

  const listed = checkTargetAllowed({
    targetUrl: 'https://shop.example.com/',
    allowlistText: 'other.example.org\nShop.Example.COM # the site we may test\n',
  });
  assert.equal(listed.allowed, true);
  assert.match(listed.reason, /listed/);

  const wrong = checkTargetAllowed({
    targetUrl: 'https://evil.example.com/',
    allowlistText: 'shop.example.com\n',
  });
  assert.equal(wrong.allowed, false);
});

test('invalid targets are refused before any request', () => {
  const gate = checkTargetAllowed({ targetUrl: 'http://user:pass@example.com/', allowlistText: 'example.com' }); // hdd-secret-scan:allow (test vector: credential URL must be refused)
  assert.equal(gate.allowed, false);
  assert.match(gate.reason, /credentials/);
});
