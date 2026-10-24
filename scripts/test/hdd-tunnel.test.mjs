// Tests for the demo-only localhost.run tunnel helper (COLLAB.md Addendum 7 item 4).
//
// Everything here is pure: the ssh command line, the public-URL parser, the heartbeat
// URL, the restart backoff and the announcement lines. The two `main` tests inject a fake
// spawnSync/out/err, so no real ssh process is started and no network request is made.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BASE_BACKOFF_MS,
  DEFAULT_PORT,
  HEARTBEAT_INTERVAL_MS,
  MAX_BACKOFF_MS,
  SSH_OPTIONS,
  SSH_TARGET,
  STABLE_RUN_MS,
  backoffMs,
  buildSshArgs,
  heartbeatUrl,
  main,
  missingSshLines,
  parseArgs,
  parsePort,
  parsePublicUrl,
  publicUrlLines,
  shouldResetBackoff,
  sshAvailable,
} from '../hdd-tunnel.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

function fakeSpawnSync({ error = undefined } = {}) {
  return () => ({ error, status: error === undefined ? 0 : null, stdout: '', stderr: '' });
}

function noSpawn() {
  throw new Error('the tunnel must not spawn ssh when it refuses to start');
}

test('buildSshArgs is the exact documented localhost.run reverse tunnel command', () => {
  assert.deepEqual(buildSshArgs(DEFAULT_PORT), [
    '-o',
    'ServerAliveInterval=15',
    '-o',
    'ServerAliveCountMax=3',
    '-o',
    'ExitOnForwardFailure=yes',
    '-R',
    '80:127.0.0.1:8080',
    'nokey@localhost.run',
  ]);
  assert.deepEqual(buildSshArgs(18080), [
    ...SSH_OPTIONS,
    '-R',
    '80:127.0.0.1:18080',
    SSH_TARGET,
  ]);
  assert.ok(SSH_OPTIONS.includes('ServerAliveInterval=15'));
  assert.ok(SSH_OPTIONS.includes('ServerAliveCountMax=3'));
  assert.ok(SSH_OPTIONS.includes('ExitOnForwardFailure=yes'));
  assert.throws(() => buildSshArgs(0), /between 1 and 65535/);
});

test('parsePort accepts only whole numbers from 1 to 65535', () => {
  assert.equal(parsePort('8080'), 8080);
  assert.equal(parsePort(8080), 8080);
  assert.equal(parsePort('1'), 1);
  assert.equal(parsePort('65535'), 65535);
  for (const bad of ['0', '65536', '-1', 'abc', '', '80.5', '  ', '8080x']) {
    assert.throws(() => parsePort(bad), /between 1 and 65535/, `port "${bad}" is refused`);
  }
});

test('parseArgs parses --port/--port= and rejects unknown options', () => {
  assert.deepEqual(parseArgs([]), { port: DEFAULT_PORT, help: false, gist: null });
  assert.deepEqual(parseArgs(['--port', '3000']), { port: 3000, help: false, gist: null });
  assert.deepEqual(parseArgs(['--port=3000']), { port: 3000, help: false, gist: null });
  assert.deepEqual(parseArgs(['--help']), { port: DEFAULT_PORT, help: true, gist: null });
  assert.throws(() => parseArgs(['--port']), /needs a value between 1 and 65535/);
  assert.throws(() => parseArgs(['--port', '0']), /between 1 and 65535/);
  assert.throws(() => parseArgs(['--bogus']), /unknown option/);
  assert.equal(parseArgs(['--publish-gist', '7e2a7c825c1a229b3905577da6dfd36f']).gist, '7e2a7c825c1a229b3905577da6dfd36f');
  assert.throws(() => parseArgs(['--publish-gist', 'x; rm -rf /']), /gist id/);
  assert.throws(() => parseArgs(['--publish-gist']), /needs a gist id/);
});

test('parsePublicUrl reads the URL from realistic localhost.run output only', () => {
  const banner = [
    '===============================================================================',
    'Welcome to localhost.run!',
    '',
    'Follow your favourite reverse tunnel at https://localhost.run/.',
    '',
    '** your connection id is 6d1f2c3b-9a44-4a0e-9d55-3f8a1b2c4d5e **',
    '',
    '9f2c1d4e8a7b.lhr.life tunneled with tls termination, https://9f2c1d4e8a7b.lhr.life',
    '',
  ].join('\r\n');
  assert.equal(parsePublicUrl(banner), 'https://9f2c1d4e8a7b.lhr.life');
  // A newer address of the same service (subdomain form) is accepted too.
  assert.equal(
    parsePublicUrl('abcd1234.localhost.run tunneled with tls termination, https://abcd1234.localhost.run'),
    'https://abcd1234.localhost.run',
  );
  // Trailing sentence punctuation is not part of the URL.
  assert.equal(
    parsePublicUrl('see https://1a2b3c4d.lhr.life tunneled with tls termination, https://1a2b3c4d.lhr.life.'),
    'https://1a2b3c4d.lhr.life',
  );
  // The service's own home-page links are never mistaken for the tunnel URL.
  assert.equal(parsePublicUrl('Welcome to localhost.run: https://localhost.run/ and https://admin.localhost.run/'), null);
  assert.equal(parsePublicUrl('nothing useful here'), null);
  assert.equal(parsePublicUrl(''), null);
});

test('heartbeatUrl targets <url>/healthz every 8 s', () => {
  assert.equal(heartbeatUrl('https://9f2c1d4e8a7b.lhr.life'), 'https://9f2c1d4e8a7b.lhr.life/healthz');
  assert.equal(heartbeatUrl('https://9f2c1d4e8a7b.lhr.life/'), 'https://9f2c1d4e8a7b.lhr.life/healthz');
  assert.throws(() => heartbeatUrl('not-a-url'), /URL/);
  assert.throws(() => heartbeatUrl('ftp://example.test'), /http\(s\)/);
  assert.equal(HEARTBEAT_INTERVAL_MS, 8000);
});

test('backoffMs is exponential and bounded; a stable run resets it', () => {
  assert.equal(backoffMs(0), BASE_BACKOFF_MS);
  assert.equal(backoffMs(1), 2_000);
  assert.equal(backoffMs(2), 4_000);
  assert.equal(backoffMs(3), 8_000);
  assert.equal(backoffMs(10), MAX_BACKOFF_MS);
  assert.equal(backoffMs(1_000), MAX_BACKOFF_MS);
  assert.equal(backoffMs(-2), BASE_BACKOFF_MS);
  assert.equal(MAX_BACKOFF_MS, 30_000);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    assert.ok(backoffMs(attempt) >= BASE_BACKOFF_MS);
    assert.ok(backoffMs(attempt) <= MAX_BACKOFF_MS);
  }
  assert.equal(shouldResetBackoff(1_000, 1_000 + STABLE_RUN_MS), true);
  assert.equal(shouldResetBackoff(1_000, 1_000 + STABLE_RUN_MS - 1), false);
  assert.equal(shouldResetBackoff(Number.NaN, 10_000), false);
});

test('sshAvailable reports a missing ssh from an injected spawnSync', () => {
  const enoent = Object.assign(new Error('spawnSync ssh ENOENT'), { code: 'ENOENT' });
  assert.equal(sshAvailable(fakeSpawnSync()), true);
  assert.equal(sshAvailable(fakeSpawnSync({ error: enoent })), false);
  assert.equal(sshAvailable(() => ({ error: null, status: 1 })), true);
  assert.equal(
    sshAvailable(() => {
      throw new Error('spawnSync itself failed');
    }),
    false,
  );
});

test('main refuses to start without ssh, names it and how to install it', async () => {
  const out = [];
  const err = [];
  const enoent = Object.assign(new Error('spawnSync ssh ENOENT'), { code: 'ENOENT' });
  const code = await main([], {
    spawnSync: fakeSpawnSync({ error: enoent }),
    spawn: noSpawn,
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  });
  assert.equal(code, 1);
  const text = err.join('\n');
  assert.match(text, /ssh/);
  assert.match(text, /OpenSSH/);
  assert.match(text, /install/i);
  assert.match(text, /Windows/);
  assert.match(text, /apt install openssh-client/);
  assert.match(text, /no fallback tunnel/);
  assert.deepEqual(out, [], 'nothing was announced and nothing was started');
  assert.match(missingSshLines().join('\n'), /nothing was started/);
});

test('main prints usage for --help without checking or starting ssh', async () => {
  const out = [];
  let syncCalls = 0;
  const code = await main(['--help'], {
    spawnSync: () => {
      syncCalls += 1;
      return { error: undefined, status: 0 };
    },
    spawn: noSpawn,
    out: (line) => out.push(line),
    err: () => {},
  });
  assert.equal(code, 0);
  assert.equal(syncCalls, 0);
  const text = out.join('\n');
  assert.match(text, /--port/);
  assert.match(text, /nokey@localhost\.run/);
});

test('the URL announcement names the change and the Vercel step', () => {
  const first = publicUrlLines('https://one.lhr.life');
  assert.equal(first[0], 'HDD_GATE_URL=https://one.lhr.life');
  assert.doesNotMatch(first.join('\n'), /changed/i);
  assert.match(first.join('\n'), /Vercel/);
  assert.match(first.join('\n'), /Environment Variables/);
  assert.match(first.join('\n'), /redeploy/);

  const changed = publicUrlLines('https://two.lhr.life', 'https://one.lhr.life');
  const text = changed.join('\n');
  assert.match(text, /changed/i);
  assert.match(text, /https:\/\/one\.lhr\.life -> https:\/\/two\.lhr\.life/);
  assert.match(text, /HDD_GATE_URL=https:\/\/two\.lhr\.life/);
  assert.match(text, /Vercel/);
  assert.match(text, /Environment Variables/);
  assert.match(text, /redeploy/);
  // No change, no noise.
  assert.deepEqual(publicUrlLines('https://one.lhr.life', 'https://one.lhr.life'), first);
});

test('package.json exposes the helper as npm run tunnel and stays dependency-free', () => {
  const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.tunnel, 'node scripts/hdd-tunnel.mjs');
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
});
