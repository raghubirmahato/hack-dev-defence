// Deterministic tests for the launcher prerequisite check.
//
// The spawnSync implementation and the Node version are injected, so the test does
// not depend on what is installed on the machine: it proves that missing tools are
// reported with actionable errors instead of a stack trace or a half-started stack.

import assert from 'node:assert/strict';
import test from 'node:test';

import { checkPrerequisites, MIN_NODE_MAJOR } from '../lib/prereqs.mjs';

const VERSIONS = {
  cargo: 'cargo 1.98.1 (797e8a9bc 2026-08-05)\n',
  python: 'Python 3.14.6\n',
  python3: 'Python 3.14.6\n',
  py: 'Python 3.14.6\n',
  'cargo-watch': 'cargo-watch 8.5.3\n',
};

/**
 * Fake spawnSync: `available` lists the commands present on the fake PATH.
 * `cargo-watch` is special: it is probed as `cargo watch --version`.
 */
function fakeSpawnSync(available) {
  return (command, args = []) => {
    if (command === 'cargo' && args[0] === 'watch') {
      if (available.includes('cargo-watch')) {
        return { status: 0, stdout: VERSIONS['cargo-watch'], stderr: '' };
      }
      return { status: 101, stdout: '', stderr: 'error: no such command: `watch`' };
    }
    if (available.includes(command)) {
      return { status: 0, stdout: VERSIONS[command] ?? '', stderr: '' };
    }
    const error = new Error(`spawn ${command} ENOENT`);
    error.code = 'ENOENT';
    return { status: null, error, stdout: '', stderr: '' };
  };
}

test('missing cargo, old Node and missing Python are reported honestly', () => {
  const result = checkPrerequisites({
    env: { PATH: '' },
    spawnSyncImpl: fakeSpawnSync([]),
    nodeVersion: '16.4.0',
    platform: 'win32',
  });
  assert.equal(result.ok, false);
  const text = result.errors.join('\n');
  assert.match(text, /cargo was not found on PATH/);
  assert.match(text, /Node\.js 16\.4\.0 is too old/);
  assert.match(text, /Python 3 was not found/);
  assert.match(text, /rustup\.rs/);
  assert.match(text, /python\.org/);
  for (const error of result.errors) {
    assert.ok(error.length > 40, `error message is actionable: ${error}`);
    assert.ok(!error.includes('\n'), 'errors are one-liners so they print cleanly');
  }
  assert.equal(result.details.cargo.found, false);
  assert.equal(result.python.found, false);
});

test('a healthy toolchain passes and reports the versions it found', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo', 'python3']),
    nodeVersion: '24.18.0',
    platform: 'linux',
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.details.cargo.version, '1.98.1');
  assert.equal(result.python.found, true);
  assert.equal(result.python.command, 'python3');
  assert.equal(result.details.cargoWatch.found, false);
  assert.match(result.notes.join('\n'), /live reload: unavailable/);
});

test('Node older than the minimum is the only error when the rest exists', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo', 'python']),
    nodeVersion: `${MIN_NODE_MAJOR - 1}.0.0`,
    platform: 'win32',
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /Node\.js .* is too old/);
});

test('missing Python only: the error names the lab origin and Python 3', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo']),
    nodeVersion: '24.18.0',
    platform: 'win32',
  });
  assert.equal(result.ok, false);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /Python 3 was not found/);
  assert.match(result.errors[0], /lab\/demo\/vuln_login\/app\.py/);
});

test('cargo-watch present turns live reload on in the notes', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo', 'python', 'cargo-watch']),
    nodeVersion: '24.18.0',
    platform: 'linux',
  });
  assert.equal(result.ok, true);
  assert.equal(result.details.cargoWatch.found, true);
  assert.match(result.notes.join('\n'), /live reload: cargo-watch 8\.5\.3 found/);
});

test('Windows falls back to py -3 when python is absent', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo', 'py']),
    nodeVersion: '24.18.0',
    platform: 'win32',
  });
  assert.equal(result.ok, true);
  assert.equal(result.python.command, 'py');
  assert.deepEqual(result.python.argsPrefix, ['-3']);
});

test('the Node lab shop run does not require Python', () => {
  const result = checkPrerequisites({
    spawnSyncImpl: fakeSpawnSync(['cargo']),
    nodeVersion: '24.18.0',
    platform: 'win32',
    requiresPython: false,
  });
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);
  assert.match(result.notes.join('\n'), /not needed for this run/);
});