// Tests for the HK1 payload catalogue: the six mandated SQL-injection payloads must
// match docs/SPEC.md (C4.1 / E1.1) exactly, the six auth-bypass forms must match the
// HK1 assignment, and both attack scripts must read the same catalogue and print the
// required "reached admin / blocked yes/no per payload" headers.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

const MANDATED = {
  M1: "' OR 1=1--",
  M2: "' OR '1'='1",
  M3: "admin' --",
  M4: "admin' #",
  M5: "admin'/*",
  M6: "' or 1=1 LIMIT 1 --",
};

const AUTH_BYPASS = {
  B1: "admin'--",
  B2: "admin' or '1'='1",
  B3: "admin') or ('1'='1",
  B4: "' or 1=1#",
  B5: '" or ""="',
  B6: "admin'/*",
};

function parsePayloadCatalogue(text) {
  const rows = [];
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.trim() === '' || rawLine.trimStart().startsWith('#')) continue;
    const parts = rawLine.split('\t');
    assert.equal(parts.length, 3, `payload line must have 3 tab-separated columns: ${JSON.stringify(rawLine)}`);
    rows.push({ id: parts[0], group: parts[1], payload: parts[2] });
  }
  return rows;
}

test('payload catalogue has exactly the six mandated + six auth-bypass payloads', () => {
  const text = readFileSync(join(repoRoot, 'lab', 'demo', 'payloads.tsv'), 'utf8');
  const rows = parsePayloadCatalogue(text);
  assert.equal(rows.length, 12);
  assert.deepEqual(
    rows.map((row) => row.id),
    ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'B1', 'B2', 'B3', 'B4', 'B5', 'B6'],
  );
  for (const [id, payload] of Object.entries(MANDATED)) {
    const row = rows.find((candidate) => candidate.id === id);
    assert.ok(row, `mandated payload ${id} present`);
    assert.equal(row.group, 'mandated');
    assert.equal(row.payload, payload, `${id} is exactly the spec payload`);
  }
  for (const [id, payload] of Object.entries(AUTH_BYPASS)) {
    const row = rows.find((candidate) => candidate.id === id);
    assert.ok(row, `auth-bypass payload ${id} present`);
    assert.equal(row.group, 'auth-bypass');
    assert.equal(row.payload, payload, `${id} is exactly the assignment payload`);
  }
});

test('the six mandated payloads appear in docs/SPEC.md (C4.1 / E1.1)', () => {
  const spec = readFileSync(join(repoRoot, 'docs', 'SPEC.md'), 'utf8');
  for (const [id, payload] of Object.entries(MANDATED)) {
    assert.ok(spec.includes(payload), `docs/SPEC.md contains mandated payload ${id} (${payload})`);
  }
  assert.ok(spec.includes('The mandated SQL injection set'), 'E1.1 section is present');
});

test('both attack scripts read the shared catalogue and print the required headers', () => {
  const ps1 = readFileSync(join(repoRoot, 'lab', 'demo', 'attack.ps1'), 'utf8');
  const sh = readFileSync(join(repoRoot, 'lab', 'demo', 'attack.sh'), 'utf8');
  for (const content of [ps1, sh]) {
    assert.ok(content.includes('payloads.tsv'), 'attack script reads lab/demo/payloads.tsv');
    assert.ok(content.includes('direct origin: reached admin yes/no per payload'), 'direct header');
    assert.ok(content.includes('through HDD: blocked yes/no per payload'), 'proxy header');
    assert.ok(content.includes('targets.allow'), 'attack script enforces the allowlist');
    assert.ok(content.includes('loopback'), 'attack script documents the loopback exception');
    assert.ok(content.includes('/admin/login'), 'attack script defaults to the lab shop login POST /admin/login');
    assert.ok(/Demo data only/i.test(content), 'attack script detects the lab shop admin dashboard marker');
    assert.match(content, /no scanning/i, 'attack script states it does not scan');
  }
});

test('the lab app documents that it is intentionally vulnerable and loopback only', () => {
  const app = readFileSync(join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py'), 'utf8');
  assert.match(app, /INTENTIONALLY VULNERABLE/i);
  assert.match(app, /never (be )?exposed/i);
  assert.ok(app.includes("WHERE username='%s' AND password='%s'"), 'the real concatenated SQL query is present');
  assert.ok(!/parameteri[sz]ed|placeholder/i.test(app.split('\n').filter((line) => line.includes("WHERE username='%s'")).join('\n')));
});

test('the lab app seeds random passwords instead of a hardcoded default', () => {
  const app = readFileSync(join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py'), 'utf8');
  assert.ok(app.includes('secrets.token_urlsafe'), 'seeded passwords are random per run');
  assert.ok(app.includes('printed once') || app.includes('printed once per run'), 'passwords are printed once to the console');
  assert.ok(!/password\s*=\s*["'](admin|password|changeme|demo)["']/i.test(app), 'no hardcoded default password');
});
