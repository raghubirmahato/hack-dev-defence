// Tests that the launcher scripts parse, that package.json stays dependency-free,
// that the dev launcher parses its config/flags, and that the attack scripts and the
// lab app skip/pass honestly with their real interpreters.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { parseArgs, readDevConfig } from '../dev.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const scriptsDir = join(repoRoot, 'scripts');

function checkNode(file) {
  return spawnSync(process.execPath, ['--check', file], { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
}

function findCommand(candidates, probeArgs) {
  for (const candidate of candidates) {
    if (candidate.includes('\\') && !existsSync(candidate)) continue;
    const probe = spawnSync(candidate, probeArgs, { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

function pythonCommand() {
  const candidates =
    process.platform === 'win32'
      ? [
          { command: 'python', argsPrefix: [] },
          { command: 'py', argsPrefix: ['-3'] },
          { command: 'python3', argsPrefix: [] },
        ]
      : [
          { command: 'python3', argsPrefix: [] },
          { command: 'python', argsPrefix: [] },
        ];
  for (const candidate of candidates) {
    const probe = spawnSync(
      candidate.command,
      [...candidate.argsPrefix, '-c', 'import sys; raise SystemExit(0 if sys.version_info[0] == 3 else 1)'],
      { encoding: 'utf8', windowsHide: true, timeout: 30_000 },
    );
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

test('every launcher file parses with node --check', () => {
  const files = [];
  const collect = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      if (name.endsWith('.mjs')) files.push(join(directory, name));
    }
  };
  collect(scriptsDir);
  collect(join(scriptsDir, 'lib'));
  collect(join(scriptsDir, 'test'));
  assert.ok(files.length >= 8, `found launcher files to check (${files.length})`);
  for (const file of files) {
    const result = checkNode(file);
    assert.equal(result.status, 0, `node --check ${file}: ${result.stderr}`);
  }
});

test('package.json is private, dependency-free and points at existing scripts', () => {
  const raw = readFileSync(join(repoRoot, 'package.json'), 'utf8');
  const pkg = JSON.parse(raw);
  assert.equal(pkg.private, true);
  assert.equal(pkg.dependencies, undefined, 'no runtime dependencies (no npm install needed)');
  assert.equal(pkg.devDependencies, undefined, 'no dev dependencies');
  assert.equal(pkg.optionalDependencies, undefined);
  assert.match(pkg.engines.node, /18/);
  const expected = ['dev', 'demo', 'demo:fixed', 'build', 'test', 'test:scripts', 'attack', 'lint'];
  for (const name of expected) {
    assert.ok(typeof pkg.scripts[name] === 'string', `npm script "${name}" exists`);
    const value = pkg.scripts[name];
    assert.ok(!value.includes('&&') && !value.includes('||'), `"${name}" has no shell-specific operators`);
    assert.match(value, /^node /, `"${name}" runs a node launcher`);
    const target = resolve(repoRoot, value.split(/\s+/)[1]);
    assert.ok(existsSync(target), `"${name}" launcher exists: ${target}`);
  }
});

test('dev.mjs parses its flags and the dev profile endpoints', () => {
  const defaults = parseArgs([]);
  assert.equal(defaults.config, 'demo/hdd-dev.yaml');
  assert.equal(defaults.walkthrough, false);
  assert.equal(defaults.fixed, false);
  assert.equal(defaults.build, true);
  const configured = parseArgs(['--walkthrough', '--fixed', '--config', 'demo/other.yaml', '--no-build']);
  assert.equal(configured.config, 'demo/other.yaml');
  assert.equal(configured.walkthrough, true);
  assert.equal(configured.fixed, true);
  assert.equal(configured.build, false);
  assert.throws(() => parseArgs(['--bogus']), /unknown option/);
  assert.throws(() => parseArgs(['--config']), /needs a value/);

  const configPath = join(repoRoot, 'demo', 'hdd-dev.yaml');
  if (!existsSync(configPath)) {
    // The integration file is lead-owned; the launcher must say so instead of guessing.
    return;
  }
  const config = readDevConfig(configPath);
  assert.equal(config.listen.port, 8080);
  assert.equal(config.admin.port, 9090);
  assert.equal(config.origin.port, 8082);
  assert.equal(config.mode, 'block');
  assert.equal(config.siteHost, '127.0.0.1');
  assert.equal(config.stack, 'node');
  assert.equal(config.loginPath, '/admin/login');
});

test('attack.ps1 parses with PowerShell when PowerShell is installed', (t) => {
  const shell = findCommand(['pwsh', 'powershell'], ['-NoProfile', '-Command', 'exit 0']);
  if (shell === null) {
    t.skip('PowerShell is not installed on this platform');
    return;
  }
  const script = join(repoRoot, 'lab', 'demo', 'attack.ps1');
  const escaped = script.replace(/'/g, "''");
  const result = spawnSync(
    shell,
    [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      `$text = [System.IO.File]::ReadAllText('${escaped}'); [void][scriptblock]::Create($text)`,
    ],
    { encoding: 'utf8', windowsHide: true, timeout: 90_000 },
  );
  assert.equal(result.status, 0, `attack.ps1 must parse: ${result.stderr}`);
});

test('attack.sh parses with bash -n when bash is installed', (t) => {
  const bash = findCommand(
    process.platform === 'win32'
      ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe', 'bash']
      : ['bash'],
    ['--version'],
  );
  if (bash === null) {
    t.skip('bash is not installed on this platform');
    return;
  }
  const result = spawnSync(bash, ['-n', join(repoRoot, 'lab', 'demo', 'attack.sh')], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30_000,
  });
  assert.equal(result.status, 0, `attack.sh must parse: ${result.stderr}`);
});

test('the lab app compiles as Python 3 when Python 3 is installed', (t) => {
  const python = pythonCommand();
  if (python === null) {
    t.skip('Python 3 is not installed on this platform');
    return;
  }
  const app = join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py');
  const result = spawnSync(
    python.command,
    [
      ...python.argsPrefix,
      '-c',
      'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")',
      app,
    ],
    { encoding: 'utf8', windowsHide: true, timeout: 30_000 },
  );
  assert.equal(result.status, 0, `app.py must compile: ${result.stderr}`);
});

test('README documents the HK1 quickstart honestly', () => {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  assert.ok(readme.includes('npm run dev'), 'README mentions npm run dev');
  assert.ok(readme.includes('docs/DEMO.md'), 'README links the demo script');
  assert.ok(readme.includes('npm run attack'), 'README mentions the attack command');
  assert.match(readme, /not a claim/i, 'README keeps the honest-limits wording');
  assert.match(readme, /fully protected/i, 'README explicitly says the live site is not fully protected');
});
