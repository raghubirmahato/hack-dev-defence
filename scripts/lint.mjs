// `npm run lint`: fast static checks for the non-Rust demo kit plus the Rust format
// and clippy gates. It never edits files and never reports a skipped check as a
// pass: a tool that is not installed is printed as SKIP(<reason>).

import { existsSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { fail, info, isWindows, paint, repoRoot, runCaptured } from './lib/util.mjs';

const results = [];

function record(name, status, detail) {
  const ok = status === 'PASS' || status === 'SKIP';
  results.push({ name, status, detail });
  const badge =
    status === 'PASS' ? paint('PASS', 'green') : status === 'FAIL' ? paint('FAIL', 'red') : paint('SKIP', 'yellow');
  console.log(`  ${badge}  ${name}${detail ? ` (${detail})` : ''}`);
  return ok;
}

function findCommand(candidates, probeArgs) {
  for (const candidate of candidates) {
    const probe = runCaptured(candidate, probeArgs, { timeoutMs: 30_000 });
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
    const probe = runCaptured(candidate.command, [
      ...candidate.argsPrefix,
      '-c',
      'import sys; raise SystemExit(0 if sys.version_info[0] == 3 else 1)',
    ]);
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

function globScripts() {
  const entries = [];
  const pushDir = (directory) => {
    if (!existsSync(directory)) return;
    for (const name of readdirSync(directory).sort()) {
      const full = join(directory, name);
      if (name.endsWith('.mjs')) entries.push(full);
    }
  };
  pushDir(join(repoRoot, 'scripts'));
  pushDir(join(repoRoot, 'scripts', 'lib'));
  pushDir(join(repoRoot, 'scripts', 'test'));
  return entries;
}

info('npm run lint: node syntax + lab app syntax + attack script syntax + cargo fmt/clippy');

// 1. Every launcher parses (node --check is a pure syntax check).
let scriptFailures = 0;
for (const file of globScripts()) {
  const check = runCaptured(process.execPath, ['--check', file], { timeoutMs: 30_000 });
  if (check.status !== 0) {
    scriptFailures += 1;
    record(`node --check ${relative(repoRoot, file)}`, 'FAIL', check.stderr.trim().split('\n')[0]);
  }
}
if (scriptFailures === 0) record(`node --check for ${globScripts().length} launcher file(s)`, 'PASS');

// 2. The attack scripts parse with their real interpreters (PowerShell 5.1/7, bash).
const powershell = isWindows
  ? findCommand(['pwsh', 'powershell'], ['-NoProfile', '-Command', 'exit 0'])
  : findCommand(['pwsh'], ['-NoProfile', '-Command', 'exit 0']);
const ps1 = join(repoRoot, 'lab', 'demo', 'attack.ps1');
if (powershell === null) {
  record('attack.ps1 syntax', 'SKIP', 'PowerShell not installed on this platform (the bash twin is checked instead)');
} else {
  const escaped = ps1.replace(/'/g, "''");
  const parse = runCaptured(
    powershell,
    [
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      `$text = [System.IO.File]::ReadAllText('${escaped}'); [void][scriptblock]::Create($text); Write-Output 'attack.ps1 parse OK'`,
    ],
    { timeoutMs: 60_000 },
  );
  record('attack.ps1 syntax', parse.status === 0 ? 'PASS' : 'FAIL', (parse.stdout + parse.stderr).trim().split('\n')[0]);
}

const bashCandidates = isWindows
  ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe', 'bash']
  : ['bash'];
const bash = findCommand(bashCandidates, ['--version']);
const shScript = join(repoRoot, 'lab', 'demo', 'attack.sh');
if (bash === null) {
  record('attack.sh syntax', 'SKIP', 'bash not installed (the PowerShell twin is checked instead)');
} else {
  const parse = runCaptured(bash, ['-n', shScript], { timeoutMs: 30_000 });
  record('attack.sh syntax', parse.status === 0 ? 'PASS' : 'FAIL', parse.stderr.trim().split('\n')[0]);
}

// 3. The deliberately vulnerable lab app parses as Python 3 (starting it is a dev run).
const python = pythonCommand();
const app = join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py');
if (python === null) {
  record('lab/demo/vuln_login/app.py syntax', 'SKIP', 'Python 3 not installed');
} else {
  const compile = runCaptured(python.command, [
    ...python.argsPrefix,
    '-c',
    'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")',
    app,
  ]);
  record('lab/demo/vuln_login/app.py syntax', compile.status === 0 ? 'PASS' : 'FAIL', compile.stderr.trim().split('\n')[0]);
}

// 4. The Rust gates that can run in a lint loop.
const fmt = runCaptured('cargo', ['fmt', '--all', '--check']);
record('cargo fmt --all --check', fmt.status === 0 ? 'PASS' : 'FAIL', (fmt.stderr || fmt.stdout).trim().split('\n')[0]);
const clippy = runCaptured('cargo', ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'], {
  timeoutMs: 900_000,
});
record(
  'cargo clippy --workspace --all-targets -- -D warnings',
  clippy.status === 0 ? 'PASS' : 'FAIL',
  (clippy.stderr || clippy.stdout).trim().split('\n').slice(-1)[0],
);

console.log('');
const failed = results.filter((result) => result.status === 'FAIL');
const skipped = results.filter((result) => result.status === 'SKIP');
if (failed.length > 0) {
  fail(`${failed.length} check(s) FAILED; fix them before merging. Real output is above.`);
  process.exitCode = 1;
} else {
  info(`lint checks PASS${skipped.length > 0 ? ` (${skipped.length} skipped with a printed reason)` : ''}`);
  process.exitCode = 0;
}
