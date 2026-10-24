// `npm run build`: build the Rust workspace (default members; the lab Vuln-Lab crate
// is excluded from default-members by repository rule). This is the same cargo build
// the rest of the repository uses, so nothing here is a special "demo build".

import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { fail, info, isWindows, repoRoot, runCaptured, runVisible } from './lib/util.mjs';

const HELP = `Usage: npm run build [-- --help]

Runs "cargo build" for the Rust workspace default members (crates/hdd-proxy included;
lab/vulnlab excluded by the repository rule) and checks that the proxy binary exists.
Optionally compiles the lab Python app as a syntax check when Python 3 is available.
`;

if (process.argv.slice(2).includes('--help')) {
  console.log(HELP);
  process.exitCode = 0;
} else {
  info('building the Rust workspace: cargo build (default members; lab/vulnlab excluded by repository rule)');
  const status = runVisible('cargo', ['build']);
  if (status !== 0) {
    fail(
      'cargo build failed (see the output above). This is the same build the Rust gates use; ' +
        'run "npm run lint" / "npm test" for the full format + clippy + nextest gates.',
    );
    process.exitCode = status;
  } else {
    const binary = join(repoRoot, 'target', 'debug', isWindows ? 'hdd-proxy.exe' : 'hdd-proxy');
    if (existsSync(binary)) {
      info('cargo build OK; proxy binary target/debug/hdd-proxy is ready for "npm run dev"');
    } else {
      info('cargo build OK (the hdd-proxy binary was not produced; check Cargo.toml members/default-members)');
    }
    // The lab origin is outside the Rust build; a Python syntax check is cheap and honest.
    const python = findPython();
    if (python === null) {
      info('Python 3 not found: skipped the lab origin syntax check (npm run dev will report it as a prerequisite)');
    } else {
      const appPath = join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py');
      const check = runCaptured(python.command, [
        ...python.argsPrefix,
        '-c',
        'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")',
        appPath,
      ]);
      if (check.status !== 0) {
        fail(`lab origin syntax check failed for ${appPath}:\n${check.stderr.trim()}`);
        process.exitCode = 1;
      } else {
        info('lab origin syntax check OK: lab/demo/vuln_login/app.py compiles');
        process.exitCode = 0;
      }
    }
  }
}

function findPython() {
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
