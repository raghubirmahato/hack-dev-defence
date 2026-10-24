// `npm test`: the node --test suite for the launchers plus the Rust gates
// (fmt check, clippy -D warnings, nextest). The Rust gates stay the authority for
// the Rust crates; a PASS here is evidence for exactly these commands on this
// machine, nothing more (R-02, R-10).

import { fail, formatCommand, info, paint, runVisible } from './lib/util.mjs';

const HELP = `Usage: npm test [-- --only <substring>]

Runs, in order:
  1. node --test scripts/test/*.test.mjs   (launcher/prereq/allowlist/payload tests)
  2. cargo fmt --all --check
  3. cargo clippy --workspace --all-targets -- -D warnings
  4. cargo nextest run --workspace --no-fail-fast
--only <substring> runs only the gates whose name contains the substring.
`;

const argv = process.argv.slice(2);
if (argv.includes('--help')) {
  console.log(HELP);
  process.exitCode = 0;
} else {
  let only = '';
  const onlyIndex = argv.indexOf('--only');
  if (onlyIndex !== -1) {
    only = String(argv[onlyIndex + 1] ?? '');
    if (only === '') {
      fail('--only needs a substring (for example --only node)');
      process.exitCode = 2;
    }
  }

  const gates = [
    {
      name: 'node --test (launcher tests)',
      command: process.execPath,
      args: ['scripts/run-node-tests.mjs'],
    },
    {
      name: 'cargo fmt --all --check',
      command: 'cargo',
      args: ['fmt', '--all', '--check'],
    },
    {
      name: 'cargo clippy --workspace --all-targets -- -D warnings',
      command: 'cargo',
      args: ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'],
    },
    {
      name: 'cargo nextest run --workspace --no-fail-fast',
      command: 'cargo',
      args: ['nextest', 'run', '--workspace', '--no-fail-fast'],
    },
  ];

  info('npm test: node launcher tests + the Rust gates (fmt, clippy, nextest)');
  info('the Rust gates are the authority for the Rust crates; this script only runs them honestly');
  if (only !== '') info(`--only ${only}`);

  const results = [];
  for (const gate of gates) {
    if (only !== '' && !gate.name.includes(only)) continue;
    info(`running: ${formatCommand(gate.command, gate.args)}`);
    const startedAt = Date.now();
    const status = runVisible(gate.command, gate.args);
    const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
    const ok = status === 0;
    results.push({ name: gate.name, ok, seconds });
    console.log(`  ${ok ? paint('PASS', 'green') : paint('FAIL', 'red')}  ${gate.name} (${seconds} s)`);
    if (!ok && gate.name.includes('nextest') && status !== 0) {
      fail('cargo nextest failed or is not installed: install it with "cargo install cargo-nextest --locked" or run "cargo test" if the repository policy allows it');
    }
  }

  console.log('');
  const failed = results.filter((result) => !result.ok);
  for (const result of results) {
    console.log(`  ${result.ok ? paint('PASS', 'green') : paint('FAIL', 'red')}  ${result.name} (${result.seconds} s)`);
  }
  if (failed.length > 0) {
    fail(`${failed.length} gate(s) FAILED. Real output is above; do not report these as passing (R-02).`);
    process.exitCode = 1;
  } else {
    info('all selected gates PASS on this machine (see the per-gate output above for the real result lines)');
    process.exitCode = 0;
  }
}
