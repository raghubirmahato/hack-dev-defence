// Prerequisite checks for the HK1 launchers.
//
// The launcher must fail with an honest, actionable message when a tool is missing
// instead of throwing a stack trace or pretending to start. Everything is injectable
// (env, spawnSync impl, nodeVersion) so `node --test` can assert the behaviour
// deterministically without touching the machine's real PATH.

import { spawnSync } from 'node:child_process';

export const MIN_NODE_MAJOR = 18;

/**
 * Probe `<command> <args...>` without throwing.
 * Returns { found, version, output }; found is true only for exit status 0.
 */
export function probeTool(run, env, command, args) {
  const result = run(command, args, {
    encoding: 'utf8',
    windowsHide: true,
    env,
    timeout: 20_000,
    shell: false,
  });
  if (result.error && result.error.code === 'ENOENT') {
    return { found: false, version: null, output: '', command };
  }
  if (result.error) {
    return { found: false, version: null, output: String(result.error.message ?? result.error), command };
  }
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
  if (result.status !== 0) {
    return { found: false, version: null, output, command };
  }
  const versionMatch = /(\d+\.\d+\.\d+)/.exec(output);
  return { found: true, version: versionMatch ? versionMatch[1] : null, output, command };
}

function pythonCandidates(platform) {
  if (platform === 'win32') {
    return [
      { command: 'python', argsPrefix: [] },
      { command: 'py', argsPrefix: ['-3'] },
      { command: 'python3', argsPrefix: [] },
    ];
  }
  return [
    { command: 'python3', argsPrefix: [] },
    { command: 'python', argsPrefix: [] },
  ];
}

function findPython(run, env, platform) {
  for (const candidate of pythonCandidates(platform)) {
    const probe = probeTool(run, env, candidate.command, [
      ...candidate.argsPrefix,
      '-c',
      'import sys; raise SystemExit(0 if sys.version_info[0] == 3 else 1)',
    ]);
    if (probe.found) {
      const versionProbe = probeTool(run, env, candidate.command, [...candidate.argsPrefix, '--version']);
      return {
        found: true,
        command: candidate.command,
        argsPrefix: candidate.argsPrefix,
        version: versionProbe.version,
      };
    }
  }
  return { found: false, command: null, argsPrefix: [], version: null };
}

function nodeMajor(nodeVersion) {
  const major = Number.parseInt(String(nodeVersion).split('.')[0], 10);
  return Number.isFinite(major) ? major : NaN;
}

/**
 * Check the tools the local rehearsal stack needs.
 *
 * @param {object} [options]
 * @param {NodeJS.ProcessEnv} [options.env]                    environment (PATH is what matters)
 * @param {string} [options.nodeVersion]                       defaults to process.versions.node
 * @param {Function} [options.spawnSyncImpl]                   injectable spawnSync (tests)
 * @param {string} [options.platform]                          defaults to process.platform
 * @param {boolean} [options.requiresPython]                   true unless the demo origin is the Node shop
 * @returns {{ok: boolean, errors: string[], warnings: string[], notes: string[],
 *            details: {node: object, cargo: object, python: object, cargoWatch: object},
 *            python: object}}
 */
export function checkPrerequisites(options = {}) {
  const env = options.env ?? process.env;
  const nodeVersion = options.nodeVersion ?? process.versions.node;
  const run = options.spawnSyncImpl ?? spawnSync;
  const platform = options.platform ?? process.platform;
  const requiresPython = options.requiresPython ?? true;

  const errors = [];
  const warnings = [];
  const notes = [];
  const details = {};

  const major = nodeMajor(nodeVersion);
  details.node = { version: nodeVersion, major };
  if (!Number.isFinite(major) || major < MIN_NODE_MAJOR) {
    errors.push(
      `Node.js ${nodeVersion} is too old: the HK1 launchers need Node.js ${MIN_NODE_MAJOR} or newer. ` +
        'Install a current Node.js from https://nodejs.org (or use nvm/fnm) and re-run `npm run dev`.',
    );
  }

  const cargo = probeTool(run, env, 'cargo', ['--version']);
  details.cargo = cargo;
  if (!cargo.found) {
    const pathHint =
      platform === 'win32' ? '%USERPROFILE%\\.cargo\\bin' : '$HOME/.cargo/bin';
    errors.push(
      'cargo was not found on PATH. Install Rust with rustup (https://rustup.rs) and make sure ' +
        `${pathHint} is on PATH, then open a new terminal and re-run. ` +
        'The repository pins its toolchain in rust-toolchain.toml.',
    );
  }

  const python = findPython(run, env, platform);
  details.python = python;
  if (!python.found && requiresPython) {
    errors.push(
      'Python 3 was not found (tried python, python3 and py -3). The deliberately vulnerable lab origin ' +
        'lab/demo/vuln_login/app.py uses the Python standard library only. Install Python 3 from ' +
        'https://www.python.org/downloads/ (on Windows tick "Add python.exe to PATH") and re-run `npm run dev`.',
    );
  }
  if (!python.found && !requiresPython) {
    notes.push('Python 3 not found: not needed for this run (the demo origin is the Node lab shop).');
  }

  // Optional: cargo-watch gives the proxy live reload on crates/** changes.
  const cargoWatch = probeTool(run, env, 'cargo', ['watch', '--version']);
  details.cargoWatch = { found: cargoWatch.found, version: cargoWatch.version };
  if (!cargoWatch.found) {
    notes.push(
      'live reload: unavailable (cargo-watch not installed). The running proxy keeps its current binary; ' +
        'install with `cargo install cargo-watch` and restart `npm run dev` to restart the proxy on Rust changes.',
    );
  } else {
    notes.push(`live reload: cargo-watch ${cargoWatch.version ?? ''} found; the proxy restarts on crates/** changes.`.trim());
  }

  return { ok: errors.length === 0, errors, warnings, notes, details, python };
}

/** Print a prerequisite result in the launcher's log format; returns true when ok. */
export function reportPrerequisites(result, logger) {
  for (const note of result.notes) logger.info(note);
  for (const warning of result.warnings) logger.warn(warning);
  if (!result.ok) {
    logger.fail('cannot start the local rehearsal stack - missing prerequisite(s):');
    for (const error of result.errors) logger.fail(`  - ${error}`);
    return false;
  }
  return true;
}
