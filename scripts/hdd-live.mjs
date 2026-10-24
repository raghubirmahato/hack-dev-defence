// One command for the live demo stack: the HDD proxy plus the temporary public tunnel, both supervised.
//
//   node scripts/hdd-live.mjs --config <hdd.yaml> [--gist <id>] [--release]
//   npm run live -- --config demo/hdd-live.yaml --gist 7e2a7c825c1a229b3905577da6dfd36f
//
// - starts target/release (with --release) or target/debug `hdd-proxy` with the given configuration and restarts it with a
//   short backoff if it exits;
// - starts scripts/hdd-tunnel.mjs for the proxy's listen port (it publishes the public address to the gist when --gist is
//   given, so the app finds HDD again without a Vercel change);
// - Ctrl+C stops both. A bootstrap admin token is generated for this run when HDD_ADMIN_TOKEN is not set (never printed;
//   use the panel's account login). Demo only: the tunnel exposes the loopback proxy to the internet while it runs.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

/** Parse `--config <file>`, `--gist <id>`, `--release`, `--help`; throws on anything else. */
export function parseArgs(argv = []) {
  const rest = [...argv];
  const options = { config: null, gist: null, release: false, help: false };
  while (rest.length > 0) {
    const current = rest.shift();
    if (current === '--help' || current === '-h') options.help = true;
    else if (current === '--release') options.release = true;
    else if (current === '--config') {
      if (rest.length === 0) throw new Error('--config needs a file');
      options.config = rest.shift();
    } else if (current === '--gist') {
      if (rest.length === 0) throw new Error('--gist needs a gist id');
      const id = rest.shift();
      if (!/^[0-9a-f]{20,40}$/.test(id)) throw new Error('--gist needs a gist id (20 to 40 hex characters)');
      options.gist = id;
    } else throw new Error(`unknown option "${current}"`);
  }
  return options;
}

/** The proxy's listen port from a configuration file (`listen: "127.0.0.1:18083"`), or null. */
export function listenPort(yamlText) {
  const match = /^listen:\s*["']?[^"'\s:]*:(\d{2,5})["']?\s*$/m.exec(yamlText);
  return match ? Number(match[1]) : null;
}

function exePath(release) {
  const name = process.platform === 'win32' ? 'hdd-proxy.exe' : 'hdd-proxy';
  const order = release ? ['release', 'debug'] : ['debug', 'release'];
  for (const profile of order) {
    const candidate = path.join(root, 'target', profile, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function prefixed(label, stream, sink) {
  let buffer = '';
  stream.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let at;
    while ((at = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, at).replace(/\r$/, '');
      buffer = buffer.slice(at + 1);
      if (line.length > 0) sink(`[${label}] ${line}\n`);
    }
  });
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`[hdd-live] ${error.message}\nUsage: node scripts/hdd-live.mjs --config <hdd.yaml> [--gist <id>] [--release]\n`);
    return 1;
  }
  if (options.help || options.config === null) {
    process.stdout.write('Usage: node scripts/hdd-live.mjs --config <hdd.yaml> [--gist <id>] [--release]\n');
    return options.help ? 0 : 1;
  }
  const config = path.resolve(options.config);
  if (!existsSync(config)) {
    process.stderr.write(`[hdd-live] the configuration file ${config} does not exist\n`);
    return 1;
  }
  const exe = exePath(options.release);
  if (exe === null) {
    process.stderr.write('[hdd-live] no hdd-proxy binary found: run `cargo build -p hdd-proxy` (or add --release after `cargo build --release -p hdd-proxy`)\n');
    return 1;
  }
  const port = listenPort(readFileSync(config, 'utf8'));
  if (port === null) {
    process.stderr.write('[hdd-live] cannot read the proxy listen port from the configuration (expected `listen: "127.0.0.1:<port>"`)\n');
    return 1;
  }
  const env = { ...process.env };
  if (!env.HDD_ADMIN_TOKEN) env.HDD_ADMIN_TOKEN = randomBytes(24).toString('base64url');

  let stopping = false;
  let proxy = null;
  let tunnel = null;
  let backoff = 1000;

  function startProxy() {
    proxy = spawn(exe, ['--config', config], { cwd: path.dirname(config), env, stdio: ['ignore', 'pipe', 'pipe'] });
    prefixed('hdd', proxy.stdout, (line) => process.stdout.write(line));
    prefixed('hdd', proxy.stderr, (line) => process.stderr.write(line));
    const started = Date.now();
    proxy.on('exit', (code) => {
      if (stopping) return;
      backoff = Date.now() - started > 30000 ? 1000 : Math.min(backoff * 2, 15000);
      process.stderr.write(`[hdd-live] hdd-proxy exited (code ${code}); restarting in ${backoff / 1000} s\n`);
      setTimeout(() => { if (!stopping) startProxy(); }, backoff);
    });
  }

  startProxy();
  const tunnelArgs = [path.join(here, 'hdd-tunnel.mjs'), '--port', String(port)];
  if (options.gist) tunnelArgs.push('--publish-gist', options.gist);
  setTimeout(() => {
    if (stopping) return;
    tunnel = spawn(process.execPath, tunnelArgs, { cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    prefixed('tunnel', tunnel.stdout, (line) => process.stdout.write(line));
    prefixed('tunnel', tunnel.stderr, (line) => process.stderr.write(line));
  }, 2000);

  process.stdout.write(`[hdd-live] proxy on 127.0.0.1:${port}; press Ctrl+C to stop both.\n`);
  await new Promise((resolve) => {
    const stop = () => {
      if (stopping) return;
      stopping = true;
      for (const child of [proxy, tunnel]) if (child) child.kill();
      setTimeout(resolve, 500);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code));
}
