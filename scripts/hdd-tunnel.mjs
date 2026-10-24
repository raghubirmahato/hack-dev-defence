// `npm run tunnel` (demo only): put the loopback HDD proxy on the internet for a demo
// through the free localhost.run SSH tunnel.
//
// COLLAB.md Addendum 7 item 4. The front door for a serverless (Vercel) origin needs HDD
// to be reachable from the internet; this helper is the demo answer, not a production
// ingress. It runs:
//
//   ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
//       -R 80:127.0.0.1:<port> nokey@localhost.run
//
// prints the public URL as HDD_GATE_URL=<url> (set it in Vercel: Project -> Settings ->
// Environment Variables -> HDD_GATE_URL, then redeploy), sends a GET to <url>/healthz
// every 8 s to keep the free tunnel warm (the service resets the first request after
// idle), restarts ssh with a bounded exponential backoff when it exits, and stops the
// child and this process cleanly on Ctrl+C/SIGTERM (exit code 0).
//
// Honest limits: this needs the OpenSSH client; it exposes the loopback proxy (never the
// origin itself) to the internet while it runs; the free service hands out a new URL on
// every restart; it is for demos only and the permanent answer is hosting HDD on a
// server. The helper never reads or prints environment values or secrets.
//
// Usage: node scripts/hdd-tunnel.mjs [--port <n>]   (or: npm run tunnel -- --port <n>)
//   --port   local TCP port the tunnel forwards to (default 8080; use the port the dev
//            launcher printed when 8080 was busy, for example --port 18080). 1..65535.
//   --help   print this usage.
//
// The file is importable with no side effects: only helpers and `main` are exported, and
// `main` runs only when this file is the process entry point. Tests therefore inject a
// fake `ssh` check and never touch ssh or the network.

import { spawn, spawnSync } from 'node:child_process';

import { isMainModule } from './lib/util.mjs';

/** Local TCP port the tunnel forwards to unless --port overrides it. */
export const DEFAULT_PORT = 8080;

/** The free tunnel service and the account-less SSH target it documents. */
export const SSH_TARGET = 'nokey@localhost.run';

/** Keepalive options of the documented command, verbatim. */
export const SSH_OPTIONS = Object.freeze([
  '-o',
  'ServerAliveInterval=15',
  '-o',
  'ServerAliveCountMax=3',
  '-o',
  'ExitOnForwardFailure=yes',
]);

/** Heartbeat: poll <url>/healthz every 8 s (the free service resets the first request after idle). */
export const HEARTBEAT_INTERVAL_MS = 8_000;

/** A single heartbeat request must not hang the timer. */
export const HEARTBEAT_TIMEOUT_MS = 5_000;

/** Restart backoff: 1 s, 2 s, 4 s, ... capped at 30 s. */
export const BASE_BACKOFF_MS = 1_000;

/** Upper bound of the restart backoff (the delay is bounded, not the number of restarts). */
export const MAX_BACKOFF_MS = 30_000;

/** A child that ran at least this long before exiting resets the backoff (a stable run). */
export const STABLE_RUN_MS = 60_000;

/** How long a stopping child gets between SIGTERM and SIGKILL. */
export const STOP_GRACE_MS = 3_000;

const SERVICE_HOSTS = new Set(['localhost.run', 'www.localhost.run', 'admin.localhost.run', 'api.trycloudflare.com', 'www.trycloudflare.com', 'trycloudflare.com']);
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/g;
const TUNNEL_LINE = /tunneled with tls termination/i;
const TUNNEL_HOST_PATTERN = /(?:^|\.)(?:lhr\.life|localhost\.run|trycloudflare\.com)$/i;

/** The default place the Windows installer puts cloudflared (used only when `--provider cloudflared` is chosen). */
export const CLOUDFLARED_DEFAULT = 'cloudflared';

/** The cloudflared quick-tunnel command: no account, no config file, the address changes on every start. */
export function buildCloudflaredArgs(port) {
  const localPort = parsePort(port);
  return ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${localPort}`];
}

/**
 * Parse and validate the local port: a whole number from 1 to 65535. Accepts a number or
 * the string form (`"8080"`), throws with a message naming the valid range otherwise.
 */
export function parsePort(raw) {
  const text = String(raw ?? '').trim();
  const range = 'a whole number between 1 and 65535';
  if (!/^[0-9]+$/.test(text)) throw new Error(`invalid port "${text}": expected ${range}`);
  const port = Number(text);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port "${text}": expected ${range}`);
  }
  return port;
}

/**
 * Parse the CLI: `--port <n>` / `--port=<n>` / `--help`, nothing else. Returns
 * `{ port, help }`; `port` is the validated local port (default 8080).
 */
export function parseArgs(argv = []) {
  const rest = [...argv];
  let port = DEFAULT_PORT;
  let help = false;
  let gist = null;
  let provider = 'ssh';
  let cloudflaredPath = CLOUDFLARED_DEFAULT;
  while (rest.length > 0) {
    const current = rest.shift();
    if (current === '--help' || current === '-h') {
      help = true;
    } else if (current === '--port') {
      if (rest.length === 0) throw new Error('--port needs a value between 1 and 65535');
      port = parsePort(rest.shift());
    } else if (current === '--publish-gist') {
      if (rest.length === 0) throw new Error('--publish-gist needs a gist id');
      gist = parseGist(rest.shift());
    } else if (current === '--provider') {
      if (rest.length === 0) throw new Error('--provider needs ssh or cloudflared');
      provider = String(rest.shift());
      if (provider !== 'ssh' && provider !== 'cloudflared') throw new Error('--provider must be ssh or cloudflared');
    } else if (current === '--cloudflared-path') {
      if (rest.length === 0) throw new Error('--cloudflared-path needs a file path');
      cloudflaredPath = String(rest.shift());
    } else if (current.startsWith('--port=')) {
      port = parsePort(current.slice('--port='.length));
    } else {
      throw new Error(`unknown option "${current}" (usage: node scripts/hdd-tunnel.mjs [--port <n>])`);
    }
  }
  // The ssh defaults stay out of the result so the long-standing shape of the ssh-only options does not change.
  return provider === 'ssh' ? { port, help, gist } : { port, help, gist, provider, cloudflaredPath };
}

/** A GitHub gist id (hex only), so nothing else can reach the `gh` command line. */
function parseGist(value) {
  if (!/^[0-9a-f]{20,40}$/.test(String(value))) throw new Error('--publish-gist needs a gist id (20 to 40 hex characters)');
  return String(value);
}

/** The exact ssh argument list of the documented localhost.run command. */
export function buildSshArgs(port) {
  const localPort = parsePort(port);
  return [...SSH_OPTIONS, '-R', `80:127.0.0.1:${localPort}`, SSH_TARGET];
}

/** Trim trailing punctuation and return the URL origin, or null when it is not http(s). */
function normalizePublicUrl(candidate) {
  const cleaned = String(candidate).replace(/[),.;]+$/, '');
  let url;
  try {
    url = new URL(cleaned);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (!url.hostname || url.hostname === 'localhost') return null;
  return `${url.protocol}//${url.host}`;
}

/** True for the hosts the free service has handed out (`*.lhr.life`, `*.localhost.run`). */
function isTunnelHost(publicUrl) {
  try {
    const hostname = new URL(publicUrl).hostname;
    return !SERVICE_HOSTS.has(hostname) && TUNNEL_HOST_PATTERN.test(hostname);
  } catch {
    return false;
  }
}

/**
 * Parse the public tunnel URL from ssh output. The authoritative line is the one that
 * says "tunneled with tls termination"; as a fallback any URL on a service host
 * (`*.lhr.life`, `*.localhost.run`) is accepted. The service's own home-page links
 * (`https://localhost.run/`, ...) are never returned. Returns null when no URL is there.
 */
export function parsePublicUrl(output) {
  const text = String(output ?? '');
  const preferred = [];
  const fallback = [];
  for (const line of text.split(/\r?\n/)) {
    for (const match of line.matchAll(URL_PATTERN)) {
      const normalized = normalizePublicUrl(match[0]);
      if (normalized === null) continue;
      (TUNNEL_LINE.test(line) ? preferred : fallback).push(normalized);
    }
  }
  if (preferred.length > 0) return preferred[preferred.length - 1];
  const tunneled = fallback.find(isTunnelHost);
  return tunneled ?? null;
}

/** The heartbeat URL: the tunnel origin plus `/healthz`, with any trailing slash removed. */
export function heartbeatUrl(publicUrl) {
  let url;
  try {
    url = new URL(String(publicUrl));
  } catch {
    throw new Error(`not a usable tunnel URL: ${publicUrl}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`not an http(s) tunnel URL: ${publicUrl}`);
  }
  const base = `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, '')}`;
  return `${base}/healthz`;
}

/** Bounded exponential backoff for the restart delay (attempt 0 = 1 s, capped at 30 s). */
export function backoffMs(attempt) {
  const index = Number.isFinite(attempt) ? Math.max(0, Math.floor(attempt)) : 0;
  return Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** Math.min(index, 30));
}

/** Whether a run was stable enough to reset the restart backoff. */
export function shouldResetBackoff(startedAt, exitedAt, stableMs = STABLE_RUN_MS) {
  if (!Number.isFinite(startedAt) || !Number.isFinite(exitedAt)) return false;
  return exitedAt - startedAt >= stableMs;
}

/**
 * The console lines for a public URL. The first announcement prints `HDD_GATE_URL=<url>`;
 * when a restart changes the URL it also says so and repeats the Vercel step.
 */
export function publicUrlLines(url, previousUrl = null) {
  const lines = [];
  if (previousUrl !== null && previousUrl !== url) {
    lines.push(`The tunnel public URL changed (localhost.run assigns a new address on every restart): ${previousUrl} -> ${url}`);
  }
  lines.push(`HDD_GATE_URL=${url}`);
  lines.push(
    'Set this in Vercel: Project -> Settings -> Environment Variables -> HDD_GATE_URL, then redeploy.',
  );
  return lines;
}

/** The usage block printed by --help. */
export function usageLines() {
  return [
    'Usage: node scripts/hdd-tunnel.mjs [--port <n>] [--publish-gist <id>] [--provider ssh|cloudflared] [--cloudflared-path <file>]',
    '',
    `  --port <n>  local TCP port to forward to (default ${DEFAULT_PORT}; 1..65535)`,
    '  --help      print this usage',
    '',
    `Runs: ssh ${buildSshArgs(DEFAULT_PORT).join(' ')}`,
    'Demo only: while it runs the loopback proxy is reachable from the internet through the',
    'free localhost.run tunnel, and the public URL changes on every restart. Never leave it',
    'running and never put secret values on the command line or in a log.',
  ];
}

/**
 * What to print when `ssh` is missing: exactly what is missing and how to install it.
 * There is deliberately no fallback tunnel and no silent workaround.
 */
export function missingSshLines() {
  return [
    'Cannot start the tunnel: the `ssh` command (OpenSSH client) was not found on PATH.',
    'Install it and run this command again:',
    '  Windows: Settings -> System -> Optional features -> Add a feature -> OpenSSH Client',
    '           (or: winget install --id Microsoft.OpenSSH.Beta)',
    '  macOS:   brew install openssh (the Xcode command line tools also provide ssh)',
    '  Debian/Ubuntu: sudo apt install openssh-client',
    'Refusing to start: this demo helper has no fallback tunnel, and nothing was started.',
  ];
}

/**
 * Whether an ssh binary is available, using an injected spawnSync implementation (tests
 * pass a fake, so no real process is started). A spawn error such as ENOENT means the
 * binary is missing; a non-zero `ssh -V` still means a binary exists to try.
 */
export function sshAvailable(spawnSyncImpl) {
  let result;
  try {
    result = spawnSyncImpl('ssh', ['-V'], {
      encoding: 'utf8',
      windowsHide: true,
      shell: false,
      timeout: 15_000,
    });
  } catch {
    return false;
  }
  return result !== null && result !== undefined && (result.error === undefined || result.error === null);
}

function writeLine(stream) {
  return (line) => stream.write(`${line}\n`);
}

/**
 * Run the tunnel until Ctrl+C/SIGTERM (or a fatal start error). Exported so the helper is
 * testable; the entry point below calls it only when this file is the process entry.
 * Returns the intended exit code: 0 after a clean stop, 1 when the tunnel cannot start.
 */
export async function main(argv = process.argv.slice(2), deps = {}) {
  const spawnImpl = deps.spawn ?? spawn;
  const spawnSyncImpl = deps.spawnSync ?? spawnSync;
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  const now = deps.now ?? (() => Date.now());
  const out = deps.out ?? writeLine(process.stdout);
  const err = deps.err ?? writeLine(process.stderr);
  const timers = deps.timers ?? {
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  };

  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    err(`[hdd-tunnel] ${error.message}`);
    for (const line of usageLines()) err(line);
    return 1;
  }
  if (options.help) {
    for (const line of usageLines()) out(line);
    return 0;
  }
  const provider = options.provider ?? 'ssh';
  const cloudflaredPath = options.cloudflaredPath ?? CLOUDFLARED_DEFAULT;
  if (provider === 'cloudflared') {
    let probe;
    try {
      probe = spawnSyncImpl(cloudflaredPath, ['--version'], { encoding: 'utf8', windowsHide: true, shell: false, timeout: 15_000 });
    } catch {
      probe = { error: new Error('not found') };
    }
    if (!probe || probe.error) {
      err('Cannot start the tunnel: cloudflared was not found (winget install --id Cloudflare.cloudflared) or is blocked.');
      return 1;
    }
  } else if (!sshAvailable(spawnSyncImpl)) {
    for (const line of missingSshLines()) err(line);
    return 1;
  }
  if (typeof fetchImpl !== 'function') {
    err('[hdd-tunnel] this Node.js has no global fetch; the /healthz heartbeat is skipped (the tunnel still runs)');
  }

  out(`[hdd-tunnel] demo only: forwarding 127.0.0.1:${options.port} through the free ${provider === 'cloudflared' ? 'Cloudflare quick' : 'localhost.run'} tunnel.`);
  out('[hdd-tunnel] while it runs, the loopback HDD proxy is reachable from the internet; stop it with Ctrl+C.');
  out('[hdd-tunnel] the public URL changes on every restart: update HDD_GATE_URL in Vercel and redeploy when it does.');
  out('[hdd-tunnel] this helper never reads or prints environment values or secrets.');

  return runTunnel(options.port, { spawnImpl, fetchImpl, now, out, err, timers, gist: options.gist, spawnSyncImpl, provider, cloudflaredPath });
}

/** The restart/heartbeat loop. Resolves with the exit code; never rejects for ssh exits. */
function runTunnel(port, { spawnImpl, fetchImpl, now, out, err, timers, gist = null, spawnSyncImpl = spawnSync, provider = 'ssh', cloudflaredPath = CLOUDFLARED_DEFAULT }) {
  const later = timers.setTimeout;
  const cancel = timers.clearTimeout;
  const every = timers.setInterval;
  const stopEvery = timers.clearInterval;

  let child = null;
  let childStartedAt = 0;
  let attempt = 0;
  let currentUrl = null;
  let heartbeatTimer = null;
  let heartbeatFailing = false;
  let restartTimer = null;
  let stopTimer = null;
  let stopping = false;
  let finished = false;
  let resolveRun = null;

  const finishedPromise = new Promise((resolve) => {
    resolveRun = resolve;
  });

  function clearTimers() {
    if (heartbeatTimer !== null) {
      stopEvery(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (restartTimer !== null) {
      cancel(restartTimer);
      restartTimer = null;
    }
    if (stopTimer !== null) {
      cancel(stopTimer);
      stopTimer = null;
    }
  }

  function finish(code) {
    if (finished) return;
    finished = true;
    clearTimers();
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    resolveRun(code);
  }

  function stopHeartbeat() {
    if (heartbeatTimer !== null) {
      stopEvery(heartbeatTimer);
      heartbeatTimer = null;
    }
  }

  async function heartbeat() {
    if (currentUrl === null || stopping || finished || typeof fetchImpl !== 'function') return;
    try {
      const response = await fetchImpl(heartbeatUrl(currentUrl), {
        method: 'GET',
        redirect: 'manual',
        headers: { 'user-agent': 'hdd-tunnel' },
        signal: AbortSignal.timeout(HEARTBEAT_TIMEOUT_MS),
      });
      if (heartbeatFailing) {
        out('[hdd-tunnel] heartbeat is answered again; the tunnel is being kept warm.');
        heartbeatFailing = false;
      }
      // Do not read or keep the answer: the heartbeat only keeps the tunnel warm.
      if (response && response.body && typeof response.body.cancel === 'function') {
        try {
          await response.body.cancel();
        } catch {
          // The body is irrelevant; a cancelled stream is fine.
        }
      }
    } catch (error) {
      if (!heartbeatFailing) {
        heartbeatFailing = true;
        err(
          `[hdd-tunnel] heartbeat failed (will retry every ${HEARTBEAT_INTERVAL_MS / 1000} s): ${error?.message ?? 'request failed'}`,
        );
      }
    }
  }

  function startHeartbeat() {
    if (stopping || finished) return;
    stopHeartbeat();
    if (currentUrl === null) return;
    void heartbeat();
    heartbeatTimer = every(() => {
      void heartbeat();
    }, HEARTBEAT_INTERVAL_MS);
  }

  function announcePublicUrl(url) {
    if (stopping || finished) return;
    if (url === currentUrl) return;
    const previousUrl = currentUrl;
    currentUrl = url;
    for (const line of publicUrlLines(url, previousUrl)) out(line);
    if (gist !== null) {
      // Keep a stable registry current so the app finds HDD again without a Vercel change (HDD_GATE_URL_FROM).
      const result = spawnSyncImpl('gh', ['gist', 'edit', gist, '-f', 'gate.txt', '-'], { input: `${url}
`, encoding: 'utf8' });
      if (result && result.status === 0) out('[hdd-tunnel] published the new address to the gist (gate.txt).');
      else err('[hdd-tunnel] could not update the gist with `gh gist edit`; is `gh` installed and signed in?');
    }
    startHeartbeat();
  }

  function attachSshStream(stream) {
    if (!stream) return null;
    const state = { buffer: '' };
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      state.buffer += chunk;
      let index = state.buffer.indexOf('\n');
      while (index !== -1) {
        const line = state.buffer.slice(0, index).replace(/\r$/, '');
        state.buffer = state.buffer.slice(index + 1);
        handleSshLine(line);
        index = state.buffer.indexOf('\n');
      }
    });
    return state;
  }

  function handleSshLine(line) {
    if (line.trim() !== '') out(`[ssh] ${line}`);
    const url = parsePublicUrl(line);
    if (url !== null) announcePublicUrl(url);
  }

  function flushSshStreams(buffers) {
    for (const state of buffers) {
      if (!state) continue;
      const line = state.buffer.replace(/\r$/, '');
      state.buffer = '';
      if (line.trim() !== '') handleSshLine(line);
    }
  }

  function scheduleRestart(exitReason) {
    const exitedAt = now();
    const ranMs = exitedAt - childStartedAt;
    if (shouldResetBackoff(childStartedAt, exitedAt)) attempt = 0;
    const delay = backoffMs(attempt);
    attempt += 1;
    const seconds = Math.round(ranMs / 1000);
    out(
      `[hdd-tunnel] ssh exited (${exitReason}) after ${seconds} s; restarting in ${Math.round(delay / 1000)} s (attempt ${attempt}).`,
    );
    restartTimer = later(() => {
      restartTimer = null;
      if (!stopping) startChild();
    }, delay);
  }

  function handleChildClose(spawned, buffers, code, signal) {
    if (child !== spawned) return;
    flushSshStreams(buffers);
    child = null;
    stopHeartbeat();
    if (stopping) {
      finish(0);
      return;
    }
    const exitReason = signal ? `signal ${signal}` : `code ${code}`;
    scheduleRestart(exitReason);
  }

  function startChild() {
    if (finished || stopping) return;
    const command = provider === 'cloudflared' ? cloudflaredPath : 'ssh';
    const args = provider === 'cloudflared' ? buildCloudflaredArgs(port) : buildSshArgs(port);
    out(`[hdd-tunnel] starting: ${command === 'ssh' ? 'ssh' : 'cloudflared'} ${args.join(' ')}`);
    let spawned;
    try {
      // stdin is inherited so a first-run host-key prompt can be answered in the terminal;
      // stdout/stderr are read to find the public URL. No shell is involved.
      spawned = spawnImpl(command, args, { stdio: ['inherit', 'pipe', 'pipe'], windowsHide: true, shell: false });
    } catch (error) {
      err(`[hdd-tunnel] ssh could not be started: ${error?.message ?? error}`);
      finish(1);
      return;
    }
    child = spawned;
    childStartedAt = now();
    const buffers = [attachSshStream(spawned.stdout), attachSshStream(spawned.stderr)];
    spawned.once('close', (code, signal) => handleChildClose(spawned, buffers, code, signal));
    spawned.once('error', (error) => {
      if (child !== spawned) return;
      err(`[hdd-tunnel] ssh failed: ${error?.message ?? error}`);
      child = null;
      finish(1);
    });
  }

  function requestStop(signalName) {
    if (stopping || finished) return;
    stopping = true;
    out(`[hdd-tunnel] ${signalName} received: stopping the tunnel`);
    if (restartTimer !== null) {
      cancel(restartTimer);
      restartTimer = null;
    }
    stopHeartbeat();
    const current = child;
    if (current === null || current.exitCode !== null) {
      finish(0);
      return;
    }
    try {
      current.kill('SIGTERM');
    } catch {
      // The child is already gone; the exit event or the watchdog below finishes us.
    }
    stopTimer = later(() => {
      stopTimer = null;
      try {
        current.kill('SIGKILL');
      } catch {
        // Already gone.
      }
      if (typeof current.unref === 'function') current.unref();
      finish(0);
    }, STOP_GRACE_MS);
  }

  function onSigint() {
    requestStop('SIGINT');
  }

  function onSigterm() {
    requestStop('SIGTERM');
  }

  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  startChild();

  return finishedPromise;
}

if (isMainModule(import.meta.url)) {
  main().then(
    (code) => {
      process.exitCode = typeof code === 'number' ? code : 0;
    },
    (error) => {
      process.stderr.write(`[hdd-tunnel] crashed: ${error?.stack ?? error}\n`);
      process.exitCode = 1;
    },
  );
}
