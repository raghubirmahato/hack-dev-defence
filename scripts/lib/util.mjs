// Shared helpers for the HK1 developer launchers (Node 18+, standard library only).
//
// These scripts are developer convenience for the local rehearsal stack: they start
// the lab origin (lab/demo/vuln_login), the HDD proxy (crates/hdd-proxy) and open the
// admin UI, and they wrap the Rust gates. They are not product code and make no
// security claim (R-10; the Rust gates stay the authority for the Rust crates).

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repository root (parent of scripts/). */
export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** True on Windows (the launchers support Windows and Linux/macOS). */
export const isWindows = process.platform === 'win32';

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const ANSI = {
  reset: '\u001b[0m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  blue: '\u001b[34m',
  magenta: '\u001b[35m',
  cyan: '\u001b[36m',
  dim: '\u001b[2m',
};

/** Colour a short console token when stdout is a TTY and NO_COLOR is unset. */
export function paint(text, colour) {
  if (!useColor || !colour || !ANSI[colour]) return text;
  return `${ANSI[colour]}${text}${ANSI.reset}`;
}

export function info(message) {
  process.stdout.write(`${paint('[hdd]', 'blue')} ${message}\n`);
}

export function warn(message) {
  process.stdout.write(`${paint('[hdd]', 'yellow')} ${message}\n`);
}

export function fail(message) {
  process.stderr.write(`${paint('[hdd]', 'red')} ${message}\n`);
}

export function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

/** Format a command line for honest log output (no shell involved). */
export function formatCommand(command, args = []) {
  return [command, ...args]
    .map((part) => (/\s/.test(part) ? `"${part}"` : part))
    .join(' ');
}

/** Run a command capturing stdout/stderr; never throws for a missing binary. */
export function runCaptured(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? process.env,
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs ?? 120_000,
    shell: false,
  });
  return {
    command,
    args,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error ?? null,
  };
}

/** Run a command with inherited stdio (interactive/build output); returns the exit status. */
export function runVisible(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? process.env,
    stdio: 'inherit',
    windowsHide: true,
    shell: false,
  });
  return result.status === null ? 1 : result.status;
}

/** Spawn a long-running child with piped stdio, cwd defaults to the repository root. */
export function spawnProcess(command, args, options = {}) {
  return spawn(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    shell: false,
    detached: false,
  });
}

/** Prefix every line of a readable stream with a coloured label; returns the child line hook. */
export function prefixLines(readable, { label, colour, target = process.stdout, onLine } = {}) {
  let buffer = '';
  const emit = (line) => {
    target.write(`${paint(`[${label}]`, colour)} ${line}\n`);
    if (onLine) onLine(line);
  };
  readable.setEncoding('utf8');
  readable.on('data', (chunk) => {
    buffer += chunk;
    let index = buffer.indexOf('\n');
    while (index !== -1) {
      const line = buffer.slice(0, index).replace(/\r$/, '');
      buffer = buffer.slice(index + 1);
      emit(line);
      index = buffer.indexOf('\n');
    }
  });
  readable.on('end', () => {
    if (buffer.length > 0) {
      emit(buffer.replace(/\r$/, ''));
      buffer = '';
    }
  });
}

/** True when a TCP port accepts a connection on the given host. */
export function checkPortOpen(port, host = '127.0.0.1', timeoutMs = 500) {
  return new Promise((resolvePromise) => {
    const socket = net.connect({ port, host });
    let settled = false;
    const done = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolvePromise(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

/** Wait until a TCP port opens; resolves true on success, false on timeout. */
export async function waitForPort(port, options = {}) {
  const host = options.host ?? '127.0.0.1';
  const deadline = Date.now() + (options.timeoutMs ?? 20_000);
  const intervalMs = options.intervalMs ?? 250;
  while (Date.now() < deadline) {
    if (await checkPortOpen(port, host, 500)) return true;
    await sleep(intervalMs);
  }
  return false;
}

function requestOnce({ method, url, headers, body, timeoutMs }) {
  return new Promise((resolvePromise, rejectPromise) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const request = transport.request(parsed, { method, headers, timeout: timeoutMs }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        resolvePromise({
          status: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      response.on('error', rejectPromise);
    });
    request.on('timeout', () => request.destroy(new Error(`request timed out after ${timeoutMs} ms`)));
    request.on('error', rejectPromise);
    if (body !== undefined && body !== null) request.write(body);
    request.end();
  });
}

/**
 * Minimal HTTP client for the rehearsal checks: manual redirects (so a login POST's
 * Set-Cookie can be carried to /admin), optional cookie jar, no external requests
 * beyond the URL given. The launchers use it only against loopback URLs.
 */
export async function httpRequest(options = {}) {
  let currentUrl = options.url;
  let currentMethod = options.method ?? 'GET';
  let currentBody = options.body;
  let redirects = 0;
  const cookieJar = options.cookieJar ?? null;
  const maxRedirects = options.maxRedirects ?? 5;
  for (;;) {
    const headers = { ...(options.headers ?? {}) };
    if (cookieJar && cookieJar.size > 0) {
      headers.Cookie = Array.from(cookieJar, ([name, value]) => `${name}=${value}`).join('; ');
    }
    if (currentBody !== undefined && currentBody !== null && headers['Content-Length'] === undefined) {
      headers['Content-Length'] = Buffer.byteLength(currentBody);
    }
    const response = await requestOnce({
      method: currentMethod,
      url: currentUrl,
      headers,
      body: currentBody,
      timeoutMs: options.timeoutMs ?? 5_000,
    });
    if (cookieJar && Array.isArray(response.headers['set-cookie'])) {
      for (const raw of response.headers['set-cookie']) {
        const pair = raw.split(';')[0];
        const index = pair.indexOf('=');
        if (index > 0) cookieJar.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
      }
    }
    const location = response.headers.location;
    const redirectStatus = [301, 302, 303, 307, 308].includes(response.status);
    if (redirectStatus && location && redirects < maxRedirects) {
      redirects += 1;
      currentUrl = new URL(location, currentUrl).toString();
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && currentMethod === 'POST')) {
        currentMethod = 'GET';
        currentBody = undefined;
      }
      continue;
    }
    return {
      status: response.status,
      headers: response.headers,
      body: response.body,
      redirects,
      finalUrl: currentUrl,
    };
  }
}

/** Poll an HTTP endpoint until it answers; resolves the last response or null on timeout. */
export async function waitForHttp(url, options = {}) {
  const deadline = Date.now() + (options.timeoutMs ?? 20_000);
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await httpRequest({ url, timeoutMs: options.timeoutMs ?? 2_000 });
      if (options.expectStatus === undefined || response.status === options.expectStatus) return response;
      lastError = new Error(`unexpected HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(options.intervalMs ?? 250);
  }
  if (options.quiet !== true) warn(`waiting for ${url} failed: ${lastError?.message ?? 'timeout'}`);
  return null;
}

/** Run a command and return its first version-like token, or null. */
export function firstVersion(text) {
  const match = /(\d+\.\d+\.\d+)/.exec(String(text ?? ''));
  return match ? match[1] : null;
}

/** Random hex token for the local dev admin bootstrap value (never printed in full). */
export function randomToken(byteLength = 32) {
  return randomBytes(byteLength).toString('hex');
}

/** Show only the start of a secret; the full value never goes to the console by default. */
export function maskSecret(secret) {
  const text = String(secret ?? '');
  if (text.length <= 8) return '****';
  return `${text.slice(0, 4)}...${text.slice(-2)}`;
}

/** Ensure a directory exists (recursive). */
export function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

/** True when the module was started as the process entry point (not imported). */
export function isMainModule(metaUrl) {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return resolve(entry) === fileURLToPath(metaUrl);
  } catch {
    return false;
  }
}

/** Compare two absolute URLs ignoring a trailing slash and any fragment (bad input = false). */
export function sameUrl(left, right) {
  try {
    const a = new URL(String(left));
    const b = new URL(String(right));
    a.hash = '';
    b.hash = '';
    const normalize = (url) => url.href.replace(/\/$/, '');
    return normalize(a) === normalize(b);
  } catch {
    return false;
  }
}

/**
 * Stop a child process and its tree. Windows uses taskkill /T (cargo-watch spawns a
 * grandchild proxy); POSIX sends SIGTERM and escalates to SIGKILL after a grace period.
 */
export async function stopProcess(child, options = {}) {
  if (!child || child.exitCode !== null) return;
  const graceMs = options.graceMs ?? 5_000;
  if (isWindows) {
    runCaptured('taskkill', ['/pid', String(child.pid), '/T', '/F'], { timeoutMs: 15_000 });
  } else {
    try {
      child.kill('SIGTERM');
    } catch {
      // Already gone.
    }
    const termDeadline = Date.now() + graceMs;
    while (child.exitCode === null && Date.now() < termDeadline) await sleep(100);
    if (child.exitCode === null) {
      try {
        child.kill('SIGKILL');
      } catch {
        // Already gone.
      }
    }
  }
  const killDeadline = Date.now() + graceMs;
  while (child.exitCode === null && Date.now() < killDeadline) await sleep(100);
}
