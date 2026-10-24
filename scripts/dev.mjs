// `npm run dev`: one terminal for the whole HK1 local rehearsal stack.
//
// Starts, with prefixed colour-coded logs:
//   * the deliberately vulnerable lab origin (lab/demo/vuln_login/app.py, 127.0.0.1:8081),
//   * the HDD proxy (crates/hdd-proxy, 127.0.0.1:8080, config demo/hdd-dev.yaml),
//   * the admin UI served by the proxy's admin listener (127.0.0.1:9090).
//
// It builds the proxy if needed, creates the dev data directory, generates a local
// HDD_ADMIN_TOKEN when none is set (printed masked; the full dev-only value goes to
// hdd-data/dev-admin-token.txt, which is git-ignored), prints the URLs, the /setup
// link and a one-line attack command, and stops all children cleanly on Ctrl+C.
//
// Live reload: when cargo-watch is installed the proxy runs under it and restarts on
// crates/** changes; otherwise the launcher says live reload is unavailable.
//
// Loopback only (R-31 local profile: a config file, not a code mode). No protection
// claim is made here: without the TLS terminator and an origin lockdown this is a
// rehearsal, not a protected site (R-34).

import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { checkPrerequisites, reportPrerequisites } from './lib/prereqs.mjs';
import {
  checkPortOpen,
  ensureDir,
  fail,
  info,
  isMainModule,
  isWindows,
  maskSecret,
  paint,
  prefixLines,
  randomToken,
  repoRoot,
  runVisible,
  spawnProcess,
  stopProcess,
  waitForHttp,
  waitForPort,
  warn,
} from './lib/util.mjs';
import { runWalkthrough } from './walkthrough.mjs';

const DEFAULT_CONFIG = 'demo/hdd-dev.yaml';
const ORIGIN_PORT_DEFAULT = 8082;
const PROXY_PORT_DEFAULT = 8080;
const ADMIN_PORT_DEFAULT = 9090;
const SHOP_LOGIN_PATH = '/admin/login';
const PYTHON_LOGIN_PATH = '/login';
const SHOP_DIR = join(repoRoot, 'lab', 'demo', 'shop');

const HELP = `Usage: npm run dev [-- options]        (or: node scripts/dev.mjs [options])

Starts the HK1 local rehearsal stack in one terminal: the deliberately vulnerable
lab shop (lab/demo/shop, Node, 127.0.0.1:8082 by default), the HDD proxy
(127.0.0.1:8080, demo/hdd-dev.yaml) and the admin UI (127.0.0.1:9090). Ctrl+C stops
all children cleanly. The origin is chosen by the profile's per-site \`stack\` hint
(\`node\` = the lab shop, \`python\` = lab/demo/vuln_login).

Options:
  --config <path>   proxy config file (default ${DEFAULT_CONFIG}; relative to the repo root)
  --walkthrough     after the stack is ready run the scripted walkthrough
                    (this is what \`npm run demo\` does)
  --fixed           start the shop with SHOP_VULN=0 (parameterised login; the
                    "remediation applied" state, also \`npm run demo:fixed\`)
  --no-build        do not build hdd-proxy even if the binary is missing
  --help            print this help

Environment:
  HDD_ADMIN_TOKEN   admin bootstrap token for the proxy (generated for the dev run
                    if unset; the full generated value is written to
                    hdd-data/dev-admin-token.txt)
  SHOP_VULN=0       start the lab shop with the fixed (parameterised) login even
                    without --fixed (the source fix; no code mode in the proxy)
  ADMIN_PASSWORD    fake admin password for the lab shop (default: admin)
  DEEPSEEK_API_KEY  optional; enables the AI explanation in the dashboard. Without
                    it the dashboard says AI is off and the deterministic text stays.
  HDD_FORCE_BUILD=1 rebuild hdd-proxy before starting
  NO_COLOR          disable coloured log prefixes

Requirements: Node.js 18+ and Rust (cargo); Python 3 only when the profile selects
the Python lab origin. The launcher checks them and prints an actionable error
instead of starting a half-working stack.
`;

/** Parse the small launcher CLI (no third-party argument parser). */
export function parseArgs(argv) {
  const args = { config: DEFAULT_CONFIG, walkthrough: false, fixed: false, build: true, help: false };
  const rest = [...argv];
  while (rest.length > 0) {
    const current = rest.shift();
    if (current === '--help' || current === '-h') {
      args.help = true;
    } else if (current === '--walkthrough') {
      args.walkthrough = true;
    } else if (current === '--fixed') {
      args.fixed = true;
    } else if (current === '--no-build') {
      args.build = false;
    } else if (current === '--config') {
      if (rest.length === 0) throw new Error('--config needs a value');
      args.config = rest.shift();
    } else if (current.startsWith('--config=')) {
      args.config = current.slice('--config='.length);
    } else {
      throw new Error(`unknown option: ${current} (use --help)`);
    }
  }
  return args;
}

function parseHostPort(value, fallbackHost, fallbackPort) {
  const text = String(value ?? '').trim().replace(/^"|"$/g, '');
  if (text === '') return { host: fallbackHost, port: fallbackPort };
  const ipv6 = /^\[([^\]]+)\]:(\d+)$/.exec(text);
  if (ipv6) return { host: ipv6[1], port: Number(ipv6[2]) };
  const lastColon = text.lastIndexOf(':');
  if (lastColon === -1) return { host: text, port: fallbackPort };
  const host = text.slice(0, lastColon);
  const port = Number(text.slice(lastColon + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { host, port: fallbackPort };
  return { host, port };
}

/**
 * Read the few keys the launcher needs from the dev YAML profile. This is a
 * deliberately tiny reader for loopback endpoints, not a YAML parser: the proxy
 * validates the full file strictly when it starts.
 */
export function readDevConfig(configPath) {
  const text = readFileSync(configPath, 'utf8');
  const first = (pattern, fallback) => {
    const match = pattern.exec(text);
    return match ? match[1].trim() : fallback;
  };
  const listen = parseHostPort(first(/^listen:\s*"?([^"\n#]+)"?/m, ''), '127.0.0.1', PROXY_PORT_DEFAULT);
  const admin = parseHostPort(first(/^admin_listen:\s*"?([^"\n#]+)"?/m, ''), '127.0.0.1', ADMIN_PORT_DEFAULT);
  const originRaw = first(/origin:\s*"([^"]+)"/, `http://127.0.0.1:${ORIGIN_PORT_DEFAULT}`);
  let origin;
  try {
    const url = new URL(originRaw);
    origin = {
      host: url.hostname.replace(/^\[|\]$/g, ''),
      port: url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port),
      url: originRaw.trim(),
    };
  } catch {
    origin = { host: '127.0.0.1', port: ORIGIN_PORT_DEFAULT, url: `http://127.0.0.1:${ORIGIN_PORT_DEFAULT}` };
  }
  const siteHost = first(/^\s*-?\s*host:\s*"([^"]+)"/m, '127.0.0.1');
  const mode = first(/^\s+mode:\s*"?([a-z]+)"?/m, 'block');
  // Per-site stack hint (Addendum 6): selects the local origin process and the
  // remediation code example. `node` is the lab shop; `python` is the older lab app.
  const stack = first(/^\s+stack:\s*"?([a-z]+)"?/m, 'node').toLowerCase();
  const loginPath = stack === 'python' ? PYTHON_LOGIN_PATH : SHOP_LOGIN_PATH;
  return { listen, admin, origin, siteHost, mode, stack, loginPath, configPath, text };
}

// --- port planning (configured endpoints first, then a documented fallback) ---
//
// The committed profile uses proxy 127.0.0.1:8080 and admin 127.0.0.1:9090. On some
// machines one of those ports is already held by another process (on the HK1 build
// machine MiniTool ShadowMaker's MTAgentService holds TCP 8080). Rather than editing
// the committed profile, the launcher probes the configured ports and, only for that
// run, writes a generated profile under hdd-data/ with substituted endpoints, then
// prints exactly which fallback it took.
export const FALLBACK_PROXY_PORTS = [18080, 18081, 18082, 18083, 18084];
export const FALLBACK_ADMIN_PORTS = [19090, 19091, 19092, 19093, 19094];
export const FALLBACK_ORIGIN_PORTS = [18082, 18083, 18084, 18085];

async function firstFreePort(host, candidates, isPortOpen, forbidden = []) {
  for (const port of candidates) {
    if (forbidden.includes(port)) continue;
    if (!(await isPortOpen(port, host))) return port;
  }
  return null;
}

/**
 * Work out the endpoints for this run.
 *
 * @param {object} config                         result of readDevConfig
 * @param {object} [options]
 * @param {(port: number, host: string) => Promise<boolean>} [options.isPortOpen]
 * @param {string} [options.configLabel]          profile name used in the log line
 * @returns {Promise<{ok: boolean, error?: string, origin?: object, proxy?: object,
 *   admin?: object, changed?: {origin: boolean, proxyPair: boolean},
 *   fallbackLines?: string[], needsGeneratedProfile?: boolean}>}
 */
export async function planEndpoints(config, options = {}) {
  const isPortOpen = options.isPortOpen ?? checkPortOpen;
  const configLabel = options.configLabel ?? 'demo/hdd-dev.yaml';
  const listenHost = config.listen.host || '127.0.0.1';
  const adminHost = config.admin.host || listenHost;
  const originHost = config.origin.host || '127.0.0.1';
  const configuredOrigin = config.origin.port;
  const configuredProxy = config.listen.port;
  const configuredAdmin = config.admin.port;

  const fallbackLines = [];
  let originPort = configuredOrigin;
  let originChanged = false;
  if (await isPortOpen(configuredOrigin, originHost)) {
    const free = await firstFreePort(originHost, FALLBACK_ORIGIN_PORTS, isPortOpen, [
      configuredProxy,
      configuredAdmin,
    ]);
    if (free === null) {
      return {
        ok: false,
        error:
          `the configured lab origin port ${configuredOrigin} is in use and no free fallback origin port ` +
          `(${FALLBACK_ORIGIN_PORTS.join(', ')}) was found. Stop the other process and re-run. Nothing was started.`,
      };
    }
    originPort = free;
    originChanged = true;
    fallbackLines.push(
      `port ${configuredOrigin} (configured lab origin) is unavailable (held by another process); using ` +
        `${`http://${originHost}:${originPort}`} for this run - the committed ${configLabel} keeps origin ${configuredOrigin}`,
    );
  }

  let proxyPort = configuredProxy;
  let adminPort = configuredAdmin;
  let proxyPairChanged = false;
  const proxyBusy = await isPortOpen(configuredProxy, listenHost);
  const adminBusy = await isPortOpen(configuredAdmin, adminHost);
  if (proxyBusy || adminBusy) {
    let chosen = null;
    for (let index = 0; index < FALLBACK_PROXY_PORTS.length; index += 1) {
      const candidateProxy = FALLBACK_PROXY_PORTS[index];
      const candidateAdmin = FALLBACK_ADMIN_PORTS[index];
      if (candidateProxy === originPort || candidateAdmin === originPort) continue;
      if (await isPortOpen(candidateProxy, listenHost)) continue;
      if (await isPortOpen(candidateAdmin, adminHost)) continue;
      chosen = { proxy: candidateProxy, admin: candidateAdmin };
      break;
    }
    if (chosen === null) {
      return {
        ok: false,
        error:
          `the configured proxy/admin ports ${configuredProxy}/${configuredAdmin} are in use and no free fallback ` +
          `pair from ${FALLBACK_PROXY_PORTS.map((port, index) => `${port}/${FALLBACK_ADMIN_PORTS[index]}`).join(', ')} was found. ` +
          'Stop the other process and re-run. Nothing was started.',
      };
    }
    proxyPort = chosen.proxy;
    adminPort = chosen.admin;
    proxyPairChanged = true;
    const busy = [];
    if (proxyBusy) busy.push(`port ${configuredProxy}`);
    if (adminBusy) busy.push(`port ${configuredAdmin}`);
    fallbackLines.push(
      `${busy.join(' and ')} unavailable (held by another process); using proxy http://${listenHost}:${proxyPort} ` +
        `and admin http://${adminHost}:${adminPort} for this run - the committed ${configLabel} keeps ` +
        `${configuredProxy}/${configuredAdmin}`,
    );
  }

  return {
    ok: true,
    origin: { host: originHost, port: originPort, url: `http://${originHost}:${originPort}` },
    proxy: { host: listenHost, port: proxyPort, url: `http://${listenHost}:${proxyPort}` },
    admin: { host: adminHost, port: adminPort, url: `http://${adminHost}:${adminPort}` },
    changed: { origin: originChanged, proxyPair: proxyPairChanged },
    fallbackLines,
    needsGeneratedProfile: originChanged || proxyPairChanged,
  };
}

// Small helper kept for readability of the port probe sequence (no side effects).
export async function probePorts(config, isPortOpen = checkPortOpen) {
  const listenHost = config.listen.host || '127.0.0.1';
  const adminHost = config.admin.host || listenHost;
  return {
    proxy: await isPortOpen(config.listen.port, listenHost),
    admin: await isPortOpen(config.admin.port, adminHost),
  };
}

/**
 * Write the per-run generated profile: a copy of the committed profile with the
 * listen/admin_listen/public_url/origin endpoints substituted. Comments, site host,
 * mode, field hints, bans and extra rules are kept verbatim.
 */
export function generateProfileText(config, plan, configLabel = 'demo/hdd-dev.yaml') {
  let text = config.text;
  text = text.replace(/^listen:.*$/m, `listen: "${plan.proxy.host}:${plan.proxy.port}"`);
  text = text.replace(/^admin_listen:.*$/m, `admin_listen: "${plan.admin.host}:${plan.admin.port}"`);
  text = text.replace(/^(\s*)origin:.*$/m, (match, indent) => `${indent}origin: "${plan.origin.url}"`);
  text = text.replace(/^(\s*)public_url:.*$/m, (match, indent) => `${indent}public_url: "${plan.proxy.url}"`);
  const header = [
    '# GENERATED by `npm run dev` for one run: the committed profile keeps its own endpoints.',
    `# Committed profile: ${configLabel}. This run used: proxy ${plan.proxy.url}, admin ${plan.admin.url},`,
    `# lab origin ${plan.origin.url}. Generated because a configured port was already in use on this machine;`,
    '# this file lives under the git-ignored hdd-data/ directory and is safe to delete.',
    '',
  ].join('\n');
  const generated = header + text;
  for (const expected of [
    `listen: "${plan.proxy.host}:${plan.proxy.port}"`,
    `admin_listen: "${plan.admin.host}:${plan.admin.port}"`,
    `origin: "${plan.origin.url}"`,
    `public_url: "${plan.proxy.url}"`,
  ]) {
    if (!generated.includes(expected)) {
      throw new Error(`generated profile is missing the substituted endpoint ${expected}; refusing to start with a stale profile`);
    }
  }
  return generated;
}

/** Record the endpoints of this run so `npm run attack` can use them from another terminal. */
export function writeEndpointState({ plan, configLabel, profileArgument, generatedProfile, mode, stack, loginPath }) {
  const statePath = join(repoRoot, 'hdd-data', 'dev-endpoints.json');
  ensureDir(join(repoRoot, 'hdd-data'));
  const state = {
    generatedAt: new Date().toISOString(),
    committedProfile: configLabel,
    activeProfile: profileArgument,
    generatedProfile: generatedProfile ?? null,
    fallback: plan.needsGeneratedProfile,
    originUrl: plan.origin.url,
    proxyUrl: plan.proxy.url,
    adminUrl: plan.admin.url,
    proxyKind: 'proxy',
    mode,
    stack: stack ?? null,
    loginPath: loginPath ?? null,
  };
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8' });
  return statePath;
}

/** Read the endpoints of the last `npm run dev` run (used by `npm run attack`). */
export function readEndpointState() {
  const statePath = join(repoRoot, 'hdd-data', 'dev-endpoints.json');
  try {
    const parsed = JSON.parse(readFileSync(statePath, 'utf8'));
    if (typeof parsed?.proxyUrl !== 'string' || typeof parsed?.originUrl !== 'string') return null;
    return parsed;
  } catch {
    return null;
  }
}

function proxyBinaryPath() {
  return join(repoRoot, 'target', 'debug', isWindows ? 'hdd-proxy.exe' : 'hdd-proxy');
}

function ensureProxyBinary(build) {
  const binary = proxyBinaryPath();
  const relative = isWindows ? 'target/debug/hdd-proxy.exe' : 'target/debug/hdd-proxy';
  const force = ['1', 'true', 'yes'].includes(String(process.env.HDD_FORCE_BUILD ?? '').toLowerCase());
  if (existsSync(binary) && !force) {
    info(`using the existing proxy binary ${relative} (set HDD_FORCE_BUILD=1 to rebuild)`);
    return true;
  }
  if (!build) {
    fail(`the proxy binary ${relative} is missing and --no-build was given. Run "cargo build -p hdd-proxy" or drop --no-build.`);
    return false;
  }
  info('building the proxy first: cargo build -p hdd-proxy');
  const status = runVisible('cargo', ['build', '-p', 'hdd-proxy']);
  if (status !== 0) {
    fail(
      'cargo build -p hdd-proxy failed (see the output above). The Rust gates are the authority: ' +
        'run "cargo fmt --all --check", "cargo clippy --workspace --all-targets -- -D warnings" and ' +
        '"cargo nextest run --workspace" (or "npm run test").',
    );
    return false;
  }
  if (!existsSync(binary)) {
    fail(`cargo build -p hdd-proxy reported success but ${relative} is missing; check the crate name in Cargo.toml.`);
    return false;
  }
  return true;
}

/**
 * Run the proxy from a copy so a running dev stack never locks
 * target/debug/hdd-proxy.exe: on Windows cargo cannot relink a running executable,
 * which would block the hdd-proxy test builds. Falls back to the build output with
 * a warning if the copy fails.
 */
function copyRunBinary() {
  const source = proxyBinaryPath();
  const copyPath = join(repoRoot, 'hdd-data', isWindows ? 'hdd-proxy-dev.exe' : 'hdd-proxy-dev');
  try {
    ensureDir(join(repoRoot, 'hdd-data'));
    copyFileSync(source, copyPath);
    return copyPath;
  } catch (error) {
    warn(
      `could not copy the proxy binary for this run (${error.message}); using ${source} directly ` +
        '(a Rust rebuild of hdd-proxy may be blocked while the stack runs)',
    );
    return source;
  }
}

function resolveAdminToken() {
  const fromEnv = String(process.env.HDD_ADMIN_TOKEN ?? '').trim();
  if (fromEnv !== '') {
    return {
      token: fromEnv,
      source: 'HDD_ADMIN_TOKEN from the environment',
      file: null,
    };
  }
  const token = randomToken(32);
  const dataDir = join(repoRoot, 'hdd-data');
  ensureDir(dataDir);
  const tokenFile = join(dataDir, 'dev-admin-token.txt');
  writeFileSync(tokenFile, `${token}\n`, { mode: 0o600, encoding: 'utf8' });
  return {
    token,
    source: 'generated for this dev run (local only)',
    file: tokenFile,
  };
}

function seedAccountParser(accounts) {
  return (line) => {
    const match = /username=(\S+)\s+password=(\S+)\s+role=(\S+)/.exec(line);
    if (match) {
      accounts.set(match[1], { password: match[2], role: match[3] });
    }
  };
}

/**
 * Start the deliberately vulnerable lab shop (Addendum 6 demo origin): Node,
 * loopback only, `SHOP_VULN` passed through from the environment (or forced to 0 for
 * the remediation run), fake admin credential from `ADMIN_PASSWORD`/`admin`.
 */
function startShop({ port, accounts, fixed }) {
  const sqlJs = join(SHOP_DIR, 'node_modules', 'sql.js');
  if (!existsSync(sqlJs)) {
    fail(
      `the lab shop dependency is missing: ${join('lab', 'demo', 'shop', 'node_modules', 'sql.js')}. Run ` +
        '"npm install" inside lab/demo/shop once (it is a lab-only dependency; no runtime dependency for HDD).',
    );
    return null;
  }
  const adminPassword = String(process.env.ADMIN_PASSWORD ?? 'admin');
  const shopVuln = fixed ? '0' : process.env.SHOP_VULN;
  const env = { ...process.env, PORT: String(port), ADMIN_PASSWORD: adminPassword };
  if (shopVuln !== undefined && shopVuln !== '') env.SHOP_VULN = String(shopVuln);
  else delete env.SHOP_VULN;
  const child = spawnProcess(process.execPath, [join(SHOP_DIR, 'server.js')], { env });
  accounts.set('admin', { password: adminPassword, role: 'admin' });
  prefixLines(child.stdout, { label: 'shop ', colour: 'magenta' });
  prefixLines(child.stderr, { label: 'shop!', colour: 'red', target: process.stderr });
  return child;
}

/** Start the older Python lab login app (still available when a profile selects stack: python). */
function startPythonOrigin(python, port, accounts) {
  const appPath = join(repoRoot, 'lab', 'demo', 'vuln_login', 'app.py');
  const onLine = seedAccountParser(accounts);
  const child = spawnProcess(python.command, [
    ...python.argsPrefix,
    '-u',
    appPath,
    '--host',
    '127.0.0.1',
    '--port',
    String(port),
  ]);
  prefixLines(child.stdout, { label: 'vuln ', colour: 'magenta', onLine });
  prefixLines(child.stderr, { label: 'vuln!', colour: 'red', target: process.stderr, onLine });
  return child;
}

function startOrigin({ stack, python, port, accounts, fixed }) {
  if (stack === 'python') return startPythonOrigin(python, port, accounts);
  return startShop({ port, accounts, fixed });
}

function startProxy(runBinaryPath, configArgument, token, cargoWatch) {
  const env = { ...process.env, HDD_ADMIN_TOKEN: token };
  let command;
  let args;
  if (cargoWatch.found) {
    command = 'cargo';
    args = ['watch', '-w', 'crates', '-x', `run -p hdd-proxy -- --config ${configArgument}`];
  } else {
    command = runBinaryPath;
    args = ['--config', configArgument];
  }
  const child = spawnProcess(command, args, { env });
  prefixLines(child.stdout, { label: 'proxy', colour: 'cyan' });
  prefixLines(child.stderr, { label: 'proxy', colour: 'red', target: process.stderr });
  return child;
}

function printBanner({
  plan,
  config,
  configLabel,
  profileArgument,
  tokenInfo,
  accounts,
  cargoWatch,
  fixed,
}) {
  const width = 96;
  const line = '='.repeat(width);
  const generated = plan.needsGeneratedProfile ? ` - GENERATED for this run (a configured port was in use)` : '';
  const isShop = config.stack !== 'python';
  const loginUrl = `${plan.origin.url}${config.loginPath}`;
  const proxyLoginUrl = `${plan.proxy.url}${config.loginPath}`;
  const adminLogin = accounts.get('admin');
  const adminPassword = adminLogin?.password ?? '(unknown)';
  const aiOn = String(process.env.DEEPSEEK_API_KEY ?? '').trim() !== '';
  console.log('');
  console.log(paint(line, 'green'));
  console.log(paint('  HDD HK1 local rehearsal stack is READY (loopback only; this is not a protection claim)', 'green'));
  console.log(paint(line, 'green'));
  console.log(`  config:            ${profileArgument}${generated} (committed profile: ${configLabel}; first site mode: ${config.mode})`);
  if (isShop) {
    console.log(`  lab shop (origin): ${paint(`${plan.origin.url}/`, 'magenta')}   (storefront; admin login ${paint(loginUrl, 'magenta')})`);
    console.log(`  fake admin login:  ${paint('admin / ' + adminPassword, 'magenta')}   (fake lab data, SHOP_VULN=${fixed ? '0 (fixed)' : (process.env.SHOP_VULN ?? 'unset -> injectable')})`);
    console.log(`  through HDD:       ${paint(proxyLoginUrl, 'cyan')}   (mode ${config.mode}: the same payload gets 403 + Ray ID + ban)`);
  } else {
    console.log(`  vulnerable origin: ${paint(loginUrl, 'magenta')}   (no HDD: the SQL injection reaches /admin)`);
    console.log(`  through HDD:       ${paint(proxyLoginUrl, 'cyan')}   (mode ${config.mode}: the same payload gets 403 + Ray ID + ban)`);
  }
  console.log(`  dashboard:         ${paint(`${plan.admin.url}/`, 'blue')}`);
  console.log(`  first-run setup:   ${paint(`${plan.admin.url}/setup`, 'blue')}   (only while no account exists)`);
  console.log(`  findings:          ${paint(`${plan.admin.url}/#/findings`, 'blue')}   (Addendum 6; API ${plan.admin.url}/api/findings)`);
  console.log('');
  if (tokenInfo.file) {
    console.log(`  admin token:       ${maskSecret(tokenInfo.token)}  (${tokenInfo.source})`);
    console.log(`                     full local value: ${tokenInfo.file.replace(`${repoRoot}/`, '').replace(`${repoRoot}\\`, '')}`);
  } else {
    console.log(`  admin token:       ${maskSecret(tokenInfo.token)}  (${tokenInfo.source})`);
  }
  if (isShop && adminLogin) {
    console.log(`  lab seed account:  admin / ${adminPassword} (role admin; fake lab data, printed by design)`);
  } else if (accounts.size > 0) {
    const accountList = Array.from(accounts, ([name, detail]) => `${name} / ${detail.password} (${detail.role})`).join(', ');
    console.log(`  lab seed accounts: ${accountList}`);
    console.log('                     random every start, lab only; use them to show a benign login through the proxy');
  } else {
    console.log('  lab seed accounts: not observed yet in the lab origin log');
  }
  console.log('');
  console.log('  attack (through HDD, expect 403 + Ray ID + ban for all 12; uses this run\'s proxy URL):');
  console.log(`    ${paint('npm run attack', 'yellow')}`);
  console.log(`  attack (direct origin, expect the admin dashboard reached for several payloads, login ${config.loginPath}):`);
  console.log(`    ${paint(`npm run attack -- --target ${plan.origin.url}`, 'yellow')}`);
  console.log('');
  console.log(`  AI explanation:    ${aiOn ? 'ON (DEEPSEEK_API_KEY is set; AI-generated text, verify before use)' : 'off (set DEEPSEEK_API_KEY to enable; the deterministic text stays)'}`);
  if (fixed) {
    console.log(
      `  remediation state: FIXED (SHOP_VULN=0): the same payloads no longer bypass at the origin; ` +
        'Confirm vulnerability should report not_confirmed.',
    );
  } else {
    console.log(
      `  remediation step:  ${paint('npm run demo:fixed', 'yellow')} (or SHOP_VULN=0 npm run dev) -> parameterised login, no bypass; then Confirm reports not_confirmed`,
    );
  }
  console.log(`  live reload: ${cargoWatch.found ? 'ON via cargo-watch (proxy restarts on crates/** changes)' : 'unavailable (cargo-watch not installed); the running proxy keeps its current binary'}`);
  console.log(`  full demo:  docs/DEMO.md (10-minute script)     stop: Ctrl+C`);
  console.log(paint(line, 'green'));
}

/**
 * Start the whole stack and keep it running. Resolves with the process exit code
 * when the stack stops (Ctrl+C, a child dying, or a startup failure).
 */
export async function runDev(argv = process.argv.slice(2), options = {}) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    fail(error.message);
    return 2;
  }
  if (args.help) {
    console.log(HELP);
    return 0;
  }
  const walkthrough = Boolean(options.walkthrough || args.walkthrough);
  const fixed = Boolean(options.fixed || args.fixed);

  info('HDD HK1 local rehearsal stack (dev profile: loopback only; this is not a protection claim)');

  const configPath = resolve(repoRoot, args.config);
  if (!existsSync(configPath)) {
    fail(
      `dev config not found: ${args.config}. The HK1 rehearsal profile is demo/hdd-dev.yaml (created by the ` +
        'integration step); it must exist in the repository root. Nothing was started.',
    );
    return 1;
  }
  const config = readDevConfig(configPath);
  const configLabel = args.config;
  if (fixed && config.stack === 'python') {
    fail('--fixed applies to the Node lab shop (stack: node); the Python lab origin has no SHOP_VULN switch.');
    return 2;
  }
  if (fixed) info('remediation run: SHOP_VULN=0 (parameterised lab shop login; the same payloads no longer bypass at the origin)');

  const prerequisites = checkPrerequisites({ requiresPython: config.stack === 'python' });
  if (!reportPrerequisites(prerequisites, { info, warn, fail })) return 1;
  if (config.stack !== 'python' && !prerequisites.python.found) {
    info('Python 3 not found: not needed for this run (the demo origin is the Node lab shop).');
  }

  // Endpoints: use the committed profile's ports when they are free; otherwise write a
  // generated per-run profile under hdd-data/ and use that (the committed profile is
  // never edited). The one clear fallback line is printed below.
  const plan = await planEndpoints(config, { configLabel });
  if (!plan.ok) {
    fail(plan.error);
    return 1;
  }
  for (const fallbackLine of plan.fallbackLines) warn(fallbackLine);

  let profileArgument = args.config;
  let generatedProfile = null;
  if (plan.needsGeneratedProfile) {
    const generatedPath = join(repoRoot, 'hdd-data', 'dev.generated.yaml');
    ensureDir(join(repoRoot, 'hdd-data'));
    writeFileSync(generatedPath, generateProfileText(config, plan, configLabel), { encoding: 'utf8' });
    profileArgument = relative(repoRoot, generatedPath).split('\\').join('/');
    generatedProfile = profileArgument;
    info(`per-run proxy profile: ${profileArgument} (the committed ${configLabel} is not modified)`);
  }

  if (!ensureProxyBinary(args.build)) return 1;
  const runBinary = copyRunBinary();

  const tokenInfo = resolveAdminToken();
  const dataDir = join(repoRoot, 'hdd-data');
  ensureDir(dataDir);
  info(`dev data directory: ${dataDir.replace(`${repoRoot}${isWindows ? '\\' : '/'}`, '')}`);
  const endpointsStatePath = writeEndpointState({
    plan,
    configLabel,
    profileArgument,
    generatedProfile,
    mode: config.mode,
    stack: config.stack,
    loginPath: config.loginPath,
  });
  info(`this run's endpoints: origin ${plan.origin.url}, proxy ${plan.proxy.url}, admin ${plan.admin.url}`);
  info(`npm run attack will use these endpoints (${relative(repoRoot, endpointsStatePath)}) from another terminal`);

  const accounts = new Map();
  const children = [];
  let shutdownPromise = null;
  let shuttingDown = false;
  let resolveExit = null;
  let exitCode = 0;

  const shutdown = (code, reason) => {
    if (shutdownPromise !== null) return shutdownPromise;
    shuttingDown = true;
    exitCode = code;
    shutdownPromise = (async () => {
      info(`stopping the local rehearsal stack (${reason}) ...`);
      for (const entry of [...children].reverse()) {
        await stopProcess(entry.child);
        info(`${entry.label} stopped`);
      }
      info('stack stopped. Nothing is listening on the demo ports any more.');
      if (resolveExit) resolveExit(exitCode);
    })();
    return shutdownPromise;
  };

  const track = (label, child) => {
    child.on('error', (error) => {
      fail(`${label} could not start: ${error.message}`);
      if (!shuttingDown) void shutdown(1, 'startup error');
    });
    child.on('exit', (code, signal) => {
      if (shuttingDown) return;
      fail(`${label} exited unexpectedly (code ${code ?? 'null'}, signal ${signal ?? 'none'}). Stopping the stack.`);
      if (label === 'proxy') {
        fail(
          'The proxy stopped; check the [proxy] output above (is demo/hdd-dev.yaml valid and is HDD_ADMIN_TOKEN set?).',
        );
      } else {
        fail(`The ${label} stopped; check the [shop ]/[vuln ] output above (port in use? dependency missing? server error?).`);
      }
      void shutdown(1, `${label} exit`);
    });
    children.push({ label, child });
    return child;
  };

  const onSigint = () => {
    info('Ctrl+C received: stopping children cleanly ...');
    void shutdown(0, 'Ctrl+C');
  };
  const onSigterm = () => {
    void shutdown(0, 'SIGTERM');
  };
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);

  const originLabel = config.stack === 'python' ? 'lab origin' : 'lab shop';

  try {
    info(`starting the deliberately vulnerable ${originLabel}${fixed ? ' (SHOP_VULN=0, fixed login)' : ''} ...`);
    const originChild = startOrigin({
      stack: config.stack,
      python: prerequisites.python,
      port: plan.origin.port,
      accounts,
      fixed,
    });
    if (originChild === null) {
      await shutdown(1, 'lab origin dependency missing');
      return exitCode;
    }
    track(originLabel, originChild);
    const originReady = await waitForPort(plan.origin.port, { timeoutMs: 20_000 });
    if (!originReady) {
      fail(
        `the ${originLabel} did not listen on 127.0.0.1:${plan.origin.port} within 20 s. See the [shop ]/[vuln ] ` +
          'output above (dependency missing? port already in use? server error?).',
      );
      await shutdown(1, 'lab origin not ready');
      return exitCode;
    }
    const health = await waitForHttp(`${plan.origin.url}/healthz`, {
      expectStatus: 200,
      timeoutMs: 10_000,
    });
    if (health === null) {
      fail(`the ${originLabel} port opened but /healthz did not answer with 200; see the child output above.`);
      await shutdown(1, 'lab origin health check failed');
      return exitCode;
    }
    info(`${originLabel} ready on ${plan.origin.url}${config.loginPath}`);

    info(
      prerequisites.details.cargoWatch.found
        ? 'starting the proxy under cargo-watch (live reload on crates/** changes) ...'
        : 'starting the proxy (live reload unavailable: cargo-watch not installed) ...',
    );
    if (prerequisites.details.cargoWatch.found) {
      info(
        'note: cargo-watch builds and runs target/debug/hdd-proxy.exe, so stop this dev stack before running the Rust ' +
          'gates (Windows locks a running executable)',
      );
    }
    track('proxy', startProxy(runBinary, profileArgument, tokenInfo.token, prerequisites.details.cargoWatch));
    const proxyReady = await waitForPort(plan.proxy.port, { timeoutMs: 60_000 });
    if (!proxyReady) {
      fail(
        `the proxy did not listen on 127.0.0.1:${plan.proxy.port} within 60 s. See the [proxy] output above ` +
          '(is the dev profile accepted? is HDD_ADMIN_TOKEN set? was the build up to date?).',
      );
      await shutdown(1, 'proxy not ready');
      return exitCode;
    }
    const adminReady = await waitForPort(plan.admin.port, { timeoutMs: 15_000 });
    if (!adminReady) {
      fail(
        `the proxy listener is up but the admin UI did not listen on 127.0.0.1:${plan.admin.port}. ` +
          'Check the [proxy] output: if the admin listener refuses to start without a token, set HDD_ADMIN_TOKEN.',
      );
      await shutdown(1, 'admin UI not ready');
      return exitCode;
    }
    info(`proxy ready on ${plan.proxy.url}, admin UI on ${plan.admin.url}`);

    printBanner({
      plan,
      config,
      configLabel,
      profileArgument,
      tokenInfo,
      accounts,
      cargoWatch: prerequisites.details.cargoWatch,
      fixed,
    });

    if (walkthrough) {
      await runWalkthrough({
        originBase: plan.origin.url,
        proxyBase: plan.proxy.url,
        adminBase: plan.admin.url,
        proxyHostHeader: config.siteHost,
        loginPath: config.loginPath,
        accounts,
        fixed,
        configArgument: profileArgument,
      });
      info('scripted walkthrough finished; the stack is still running (Ctrl+C to stop).');
    }

    return await new Promise((resolvePromise) => {
      resolveExit = resolvePromise;
    });
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    if (!shuttingDown) await shutdown(exitCode, 'shutdown');
    else await shutdownPromise;
  }
}

if (isMainModule(import.meta.url)) {
  runDev().then(
    (code) => {
      process.exitCode = typeof code === 'number' ? code : 0;
    },
    (error) => {
      fail(`dev launcher crashed: ${error?.stack ?? error}`);
      process.exitCode = 1;
    },
  );
}
