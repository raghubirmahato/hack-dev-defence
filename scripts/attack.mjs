// `npm run attack`: run the demo attack script against the local rehearsal stack.
//
// Default target: the proxy endpoint of the last `npm run dev` run (recorded in the
// git-ignored hdd-data/dev-endpoints.json, which accounts for the per-run port
// fallback; it is http://127.0.0.1:8080 when the configured port was free).
// Use --target <origin URL> for the direct vulnerable origin (printed by npm run dev).
//
// Safety: the target host must be loopback or listed in lab/demo/targets.allow
// (enforced here as an early refusal and again inside the attack scripts). Only the
// login endpoint is requested; no scanning, never a third-party host.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { readEndpointState } from './dev.mjs';
import { checkTargetAllowed } from './lib/allowlist.mjs';
import { fail, info, isMainModule, isWindows, repoRoot, runCaptured, runVisible, sameUrl } from './lib/util.mjs';

const HELP = `Usage: npm run attack [-- options]

Runs lab/demo/attack.ps1 (Windows) or lab/demo/attack.sh (Linux/macOS) against the
local rehearsal target: the 12 HK1 demo payloads (6 mandated SQLi M1-M6 + 6
auth-bypass forms), as login POSTs and GET query strings, rate-capped at 2 req/s,
with a final "reached admin / blocked yes/no per payload" table.

Options:
  --target <url>     target base URL (default $HDD_ATTACK_TARGET, else the proxy URL of
                     the last "npm run dev" run, else http://127.0.0.1:8080)
  --login-path <p>   login endpoint path (default: the last dev run's login path,
                     else /admin/login for the lab shop)
  --user-field <n>   login username field name (default username)
  --pass-field <n>   login password field name (default password)
  --kind <k>         auto | direct | proxy | target (default derived: the last dev run's
                     proxy URL = proxy, its origin URL = direct, else auto by port)
  --dashboard-url <url> optional HDD dashboard URL to print with a through-HDD run
  --help             print this help

Exit codes: 0 run executed (the yes/no table is the result, even when nothing was
blocked), 2 usage/prerequisite, 3 refused by targets.allow, 4 invalid target, 1 every
request failed at transport level.

Safety: the target host must be loopback (127.0.0.0/8, ::1, localhost) or listed in
lab/demo/targets.allow, one operator-authorised host per line. The attack scripts
refuse before sending anything otherwise. This is a lab demo, not a security product.
`;

/** Parse the small launcher CLI (no third-party argument parser). */
export function parseArgs(argv) {
  const args = {
    target: process.env.HDD_ATTACK_TARGET || '',
    loginPath: '',
    userField: '',
    passField: '',
    kind: '',
    dashboardUrl: '',
    help: false,
  };
  const rest = [...argv];
  const valueFor = (flag) => {
    if (rest.length === 0) throw new Error(`${flag} needs a value`);
    return rest.shift();
  };
  while (rest.length > 0) {
    const current = rest.shift();
    if (current === '--help' || current === '-h') args.help = true;
    else if (current === '--target' || current === '-t') args.target = valueFor(current);
    else if (current.startsWith('--target=')) args.target = current.slice('--target='.length);
    else if (current === '--login-path') args.loginPath = valueFor(current);
    else if (current === '--user-field') args.userField = valueFor(current);
    else if (current === '--pass-field') args.passField = valueFor(current);
    else if (current === '--kind') args.kind = valueFor(current);
    else if (current === '--dashboard-url') args.dashboardUrl = valueFor(current);
    else throw new Error(`unknown option: ${current} (use --help)`);
  }
  return args;
}

function findCommand(candidates, probeArgs) {
  for (const candidate of candidates) {
    if (candidate.includes('\\') && !existsSync(candidate)) continue;
    const probe = runCaptured(candidate, probeArgs, { timeoutMs: 30_000 });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

/**
 * Resolve the target (and its direct/proxy meaning) using the endpoints recorded by
 * the last `npm run dev` run, then validate the allowlist; returns the exit code.
 */
export async function runAttack(argv = process.argv.slice(2)) {
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

  const endpoints = readEndpointState();
  if (args.target === '') {
    args.target = endpoints?.proxyUrl || 'http://127.0.0.1:8080';
  }
  if (args.kind === '') {
    if (endpoints && sameUrl(args.target, endpoints.proxyUrl)) args.kind = 'proxy';
    else if (endpoints && sameUrl(args.target, endpoints.originUrl)) args.kind = 'direct';
  }
  if (endpoints) {
    info(
      `endpoints from the last npm run dev: proxy ${endpoints.proxyUrl}, origin ${endpoints.originUrl}` +
        `${endpoints.fallback ? ' (that run used a fallback port)' : ''} (hdd-data/dev-endpoints.json)`,
    );
  }

  const allowlistPath = join(repoRoot, 'lab', 'demo', 'targets.allow');
  const allowlistText = existsSync(allowlistPath) ? readFileSync(allowlistPath, 'utf8') : '';
  const gate = checkTargetAllowed({ targetUrl: args.target, allowlistText });
  if (!gate.valid) {
    fail(`refusing before anything is sent: ${gate.error}`);
    return 4;
  }
  if (!gate.allowed) {
    fail(`refusing before anything is sent: ${gate.reason}`);
    fail('no request was sent. Loopback hosts are always allowed for the local rehearsal.');
    return 3;
  }

  if (args.loginPath === '' && endpoints?.loginPath) args.loginPath = endpoints.loginPath;
  const effectiveKind = args.kind || gate.kind;
  info(`npm run attack: target ${args.target} (${gate.reason}; kind ${effectiveKind})`);
  if (effectiveKind === 'direct') {
    info('note: this is the DIRECT vulnerable lab shop (no HDD). Expect "reached admin: yes" for several payloads on the /admin/login form.');
  } else if (effectiveKind === 'proxy') {
    info('note: this is THROUGH HDD. In block mode expect 403 + Ray ID and a ban for all 12 payloads.');
  }

  if (isWindows) {
    const shell = findCommand(['pwsh', 'powershell'], ['-NoProfile', '-Command', 'exit 0']);
    if (shell === null) {
      fail('neither pwsh nor powershell was found on PATH; cannot run lab/demo/attack.ps1.');
      return 2;
    }
    const script = join(repoRoot, 'lab', 'demo', 'attack.ps1');
    const extras = [];
    if (args.loginPath !== '') extras.push('-LoginPath', args.loginPath);
    if (args.userField !== '') extras.push('-UserField', args.userField);
    if (args.passField !== '') extras.push('-PassField', args.passField);
    if (args.kind !== '') extras.push('-Kind', args.kind);
    const dashboardUrl = args.dashboardUrl !== '' ? args.dashboardUrl : endpoints?.adminUrl || '';
    if (dashboardUrl !== '') extras.push('-DashboardUrl', dashboardUrl);
    info(`running: lab/demo/attack.ps1 -TargetUrl ${args.target} ${extras.join(' ')}`.trim());
    return runVisible(shell, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-TargetUrl', args.target, ...extras]);
  }

  const bash = findCommand(['bash'], ['--version']);
  if (bash === null) {
    fail('bash was not found on PATH; cannot run lab/demo/attack.sh.');
    return 2;
  }
  const script = join(repoRoot, 'lab', 'demo', 'attack.sh');
  const extras = [];
  if (args.loginPath !== '') extras.push('--login-path', args.loginPath);
  if (args.userField !== '') extras.push('--user-field', args.userField);
  if (args.passField !== '') extras.push('--pass-field', args.passField);
  if (args.kind !== '') extras.push('--kind', args.kind);
  const dashboardUrl = args.dashboardUrl !== '' ? args.dashboardUrl : endpoints?.adminUrl || '';
  if (dashboardUrl !== '') extras.push('--dashboard-url', dashboardUrl);
  info(`running: lab/demo/attack.sh --target ${args.target} ${extras.join(' ')}`.trim());
  return runVisible(bash, [script, '--target', args.target, ...extras]);
}

if (isMainModule(import.meta.url)) {
  runAttack().then(
    (code) => {
      process.exitCode = typeof code === 'number' ? code : 0;
    },
    (error) => {
      fail(`attack launcher crashed: ${error?.stack ?? error}`);
      process.exitCode = 1;
    },
  );
}
