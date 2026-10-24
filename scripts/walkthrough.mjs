// Scripted walkthrough for `npm run demo` (also `npm run dev -- --walkthrough`).
//
// It makes REAL requests on loopback only and prints what it actually observed:
//   1. a seeded benign login through the proxy reaches the lab shop admin dashboard,
//   2. directly against the lab shop the M1 SQL injection reaches the admin dashboard
//      (or, with `--fixed` / SHOP_VULN=0, does NOT reach it - the remediation state),
//   3. the same M1 request through HDD in block mode gets a 403 (block page, Ray ID),
//   4. the source is then banned (the next request is 403 even though it is benign),
// then it prints where the Findings/confirm/AI views are.
//
// It never flips the site mode itself (that is the human demo step in docs/DEMO.md)
// and it makes no protection claim: it reports PASS/FAIL/UNVERIFIED lines for these
// runs on this machine only. All requests go to the loopback URLs the launcher started.

import { httpRequest, paint } from './lib/util.mjs';

// The lab shop's admin shell has "CoreByte Admin" in the title and "Demo data only" on
// the dashboard; the old Python lab page used data-page="admin"/"Admin panel". Accept
// both so a profile with `stack: python` still works.
const ADMIN_MARKER = /Demo data only|<title>Dashboard \| CoreByte Admin<\/title>|<h1>\s*Admin panel\s*<\/h1>|data-page="admin"/i;
const LOGIN_MARKER = /Store administration|Admin sign in|data-page="login"/i;
const RAY_ID = /([0-9a-f]{16}-HDD1)/i;
const BLOCK_TEXT = /access denied|your request looked like an attack|blocked by hdd/i;
const M1 = "' OR 1=1--";

export function printResult(result) {
  const badge =
    result.status === 'PASS'
      ? paint('PASS', 'green')
      : result.status === 'FAIL'
        ? paint('FAIL', 'red')
        : paint('UNVERIFIED', 'yellow');
  console.log(`  [walkthrough] ${result.step}: ${badge} - ${result.detail}`);
}

function printSection(title) {
  console.log('');
  console.log(paint('='.repeat(96), 'blue'));
  console.log(paint(`  ${title}`, 'blue'));
  console.log(paint('='.repeat(96), 'blue'));
}

function formBody(username, password) {
  return `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;
}

async function postLogin(base, loginPath, username, password, extraHeaders = {}) {
  return httpRequest({
    method: 'POST',
    url: `${base}${loginPath}`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'text/html',
      ...extraHeaders,
    },
    body: formBody(username, password),
    cookieJar: new Map(),
    timeoutMs: 8_000,
  });
}

async function getLogin(base, loginPath, extraHeaders = {}) {
  return httpRequest({
    url: `${base}${loginPath}`,
    headers: { Accept: 'text/html', ...extraHeaders },
    timeoutMs: 8_000,
  });
}

function ensureHeaders(proxyHostHeader) {
  return proxyHostHeader && proxyHostHeader !== '' ? { Host: proxyHostHeader } : {};
}

function reachedAdmin(response) {
  return response.status === 200 && ADMIN_MARKER.test(response.body) && !LOGIN_MARKER.test(response.body);
}

/**
 * Run the four scripted observations. Every step is guarded: a thrown request
 * becomes UNVERIFIED(reason) instead of aborting the walkthrough.
 */
export async function runWalkthrough({
  originBase,
  proxyBase,
  adminBase,
  proxyHostHeader,
  loginPath = '/admin/login',
  accounts,
  fixed = false,
  configArgument,
}) {
  printSection('SCRIPTED WALKTHROUGH - real loopback requests, observed output only');
  console.log(`  login endpoint: ${loginPath} (fields username/password)   origin: ${originBase}   through HDD: ${proxyBase}`);
  if (fixed) console.log('  remediation state: SHOP_VULN=0 (parameterised shop login)');
  const results = [];
  const headers = ensureHeaders(proxyHostHeader);
  const admin = accounts instanceof Map ? accounts.get('admin') : undefined;

  // 1. benign login through HDD: the detector must not block normal credentials.
  if (!admin) {
    results.push({
      step: '1/4 benign seeded login through HDD',
      status: 'UNVERIFIED',
      detail: 'no seeded admin credential was observed; the launcher prints the fake admin/admin lab credential',
    });
  } else {
    try {
      const response = await postLogin(proxyBase, loginPath, 'admin', admin.password, headers);
      if (reachedAdmin(response)) {
        results.push({
          step: '1/4 benign seeded login through HDD',
          status: 'PASS',
          detail: `HTTP ${response.status}: benign login reached the admin dashboard (no false positive)`,
        });
      } else if (response.status === 403 || BLOCK_TEXT.test(response.body)) {
        results.push({
          step: '1/4 benign seeded login through HDD',
          status: 'FAIL',
          detail:
            `HTTP ${response.status}: the benign login was blocked. The source may be banned from an earlier run ` +
            `(unban it in the dashboard Bans page at ${adminBase}) or the proxy mode rule is wrong.`,
        });
      } else {
        results.push({
          step: '1/4 benign seeded login through HDD',
          status: 'FAIL',
          detail: `HTTP ${response.status} after ${response.redirects} redirect(s): expected 200 with the admin dashboard`,
        });
      }
    } catch (error) {
      results.push({
        step: '1/4 benign seeded login through HDD',
        status: 'UNVERIFIED',
        detail: `request failed: ${error?.message ?? error}`,
      });
    }
  }

  // 2. direct origin M1: the "without HDD" proof (or the remediation proof when fixed).
  try {
    const response = await postLogin(originBase, loginPath, M1, M1);
    if (reachedAdmin(response)) {
      if (fixed) {
        results.push({
          step: '2/4 M1 SQL injection DIRECT to the fixed shop origin',
          status: 'FAIL',
          detail: 'SHOP_VULN=0 was requested but the admin dashboard was still reached at the origin: the lab shop is not fixed!',
        });
      } else {
        results.push({
          step: '2/4 M1 SQL injection DIRECT to the shop origin',
          status: 'PASS',
          detail: `HTTP ${response.status}: M1 "' OR 1=1--" reached the admin dashboard without HDD (the vulnerability is real)`,
        });
      }
    } else if (fixed) {
      results.push({
        step: '2/4 M1 SQL injection DIRECT to the fixed shop origin',
        status: 'PASS',
        detail: `HTTP ${response.status}: with SHOP_VULN=0 the same payload does not reach the admin dashboard (remediation applied at the origin)`,
      });
    } else {
      results.push({
        step: '2/4 M1 SQL injection DIRECT to the shop origin',
        status: 'FAIL',
        detail: `HTTP ${response.status}: expected the admin dashboard; is the shop running with SHOP_VULN=0?`,
      });
    }
  } catch (error) {
    results.push({
      step: '2/4 M1 SQL injection DIRECT to the shop origin',
      status: 'UNVERIFIED',
      detail: `request failed: ${error?.message ?? error}`,
    });
  }

  // 3. the same M1 through HDD in block mode.
  try {
    const response = await postLogin(proxyBase, loginPath, M1, M1, headers);
    const ray = RAY_ID.exec(response.body);
    const blocked = response.status === 403 || response.status === 429 || BLOCK_TEXT.test(response.body);
    if (reachedAdmin(response)) {
      results.push({
        step: '3/4 M1 SQL injection THROUGH HDD (block mode)',
        status: 'FAIL',
        detail: 'the admin dashboard was reached through the proxy: this run did NOT block, do not claim protection (R-34)',
      });
    } else if (blocked) {
      results.push({
        step: '3/4 M1 SQL injection THROUGH HDD (block mode)',
        status: 'PASS',
        detail: ray
          ? `HTTP ${response.status}: blocked; block page Ray ID ${ray[1]}`
          : `HTTP ${response.status}: blocked (no Ray ID parsed; this may be the early ban response)`,
      });
    } else {
      results.push({
        step: '3/4 M1 SQL injection THROUGH HDD (block mode)',
        status: 'FAIL',
        detail: `HTTP ${response.status}: expected 403 with a block page; check the proxy site mode (demo/hdd-dev.yaml)`,
      });
    }
  } catch (error) {
    results.push({
      step: '3/4 M1 SQL injection THROUGH HDD (block mode)',
      status: 'UNVERIFIED',
      detail: `request failed: ${error?.message ?? error}`,
    });
  }

  // 4. the source is banned: even a benign request now gets the early 403.
  try {
    const response = await getLogin(proxyBase, loginPath, headers);
    if (response.status === 403 || response.status === 429) {
      results.push({
        step: '4/4 source ban after the blocked payload',
        status: 'PASS',
        detail: `HTTP ${response.status}: the next (benign) request from the same source is refused (ban active)`,
      });
    } else {
      results.push({
        step: '4/4 source ban after the blocked payload',
        status: 'FAIL',
        detail: `HTTP ${response.status}: expected 403 while the ban is active; check ban.enabled and the TTL ladder`,
      });
    }
  } catch (error) {
    results.push({
      step: '4/4 source ban after the blocked payload',
      status: 'UNVERIFIED',
      detail: `request failed: ${error?.message ?? error}`,
    });
  }

  console.log('');
  for (const result of results) printResult(result);
  const pass = results.filter((result) => result.status === 'PASS').length;
  console.log('');
  console.log(`  [walkthrough] ${pass}/${results.length} observations PASS (these are local loopback runs, not a claim about any live site).`);
  console.log('');
  console.log('  Findings, attacker impact, remediation and confirm (Addendum 6):');
  console.log(`    * Findings screen: ${paint(`${adminBase}/#/findings`, 'blue')}   (API: ${adminBase}/api/findings)`);
  console.log('    * the blocked M1 event groups into a finding for POST ' + loginPath + ' field username: exact detection line,');
  console.log('      inferred weakness, attacker impact and a parameterised-query fix for the Node/sql.js shop stack');
  console.log('    * "Confirm vulnerability" needs the typed site host; it sends at most 4 inert read-only probes to the registered site');
  console.log('');
  console.log('  Manual demo steps (the 10-minute script is docs/DEMO.md):');
  console.log(`    * dashboard: ${paint(`${adminBase}/`, 'blue')} - the blocked event and the ban are listed there`);
  if (fixed) {
    console.log('    * this run is the remediated origin (SHOP_VULN=0): even with protection off the payload does not log in;');
    console.log('      Confirm vulnerability should report not_confirmed. Restart without --fixed for the vulnerable shop.');
  } else {
    console.log('    * flip protection off live (typed confirm), repeat step 2/3 through the proxy, expect the dashboard to open');
    console.log(`      (that is the contrast); flip back to block. Remediation step next: ${paint('npm run demo:fixed', 'yellow')}`);
  }
  console.log(`    * unban the source in the dashboard Bans page (the source is banned after step 3)`);
  console.log('    * AI explanation: optional; set DEEPSEEK_API_KEY to enable it. AI-generated text is labelled "verify before use"');
  console.log('      and the AI never decides a block or a ban (deterministic verdicts stay authoritative)');
}
