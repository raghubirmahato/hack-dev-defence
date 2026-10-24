// Target allowlist rules shared by `npm run attack` and the node --test suite.
//
// The canonical enforcement lives in lab/demo/attack.ps1 and lab/demo/attack.sh
// (they refuse before sending), and this module mirrors the same rules so the npm
// wrapper can explain the refusal before spawning them and so the rules are tested.
//
// Rules:
//   * loopback hosts (127.0.0.0/8, ::1, localhost) are always allowed: the local
//     rehearsal never leaves the machine;
//   * any other host must appear exactly (case-insensitively) in
//     lab/demo/targets.allow, one operator-authorised host per line;
//   * '#' starts a comment, blank lines are ignored;
//   * no wildcards: each hostname is listed explicitly.

/** Strip IPv6 brackets and lower-case a hostname for comparison. */
export function normalizeHost(host) {
  const text = String(host ?? '').trim().toLowerCase();
  if (text.startsWith('[') && text.endsWith(']')) return text.slice(1, -1);
  return text;
}

/** True for localhost, ::1 and any 127.0.0.0/8 address with valid octets. */
export function isLoopbackHost(host) {
  const normalized = normalizeHost(host);
  if (normalized === '') return false;
  if (normalized === 'localhost') return true;
  if (normalized === '::1') return true;
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(normalized);
  if (!match) return false;
  return match.slice(1).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

/** Parse a targets.allow file body into the list of host entries. */
export function parseTargetsAllow(text) {
  return String(text ?? '')
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter((line) => line.length > 0);
}

/**
 * Validate and classify a target URL.
 * kind: direct (loopback:8082 lab shop or 8081 older Python lab app), proxy
 * (loopback:8080), target (anything else).
 * Returns { valid, error?, host?, port?, isLoopback?, kind? }.
 */
export function classifyTarget(targetUrl) {
  const text = String(targetUrl ?? '').trim();
  if (text === '') return { valid: false, error: 'no target URL given' };
  let url;
  try {
    url = new URL(text);
  } catch {
    return { valid: false, error: `target URL is not an absolute http(s) URL: '${text}'` };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { valid: false, error: `target URL scheme must be http or https, got '${url.protocol.replace(':', '')}'` };
  }
  if (url.username !== '' || url.password !== '') {
    return { valid: false, error: 'target URL must not contain embedded credentials (no secrets in URLs)' };
  }
  const host = normalizeHost(url.hostname);
  if (host === '') return { valid: false, error: `target URL has no host: '${text}'` };
  const defaultPort = url.protocol === 'https:' ? 443 : 80;
  const port = url.port === '' ? defaultPort : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { valid: false, error: `invalid port in target URL: '${url.port}'` };
  }
  const loopback = isLoopbackHost(host);
  let kind = 'target';
  if (loopback && (port === 8082 || port === 8081)) kind = 'direct';
  else if (loopback && port === 8080) kind = 'proxy';
  return { valid: true, host, port, isLoopback: loopback, kind, path: url.pathname };
}

/**
 * Apply the allowlist gate to a target URL.
 * @param {{targetUrl: string, allowlistText?: string}} input
 *   allowlistText is the body of lab/demo/targets.allow ('' when the file is absent).
 * @returns {{valid: boolean, allowed: boolean, reason: string, error?: string,
 *            host?: string, port?: number, isLoopback?: boolean, kind?: string}}
 */
export function checkTargetAllowed({ targetUrl, allowlistText = '' }) {
  const classified = classifyTarget(targetUrl);
  if (!classified.valid) {
    return { ...classified, allowed: false, reason: classified.error };
  }
  if (classified.isLoopback) {
    return {
      ...classified,
      allowed: true,
      reason: 'loopback host -> always allowed (no lab/demo/targets.allow entry needed)',
    };
  }
  const entries = parseTargetsAllow(allowlistText);
  const matched = entries.some((entry) => normalizeHost(entry) === classified.host);
  if (matched) {
    return { ...classified, allowed: true, reason: 'host listed in lab/demo/targets.allow' };
  }
  return {
    ...classified,
    allowed: false,
    reason:
      `target host '${classified.host}' is not loopback and is not listed in lab/demo/targets.allow. ` +
      'Create that file (see lab/demo/targets.allow.example) with one operator-authorised host per line.',
  };
}
