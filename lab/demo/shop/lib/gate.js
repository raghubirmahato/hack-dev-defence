'use strict';
// Front-door ("gateway") mode for a locked shop. A request that does not carry HDD's secret header is not served: it is passed
// on to HDD (HDD_GATE_URL), which inspects it and, when it is clean, calls this same shop again with the secret. The address
// the visitor typed therefore never changes, and HDD's mode (off / monitor / block) decides what happens to every request.
// If HDD cannot be reached the request is refused (503), never served uninspected.
const http = require('http');
const https = require('https');

const HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
  'host', 'content-length', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'forwarded', 'x-hdd-gate-hop',
  'x-hdd-origin-secret',
]);
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 16 });
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 16 });
const ATTEMPTS = 5;
const MAX_BODY = 1024 * 1024;
const TIMEOUT_MS = 20000;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function parseGateUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u : null;
  } catch (e) { return null; }
}

async function readBody(req) {
  if (req.readable === false && req.body !== undefined) {
    const b = req.body;
    if (Buffer.isBuffer(b)) return b;
    if (typeof b === 'string') return Buffer.from(b);
    const type = String(req.headers['content-type'] || '');
    return Buffer.from(/json/i.test(type) ? JSON.stringify(b) : new URLSearchParams(b).toString());
  }
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > MAX_BODY) { const e = new Error('body too large'); e.code = 'TOO_LARGE'; throw e; }
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

// A small, self-contained HTML answer (no external assets) for refusals made before the shop itself is reached.
function refuse(res, code, headline, detail, extraHtml) {
  res.statusCode = code;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(headline)}</title><style>body{font:16px/1.55 system-ui,Segoe UI,sans-serif;background:#f4f7fa;color:#14202b;display:grid;place-items:center;min-height:100vh;margin:0}main{max-width:520px;background:#fff;border:1px solid #d8e1e8;border-radius:14px;padding:28px;margin:16px}h1{font-size:22px;margin:0 0 8px}p{margin:.5em 0;color:#3d4f5f}</style><main><h1>${esc(headline)}</h1><p>${esc(detail)}</p>${extraHtml || ''}<p>Protected by Hack Dev Defence (HDD)</p></main>`);
}

// Forward one request to HDD and stream the answer back.
async function forward(req, res, gateUrl) {
  let body;
  try { body = await readBody(req); } catch (e) {
    return refuse(res, e.code === 'TOO_LARGE' ? 413 : 400, 'Request refused', 'The request could not be read.');
  }
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k.toLowerCase())) headers[k] = v;
  const client = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '';
  // HDD (and any tunnel in front of it) routes by this Host, so it names HDD; the address the visitor used travels in x-forwarded-host.
  headers.host = gateUrl.host;
  if (req.headers.host) headers['x-forwarded-host'] = req.headers.host;
  headers['accept-encoding'] = 'identity';
  headers['x-hdd-gate-hop'] = '1';
  headers['x-forwarded-proto'] = 'https';
  if (client) headers['x-forwarded-for'] = client;
  if (body.length) headers['content-length'] = String(body.length);
  const target = new URL(req.url || '/', gateUrl);
  const lib = target.protocol === 'https:' ? https : http;
  const agent = target.protocol === 'https:' ? httpsAgent : httpAgent;
  const replayable = req.method === 'GET' || req.method === 'HEAD';
  // One attempt. Resolves 'retry' only when the connection broke before HDD answered and trying again cannot send the request
  // twice: a GET/HEAD, or a request that failed on a reused socket the other side had already closed (it never reached HDD).
  const attempt = (n) => new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const out = lib.request({ protocol: target.protocol, hostname: target.hostname, port: target.port, path: target.pathname + target.search, method: req.method, headers, timeout: TIMEOUT_MS, agent }, (back) => {
      res.statusCode = back.statusCode || 502;
      for (const [k, v] of Object.entries(back.headers)) if (!HOP.has(k.toLowerCase())) res.setHeader(k, v);
      back.on('end', () => done('ok'));
      back.on('error', () => { res.destroy(); done('ok'); });
      back.pipe(res);
    });
    out.on('timeout', () => { out.destroy(); });
    out.on('error', (e) => {
      console.error('gate: HDD request failed (attempt ' + n + '):', e && (e.code || e.message));
      if (res.headersSent) { res.destroy(); return done('ok'); }
      done(n < ATTEMPTS && (replayable || out.reusedSocket) ? 'retry' : 'fail');
    });
    out.end(body);
  });
  for (let n = 1; n <= ATTEMPTS; n++) {
    const outcome = await attempt(n);
    if (outcome === 'ok') return;
    if (outcome === 'fail') break;
    await new Promise((r) => setTimeout(r, 300 * n));
  }
  if (!res.headersSent) refuse(res, 503, 'Protection is unavailable', 'This site only answers through Hack Dev Defence, and HDD could not be reached. The request was not served. Try again shortly.');
}

module.exports = { parseGateUrl, forward, refuse };
