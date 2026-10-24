'use strict';
// Presentation layer of the lab demo shop (fictional brand "CoreByte"; fictional product brands; fake data).
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (n) => '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const CATS = [
  ['gpu', 'Graphics cards'], ['cpu', 'Processors'], ['ram', 'Memory'], ['ssd', 'Storage'], ['mb', 'Motherboards'],
  ['psu', 'Power supplies'], ['case', 'Cases'], ['cooler', 'Cooling'], ['monitor', 'Monitors'], ['kb', 'Peripherals'],
];
const catName = (c) => (CATS.find((x) => x[0] === c) || [0, c])[1];

const CSS = `
:root{--navy:#0b1b2b;--navy2:#13283d;--ac:#ff6a13;--ac2:#e65a08;--bg:#f2f4f7;--card:#fff;--fg:#17212b;--mu:#667585;--bd:#dfe4ea;--ok:#13804d;--warn:#b86e00;--bad:#c0392b;--blue:#1664d9}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}
a{color:inherit;text-decoration:none}a:hover{color:var(--ac)}h1,h2,h3{line-height:1.25;margin:0 0 .5em}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px}
.top{background:var(--navy);color:#cfd8e3;font-size:13px}.top .wrap{display:flex;justify-content:space-between;padding:7px 20px;gap:12px;flex-wrap:wrap}
.hd{background:var(--navy2);color:#fff}.hd .wrap{display:flex;align-items:center;gap:20px;padding:14px 20px}
.logo{font-weight:800;font-size:24px;letter-spacing:-.5px;display:flex;align-items:center;gap:8px;color:#fff}.logo span{display:inline}.logo b{color:var(--ac)}
.logo i{display:inline-block;width:28px;height:28px;border-radius:7px;background:linear-gradient(135deg,var(--ac),#ffb066)}
.sr{flex:1;display:flex;max-width:620px}.sr input{flex:1;border:0;border-radius:8px 0 0 8px;padding:11px 14px;font:inherit;min-width:0}
.sr button{border:0;background:var(--ac);color:#fff;padding:0 20px;border-radius:0 8px 8px 0;font-weight:600;cursor:pointer}.sr button:hover{background:var(--ac2)}
.hl{display:flex;gap:18px;align-items:center;color:#fff;font-size:14px;margin-left:auto}.cart{background:rgba(255,255,255,.1);padding:9px 14px;border-radius:8px;font-weight:600}.cart span{background:var(--ac);border-radius:10px;padding:1px 8px;margin-left:6px;font-size:12px}
.nav{background:#fff;border-bottom:1px solid var(--bd)}.nav .wrap{display:flex;gap:4px;overflow:auto;padding:0 20px}.nav a{padding:12px 14px;font-weight:600;font-size:14px;white-space:nowrap;border-bottom:3px solid transparent}.nav a.on,.nav a:hover{border-color:var(--ac);color:var(--ac)}
.hero{background:linear-gradient(120deg,#0b1b2b 0%,#18385a 60%,#ff6a13 160%);color:#fff;border-radius:16px;margin:22px 0;padding:42px;display:flex;justify-content:space-between;align-items:center;gap:20px;overflow:hidden}
.hero h1{font-size:38px;max-width:520px;margin-bottom:10px}.hero p{max-width:480px;color:#d4deea;margin:0 0 18px}.hero .art{width:280px;flex:none;opacity:.95}
.btn{display:inline-block;background:var(--ac);color:#fff;border:0;border-radius:8px;padding:11px 20px;font:600 15px inherit;cursor:pointer}.btn:hover{background:var(--ac2);color:#fff}.btn.ghost{background:#fff;color:var(--fg);border:1px solid var(--bd)}.btn.sm{padding:7px 12px;font-size:13px}.btn.block{width:100%;text-align:center}
.perks{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:24px}.perk{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;font-size:14px}.perk b{display:block}
.sec{display:flex;justify-content:space-between;align-items:end;margin:26px 0 12px}.sec h2{margin:0;font-size:22px}.sec span{color:var(--mu);font-size:14px}
.cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}.cat{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px;text-align:center;font-weight:600;font-size:14px}.cat:hover{border-color:var(--ac);box-shadow:0 4px 14px rgba(0,0,0,.08)}.cat svg{width:100%;height:70px;margin-bottom:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}
.pc{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;position:relative}.pc:hover{box-shadow:0 8px 22px rgba(11,27,43,.12)}
.pc .img{background:#eef2f6;display:block}.pc .img svg{display:block;width:100%;height:170px}.pc .bd{padding:14px;display:flex;flex-direction:column;gap:6px;flex:1}
.brand{color:var(--mu);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.pc h3{font-size:15px;margin:0}.specs{color:var(--mu);font-size:13px;margin:0}
.rt{color:#e8a200;font-size:13px}.rt small{color:var(--mu)}.pr{font-size:21px;font-weight:800}.pr s{color:var(--mu);font-weight:400;font-size:14px;margin-left:6px}.pr em{font-style:normal;color:var(--bad);font-size:13px;font-weight:700;margin-left:6px}
.badge{position:absolute;top:10px;left:10px;background:var(--bad);color:#fff;font-size:12px;font-weight:700;border-radius:6px;padding:2px 8px}.stock{font-size:13px;font-weight:600}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.lay{display:grid;grid-template-columns:230px 1fr;gap:20px;margin-top:22px}.side{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;height:max-content}.side h3{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--mu)}.side a{display:block;padding:7px 8px;border-radius:6px;font-size:14px}.side a.on,.side a:hover{background:#fff1e8;color:var(--ac2)}
.crumb{color:var(--mu);font-size:13px;margin:16px 0}.pd{display:grid;grid-template-columns:1.1fr 1fr;gap:28px;background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:24px}.pd .img svg{width:100%;height:auto;border-radius:12px}.pd ul{padding-left:18px;color:#3a4756}
.tbl{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden}.tbl th,.tbl td{padding:11px 14px;text-align:left;border-bottom:1px solid var(--bd);font-size:14px}.tbl th{background:#f7f9fb;color:var(--mu);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.tbl tr:last-child td{border-bottom:0}
.box{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:20px}.row{display:grid;grid-template-columns:1fr 360px;gap:20px;align-items:start}
label{display:block;font-weight:600;font-size:13px;margin:12px 0 4px}input[type=text],input[type=email],input[type=password],input:not([type]),select{width:100%;padding:10px 12px;border:1px solid var(--bd);border-radius:8px;font:inherit;background:#fff;color:var(--fg)}input:focus{outline:2px solid #ffc9a3;border-color:var(--ac)}
.foot{background:var(--navy);color:#9fb0c3;margin-top:40px;font-size:13px}.foot .wrap{display:flex;justify-content:space-between;gap:20px;padding:26px 20px;flex-wrap:wrap}.foot b{color:#fff}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700}.pill.shipped{background:#e3f0ff;color:#0f4fa8}.pill.processing{background:#fff3d6;color:#8a5a00}.pill.delivered{background:#dff5e8;color:#0d6b3f}.pill.cancelled{background:#fde5e2;color:#9b2a1c}
.err{background:#fde8e5;color:#8f2418;border:1px solid #f4b9b1;border-radius:8px;padding:10px 12px;margin-bottom:10px}.note{color:var(--mu);font-size:13px}
.auth{min-height:100vh;display:grid;grid-template-columns:1fr 1fr}.auth .l{background:linear-gradient(140deg,#0b1b2b,#1a3a5e);color:#fff;padding:60px;display:flex;flex-direction:column;justify-content:center}.auth .l h1{font-size:34px}.auth .r{display:flex;align-items:center;justify-content:center;padding:30px;background:#fff}.auth form{width:100%;max-width:360px}
.adm{display:grid;grid-template-columns:230px 1fr;min-height:100vh}.as{background:var(--navy);color:#b9c6d6;padding:18px 12px}.as .logo{padding:6px 10px 18px;font-size:20px}.as a{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;font-size:14px;font-weight:600;margin-bottom:2px}.as a.on,.as a:hover{background:rgba(255,255,255,.09);color:#fff}.as .who{margin-top:24px;padding:12px;border-top:1px solid rgba(255,255,255,.1);font-size:13px}
.am{padding:24px 28px}.ah{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.ah h1{margin:0;font-size:24px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:18px}.kpi{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px}.kpi small{color:var(--mu);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.kpi b{display:block;font-size:26px;margin-top:4px}
.two{display:grid;grid-template-columns:2.2fr 1fr;gap:16px}.am .tbl td:nth-child(4){min-width:190px}.bar{height:9px;border-radius:5px;background:#e8edf2;overflow:hidden;margin:4px 0 12px}.bar i{display:block;height:100%;background:var(--ac)}
@media(max-width:860px){.lay,.pd,.row,.two,.auth,.adm{grid-template-columns:1fr}.hero{flex-direction:column;padding:26px}.hero .art{width:200px}.sr{order:3;max-width:none;flex-basis:100%}.hd .wrap{flex-wrap:wrap}.auth .l{padding:30px}.as{display:flex;flex-wrap:wrap;gap:4px}.as .who{display:none}}
`;

const G = (id, a, b) => `<linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${a}"/><stop offset="1" stop-color="${b}"/></linearGradient>`;
function art(cat, uid = 'a') {
  const bg = { gpu: ['#1f2a3a', '#3a4d66'], cpu: ['#2a2236', '#4b3a63'], ram: ['#15302b', '#2c5a4f'], ssd: ['#1d2b3d', '#34506f'], mb: ['#1c2c22', '#355a42'], psu: ['#2f2a1b', '#5c5232'], case: ['#222a33', '#3d4a58'], cooler: ['#13303a', '#2a6275'], monitor: ['#1c2230', '#364462'], kb: ['#2b2230', '#4f3c5a'] }[cat] || ['#222', '#444'];
  const f = `g${uid}${cat}`;
  const body = {
    gpu: '<rect x="30" y="52" width="180" height="56" rx="6" fill="#101722" stroke="#5f7a99"/><circle cx="82" cy="80" r="21" fill="#0a0f17" stroke="#8fb0d3"/><circle cx="82" cy="80" r="4" fill="#8fb0d3"/><circle cx="148" cy="80" r="21" fill="#0a0f17" stroke="#8fb0d3"/><circle cx="148" cy="80" r="4" fill="#8fb0d3"/><rect x="40" y="108" width="80" height="8" fill="#c9a43a"/><rect x="196" y="60" width="8" height="40" fill="#ff6a13"/>',
    cpu: '<rect x="82" y="40" width="76" height="76" rx="8" fill="#b8c0cc" stroke="#e8edf3"/><rect x="96" y="54" width="48" height="48" rx="4" fill="#59616e"/><text x="120" y="84" font-size="11" fill="#e8edf3" text-anchor="middle" font-family="monospace">CORE</text><g stroke="#e0b64a" stroke-width="3">' + [92, 106, 120, 134, 148].map((x) => `<line x1="${x}" y1="116" x2="${x}" y2="126"/><line x1="${x}" y1="30" x2="${x}" y2="40"/>`).join('') + '</g>',
    ram: '<rect x="28" y="62" width="184" height="36" rx="4" fill="#12201d" stroke="#6cc9b0"/><rect x="40" y="70" width="22" height="20" fill="#0a1311" stroke="#6cc9b0"/><rect x="70" y="70" width="22" height="20" fill="#0a1311" stroke="#6cc9b0"/><rect x="100" y="70" width="22" height="20" fill="#0a1311" stroke="#6cc9b0"/><rect x="130" y="70" width="22" height="20" fill="#0a1311" stroke="#6cc9b0"/><rect x="160" y="70" width="22" height="20" fill="#0a1311" stroke="#6cc9b0"/><rect x="30" y="98" width="180" height="6" fill="#c9a43a"/>',
    ssd: '<rect x="40" y="62" width="160" height="34" rx="5" fill="#101a28" stroke="#6ea0d4"/><rect x="50" y="70" width="36" height="18" fill="#0a111b" stroke="#6ea0d4"/><rect x="92" y="70" width="36" height="18" fill="#0a111b" stroke="#6ea0d4"/><rect x="40" y="96" width="30" height="8" fill="#c9a43a"/><circle cx="188" cy="79" r="4" fill="#ff6a13"/>',
    mb: '<rect x="50" y="26" width="140" height="108" rx="6" fill="#0f1c14" stroke="#6cc98a"/><rect x="88" y="48" width="38" height="38" rx="3" fill="#4a5360"/><rect x="140" y="38" width="8" height="52" fill="#101a12" stroke="#6cc98a"/><rect x="152" y="38" width="8" height="52" fill="#101a12" stroke="#6cc98a"/><rect x="62" y="104" width="100" height="6" fill="#6cc98a"/><rect x="62" y="116" width="100" height="6" fill="#6cc98a"/>',
    psu: '<rect x="44" y="40" width="152" height="82" rx="8" fill="#171a1e" stroke="#c9b25a"/><circle cx="96" cy="81" r="28" fill="#0c0e10" stroke="#c9b25a"/><circle cx="96" cy="81" r="5" fill="#c9b25a"/><rect x="140" y="52" width="44" height="12" rx="3" fill="#2a2f35"/><text x="162" y="92" font-size="14" fill="#c9b25a" text-anchor="middle" font-family="sans-serif" font-weight="700">750W</text>',
    case: '<rect x="70" y="24" width="100" height="112" rx="8" fill="#151b22" stroke="#7c93aa"/><rect x="80" y="34" width="60" height="92" rx="3" fill="#0a0e13" stroke="#3d4a58"/><circle cx="110" cy="62" r="15" fill="none" stroke="#7c93aa"/><circle cx="110" cy="102" r="15" fill="none" stroke="#7c93aa"/><rect x="150" y="34" width="12" height="8" fill="#ff6a13"/>',
    cooler: '<rect x="30" y="58" width="76" height="76" rx="10" fill="#0e2128" stroke="#5db7cf"/><circle cx="68" cy="96" r="28" fill="#08141a" stroke="#5db7cf"/><path d="M68 96 L68 72 M68 96 L89 108 M68 96 L47 108" stroke="#5db7cf" stroke-width="5"/><path d="M106 70 C150 40 180 40 210 62" stroke="#5db7cf" stroke-width="6" fill="none"/><path d="M106 96 C150 70 180 70 210 84" stroke="#5db7cf" stroke-width="6" fill="none"/>',
    monitor: '<rect x="36" y="26" width="168" height="98" rx="8" fill="#0b0f18" stroke="#8aa0cc"/><rect x="44" y="34" width="152" height="82" fill="url(#s' + uid + ')"/><rect x="108" y="124" width="24" height="14" fill="#8aa0cc"/><rect x="88" y="136" width="64" height="5" rx="2" fill="#8aa0cc"/>',
    kb: '<rect x="24" y="52" width="192" height="62" rx="8" fill="#17111c" stroke="#b08ac9"/>' + [0, 1, 2].map((r) => Array.from({ length: 11 - (r === 2 ? 3 : 0) }, (_, c) => `<rect x="${33 + c * 16 + (r === 2 ? 18 : 0)}" y="${60 + r * 16}" width="12" height="11" rx="2" fill="#2f2538" stroke="#6a4f80"/>`).join('')).join('') + '<rect x="70" y="99" width="100" height="10" rx="3" fill="#2f2538" stroke="#6a4f80"/>',
  }[cat] || '';
  return `<svg viewBox="0 0 240 160" preserveAspectRatio="xMidYMid slice" role="img" aria-label="${esc(catName(cat))}" xmlns="http://www.w3.org/2000/svg"><defs>${G(f, bg[0], bg[1])}${cat === 'monitor' ? G('s' + uid, '#ff6a13', '#1664d9') : ''}</defs><rect width="240" height="160" fill="url(#${f})"/>${body}</svg>`;
}

const stars = (r) => '★'.repeat(Math.round(r)) + '☆'.repeat(5 - Math.round(r));
const stockLine = (n) => (n <= 0 ? '<span class="stock bad">Out of stock</span>' : n < 10 ? `<span class="stock warn">Only ${n} left</span>` : '<span class="stock ok">In stock, ships today</span>');

function shell({ title, body, cartCount = 0, active = '', q = '' }) {
  const nav = CATS.map(([k, n]) => `<a href="/?c=${k}" class="${active === k ? 'on' : ''}">${esc(n)}</a>`).join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} | CoreByte Hardware</title><style>${CSS}</style>
<div class="top"><div class="wrap"><span>Free shipping on orders over $99 &nbsp;·&nbsp; 30-day returns</span><span>Support: 1-800-555-0142 &nbsp;·&nbsp; Mon-Sat 9-6</span></div></div>
<div class="hd"><div class="wrap"><a class="logo" href="/"><i></i><span>Core<b>Byte</b></span></a><form class="sr" action="/" method="get"><input name="q" value="${esc(q)}" placeholder="Search GPUs, CPUs, SSDs, monitors..." aria-label="Search products"><button>Search</button></form><div class="hl"><a href="/admin">Admin</a><a class="cart" href="/cart">Cart<span>${Number(cartCount)}</span></a></div></div></div>
<nav class="nav"><div class="wrap"><a href="/" class="${active === '' ? 'on' : ''}">All products</a>${nav}</div></nav>
${body}
<div class="foot"><div class="wrap"><div><b>CoreByte Hardware</b><br>Computer components for builders and gamers.<br>Demo store: not a real shop, fake data.</div><div><b>Shop</b><br>Graphics cards<br>Processors<br>Storage</div><div><b>Help</b><br>Shipping<br>Returns<br>Warranty</div></div></div></html>`;
}

function card(p) {
  const off = p.was > p.price ? Math.round((1 - p.price / p.was) * 100) : 0;
  return `<div class="pc">${off ? `<span class="badge">-${off}%</span>` : ''}<a class="img" href="/product?id=${Number(p.id)}">${art(p.cat, 'c' + p.id)}</a><div class="bd"><span class="brand">${esc(p.brand)}</span><h3><a href="/product?id=${Number(p.id)}">${esc(p.name)}</a></h3><p class="specs">${esc(String(p.specs).split('|').slice(0, 3).join(' · '))}</p><div class="rt">${stars(p.rating)} <small>(${Number(p.reviews)})</small></div><div class="pr">${money(p.price)}${off ? `<s>${money(p.was)}</s>` : ''}</div>${stockLine(p.stock)}<form method="post" action="/cart/add"><input type="hidden" name="id" value="${Number(p.id)}"><button class="btn block" ${p.stock <= 0 ? 'disabled' : ''}>Add to cart</button></form></div></div>`;
}

function adminShell({ title, body, who, active }) {
  const items = [['', 'Dashboard'], ['orders', 'Orders'], ['products', 'Products'], ['customers', 'Customers'], ['team', 'Team']];
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} | CoreByte Admin</title><style>${CSS}</style>
<div class="adm"><aside class="as"><a class="logo" href="/admin"><i></i><span>Core<b>Byte</b></span></a>${items.map(([k, n]) => `<a href="/admin${k ? '/' + k : ''}" class="${active === k ? 'on' : ''}">${esc(n)}</a>`).join('')}<a href="/">View storefront</a><div class="who">Signed in as <b>${esc(who)}</b><br><a href="/admin/logout">Sign out</a></div></aside><main class="am">${body}</main></div></html>`;
}

function loginPage(error) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin sign in | CoreByte</title><style>${CSS}</style>
<div class="auth"><div class="l"><a class="logo" href="/"><i></i><span>Core<b>Byte</b></span></a><h1>Store administration</h1><p style="color:#c5d3e3;max-width:380px">Manage orders, inventory and customers. Authorised staff only.</p></div><div class="r"><form method="post" action="/admin/login"><h2>Sign in</h2>${error ? `<div class="err">${esc(error)}</div>` : ''}<label>Username</label><input name="username" autocomplete="username" required autofocus><label>Password</label><input name="password" type="password" autocomplete="current-password" required><p><button class="btn block">Sign in</button></p><p class="note">Demo store. Lab-only data.</p></form></div></div></html>`;
}

module.exports = { esc, money, CATS, catName, art, stars, stockLine, shell, card, adminShell, loginPage, CSS };
