// Rekuperācijas kalkulators — server without dependencies (Node.js 16+)
// Start:  ADMIN_PASSWORD=secret node server.js      (PORT defaults to 3000)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD || '';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'catalog.json');
const SEED_FILE = path.join(DATA_DIR, 'catalog.seed.json');
const MAX_BODY = 5 * 1024 * 1024;

if (!PASSWORD) console.warn('\n!!! ADMIN_PASSWORD is not set — admin saving is disabled. Start with: ADMIN_PASSWORD=yourpassword node server.js\n');
fs.mkdirSync(DATA_DIR, { recursive: true });
// first start: take the initial catalogue from catalog.seed.json (not in git)
if (!fs.existsSync(DATA_FILE) && fs.existsSync(SEED_FILE)) { fs.copyFileSync(SEED_FILE, DATA_FILE); console.log('Catalogue initialised from catalog.seed.json'); }

// What clients get: final prices only (price-list price × mark-up/discount), no mark-ups, no list prices.
function publicView(d) {
  const s = d.settings || {}, settings = {};
  for (const k of Object.keys(s)) if (!k.startsWith('adj_')) settings[k] = s[k];
  const items = (d.items || []).map(i => {
    const adj = Number(s['adj_' + i.type]) || 0;
    return { ...i, price: Math.round(Number(i.price) * (1 + adj / 100) * 100) / 100 };
  });
  return { settings, items };
}
function readData() { return fs.existsSync(DATA_FILE) ? JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) : null; }
function bearer(req) { return (req.headers.authorization || '').replace(/^Bearer\s+/i, ''); }

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function checkPassword(given) {
  if (!PASSWORD || typeof given !== 'string') return false;
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}
// simple brute-force protection
const fails = new Map();
function blocked(ip) { const f = fails.get(ip); return f && f.n >= 10 && Date.now() - f.t < 15 * 60 * 1000; }
function fail(ip) { const f = fails.get(ip) || { n: 0, t: 0 }; f.n++; f.t = Date.now(); fails.set(ip, f); }

const TYPES = ['recuperator', 'collector', 'plenum', 'diffuser', 'flex_pipe', 'rigid_pipe', 'elbow', 'grille', 'cap', 'ring', 'silencer', 'accessory'];
function validate(d) {
  if (!d || typeof d !== 'object' || !Array.isArray(d.items) || typeof d.settings !== 'object') throw new Error('bad format');
  const n = v => { const x = Number(v); return Number.isFinite(x) ? x : 0; };
  const settings = {}; for (const k of Object.keys(d.settings)) settings[k] = n(d.settings[k]);
  const items = d.items.filter(i => i && TYPES.includes(i.type)).map(i => ({
    id: String(i.id || crypto.randomBytes(5).toString('hex')).slice(0, 40), type: i.type,
    sku: String(i.sku ?? '').slice(0, 100), name: String(i.name ?? '').slice(0, 300),
    group: String(i.group ?? '').slice(0, 60), dims: String(i.dims ?? '').slice(0, 60), diameter: n(i.diameter), inlet: n(i.inlet), airflow: n(i.airflow), outlets: Math.round(n(i.outlets)), length: n(i.length),
    kind: ['supply', 'extract', 'any'].includes(i.kind) ? i.kind : 'any', price: n(i.price)
  }));
  return { settings, items, updated: new Date().toISOString() };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const ip = req.socket.remoteAddress;
  try {
    if (url.pathname === '/api/data' && req.method === 'GET') {
      const d = readData();
      return send(res, 200, d ? publicView(d) : null);
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (blocked(ip)) return send(res, 429, { error: 'too many attempts' });
      const body = JSON.parse(await readBody(req) || '{}');
      if (checkPassword(body.password)) { fails.delete(ip); return send(res, 200, { ok: true }); }
      fail(ip); return send(res, 401, { error: 'wrong password' });
    }
    if (url.pathname === '/api/admin/data' && req.method === 'GET') {
      if (blocked(ip)) return send(res, 429, { error: 'too many attempts' });
      if (!checkPassword(bearer(req))) { fail(ip); return send(res, 401, { error: 'wrong password' }); }
      return send(res, 200, readData());
    }
    if (url.pathname === '/api/admin/data' && req.method === 'PUT') {
      if (blocked(ip)) return send(res, 429, { error: 'too many attempts' });
      if (!checkPassword(bearer(req))) { fail(ip); return send(res, 401, { error: 'wrong password' }); }
      const data = validate(JSON.parse(await readBody(req)));
      if (fs.existsSync(DATA_FILE)) fs.copyFileSync(DATA_FILE, path.join(DATA_DIR, 'catalog.prev.json'));
      const tmp = DATA_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(data, null, 1)); fs.renameSync(tmp, DATA_FILE);
      return send(res, 200, { ok: true });
    }
    if (url.pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });
    // static files
    let p = decodeURIComponent(url.pathname); if (p === '/' || p === '') p = '/index.html';
    const file = path.normalize(path.join(PUBLIC_DIR, p));
    if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found', 'text/plain');
    send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] || 'application/octet-stream');
  } catch (e) {
    send(res, 400, { error: String(e.message || e) });
  }
});
server.listen(PORT, () => console.log(`Rekuperācijas kalkulators: http://localhost:${PORT}  (admin: http://localhost:${PORT}/#admin)`));
