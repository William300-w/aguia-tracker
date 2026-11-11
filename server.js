const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'aguia.db');

// Ensure data directory exists
const fs = require('fs');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Database setup
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT DEFAULT 'Usuário Águia',
    plan TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    project_id INTEGER,
    name TEXT NOT NULL,
    funnel TEXT DEFAULT 'Presell → Oferta',
    network TEXT DEFAULT 'Google Ads',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag_id TEXT NOT NULL,
    type TEXT NOT NULL,
    ip TEXT,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    device TEXT,
    browser TEXT,
    os TEXT,
    referer TEXT,
    url TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,
    utm_content TEXT,
    utm_term TEXT,
    visitor_id TEXT,
    session_id TEXT,
    revenue REAL DEFAULT 0,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tag_id) REFERENCES tags(id)
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    network TEXT DEFAULT '',
    payout REAL DEFAULT 0,
    url TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_events_tag ON events(tag_id);
  CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
  CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
  CREATE INDEX IF NOT EXISTS idx_events_visitor ON events(visitor_id);
  CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code);
  CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_id);
`);

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const token = req.cookies.aguia_token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ============ AUTH ROUTES ============

app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email já cadastrado' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)').run(email, hash, name || 'Usuário Águia');
  const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('aguia_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ ok: true, token });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenciais inválidas' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('aguia_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ ok: true, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('aguia_token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, plan, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ============ TRACKING ENDPOINT (public, no auth) ============

app.get('/t/:tagId', (req, res) => {
  const { tagId } = req.params;
  const tag = db.prepare('SELECT id FROM tags WHERE id = ?').get(tagId);
  if (!tag) { res.status(204).end(); return; }

  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const geo = geoip.lookup(ip) || {};
  const ua = new UAParser(req.headers['user-agent']);
  const device = ua.getDevice();
  const browser = ua.getBrowser();
  const os = ua.getOS();

  db.prepare(`INSERT INTO events (tag_id, type, ip, country, country_code, region, city, lat, lon, device, browser, os, referer, url, utm_source, utm_medium, utm_campaign, utm_content, utm_term, visitor_id, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    tagId, req.query.e || 'pageview', ip,
    geo.country || '', geo.country || '', geo.region || '', geo.city || '',
    geo.ll?.[0] || null, geo.ll?.[1] || null,
    [device.vendor, device.model, device.type].filter(Boolean).join(' ') || 'Desktop',
    [browser.name, browser.version].filter(Boolean).join(' '),
    [os.name, os.version].filter(Boolean).join(' '),
    req.query.ref || req.headers.referer || '',
    req.query.url || '',
    req.query.utm_source || '', req.query.utm_medium || '', req.query.utm_campaign || '',
    req.query.utm_content || '', req.query.utm_term || '',
    req.query.vid || '', req.query.sid || ''
  );

  // Return 1x1 transparent pixel
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
  res.send(pixel);
});

// Postback endpoint for conversions (BuyGoods, MaxWeb, etc.)
app.get('/postback/:tagId', (req, res) => {
  const { tagId } = req.params;
  const tag = db.prepare('SELECT id FROM tags WHERE id = ?').get(tagId);
  if (!tag) { res.status(404).json({ error: 'Tag não encontrada' }); return; }

  const ip = req.query.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const geo = geoip.lookup(ip) || {};

  db.prepare(`INSERT INTO events (tag_id, type, ip, country, country_code, region, city, lat, lon, visitor_id, revenue, metadata)
    VALUES (?, 'conversion', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    tagId, ip,
    geo.country || '', geo.country || '', geo.region || '', geo.city || '',
    geo.ll?.[0] || null, geo.ll?.[1] || null,
    req.query.vid || req.query.clickid || '',
    parseFloat(req.query.amount || req.query.revenue || '0') || 0,
    JSON.stringify({ offer: req.query.offer || '', txid: req.query.txid || '', network: req.query.network || '' })
  );

  res.json({ ok: true });
});

// ============ TAG ROUTES ============

app.get('/api/tags', auth, (req, res) => {
  const tags = db.prepare('SELECT * FROM tags WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  const enriched = tags.map(tag => {
    const stats = db.prepare(`SELECT
      COUNT(*) as total_events,
      SUM(CASE WHEN type = 'pageview' THEN 1 ELSE 0 END) as visits,
      SUM(CASE WHEN type = 'click' THEN 1 ELSE 0 END) as clicks,
      SUM(CASE WHEN type = 'conversion' THEN 1 ELSE 0 END) as conversions,
      SUM(revenue) as revenue
    FROM events WHERE tag_id = ?`).get(tag.id);
    return { ...tag, ...stats };
  });
  res.json(enriched);
});

app.post('/api/tags', auth, (req, res) => {
  const { name, funnel, network, project_id } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
  const id = 'ag_' + crypto.randomBytes(8).toString('hex');
  db.prepare('INSERT INTO tags (id, user_id, project_id, name, funnel, network) VALUES (?, ?, ?, ?, ?, ?)').run(
    id, req.user.id, project_id || null, name, funnel || 'Presell → Oferta', network || 'Google Ads'
  );
  res.json({ ok: true, id, name });
});

app.put('/api/tags/:id', auth, (req, res) => {
  const { name, funnel, network, status } = req.body;
  db.prepare('UPDATE tags SET name = COALESCE(?, name), funnel = COALESCE(?, funnel), network = COALESCE(?, network), status = COALESCE(?, status) WHERE id = ? AND user_id = ?')
    .run(name, funnel, network, status, req.params.id, req.user.id);
  res.json({ ok: true });
});

app.delete('/api/tags/:id', auth, (req, res) => {
  db.prepare('DELETE FROM events WHERE tag_id = ?').run(req.params.id);
  db.prepare('DELETE FROM tags WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ============ DASHBOARD DATA ============

app.get('/api/dashboard', auth, (req, res) => {
  const { period, tag_id } = req.query;
  let dateFilter = "datetime('now', '-1 day')";
  if (period === '7d') dateFilter = "datetime('now', '-7 days')";
  if (period === '30d') dateFilter = "datetime('now', '-30 days')";
  if (period === '90d') dateFilter = "datetime('now', '-90 days')";
  if (period === 'today') dateFilter = "datetime('now', 'start of day')";

  const tagFilter = tag_id ? 'AND e.tag_id = ?' : '';
  const tagParam = tag_id ? [tag_id] : [];

  const userTags = db.prepare('SELECT id FROM tags WHERE user_id = ?').all(req.user.id).map(t => t.id);
  if (userTags.length === 0) {
    return res.json({ visits: 0, clicks: 0, conversions: 0, revenue: 0, flee_rate: 0, countries: [], hourly: [], devices: [], recent: [] });
  }
  const placeholders = userTags.map(() => '?').join(',');

  const kpi = db.prepare(`SELECT
    SUM(CASE WHEN type = 'pageview' THEN 1 ELSE 0 END) as visits,
    SUM(CASE WHEN type = 'click' THEN 1 ELSE 0 END) as clicks,
    SUM(CASE WHEN type = 'conversion' THEN 1 ELSE 0 END) as conversions,
    SUM(revenue) as revenue,
    COUNT(DISTINCT visitor_id) as unique_visitors
  FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateFilter} ${tagFilter}`).get(...userTags, ...tagParam);

  const fleeRate = kpi.visits > 0 ? Math.round(((kpi.visits - kpi.clicks) / kpi.visits) * 100) : 0;

  const countries = db.prepare(`SELECT country_code as code, country as name, city,
    COUNT(*) as events, SUM(CASE WHEN type='conversion' THEN 1 ELSE 0 END) as conversions, SUM(revenue) as revenue
    FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateFilter} ${tagFilter}
    AND country_code != '' GROUP BY country_code, city ORDER BY events DESC LIMIT 20`).all(...userTags, ...tagParam);

  const hourly = db.prepare(`SELECT strftime('%H', created_at) as hour,
    SUM(CASE WHEN type='pageview' THEN 1 ELSE 0 END) as visits,
    SUM(CASE WHEN type='click' THEN 1 ELSE 0 END) as clicks,
    SUM(CASE WHEN type='conversion' THEN 1 ELSE 0 END) as conversions,
    SUM(revenue) as revenue
    FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateFilter} ${tagFilter}
    GROUP BY hour ORDER BY hour`).all(...userTags, ...tagParam);

  const devices = db.prepare(`SELECT device, COUNT(*) as total
    FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateFilter} ${tagFilter}
    GROUP BY device ORDER BY total DESC LIMIT 10`).all(...userTags, ...tagParam);

  const recent = db.prepare(`SELECT e.*, t.name as tag_name FROM events e
    JOIN tags t ON t.id = e.tag_id
    WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateFilter} ${tagFilter}
    ORDER BY e.created_at DESC LIMIT 50`).all(...userTags, ...tagParam);

  res.json({
    visits: kpi.visits || 0,
    clicks: kpi.clicks || 0,
    conversions: kpi.conversions || 0,
    revenue: kpi.revenue || 0,
    unique_visitors: kpi.unique_visitors || 0,
    flee_rate: fleeRate,
    countries,
    hourly,
    devices,
    recent
  });
});

// Events stream for real-time
app.get('/api/events/live', auth, (req, res) => {
  const userTags = db.prepare('SELECT id FROM tags WHERE user_id = ?').all(req.user.id).map(t => t.id);
  if (userTags.length === 0) return res.json([]);
  const placeholders = userTags.map(() => '?').join(',');
  const events = db.prepare(`SELECT e.*, t.name as tag_name FROM events e
    JOIN tags t ON t.id = e.tag_id
    WHERE e.tag_id IN (${placeholders}) ORDER BY e.created_at DESC LIMIT 20`).all(...userTags);
  res.json(events);
});

// ============ PROJECT ROUTES ============

app.get('/api/projects', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id));
});

app.post('/api/projects', auth, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
  const result = db.prepare('INSERT INTO projects (user_id, name, description) VALUES (?, ?, ?)').run(req.user.id, name, description || '');
  res.json({ ok: true, id: result.lastInsertRowid });
});

// ============ PRODUCTS ============

app.get('/api/products', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id));
});

app.post('/api/products', auth, (req, res) => {
  const { name, network, payout, url } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
  const result = db.prepare('INSERT INTO products (user_id, name, network, payout, url) VALUES (?, ?, ?, ?, ?)').run(req.user.id, name, network || '', payout || 0, url || '');
  res.json({ ok: true, id: result.lastInsertRowid });
});

// ============ TRACKING SCRIPT GENERATOR ============

app.get('/api/script/:tagId', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const script = `<!-- Águia Tracker - Tag: ${req.params.tagId} -->
<script>
(function(){
  var ag_id="${req.params.tagId}";
  var ag_url="${baseUrl}/t/"+ag_id;
  var vid=localStorage.getItem("ag_vid")||"v_"+Math.random().toString(36).substr(2,12);
  localStorage.setItem("ag_vid",vid);
  var sid="s_"+Math.random().toString(36).substr(2,8);
  var params=new URLSearchParams(window.location.search);
  function send(e,extra){
    var u=ag_url+"?e="+e+"&vid="+vid+"&sid="+sid+"&url="+encodeURIComponent(location.href)+"&ref="+encodeURIComponent(document.referrer);
    ["utm_source","utm_medium","utm_campaign","utm_content","utm_term"].forEach(function(k){
      var v=params.get(k);if(v)u+="&"+k+"="+encodeURIComponent(v);
    });
    if(extra)u+="&"+extra;
    new Image().src=u;
  }
  send("pageview");
  document.addEventListener("click",function(ev){
    var a=ev.target.closest("a");
    if(a&&a.href)send("click","target="+encodeURIComponent(a.href));
  });
  window.aguia={track:function(e,data){var x="";if(data)Object.keys(data).forEach(function(k){x+="&"+k+"="+encodeURIComponent(data[k])});send(e,x)}};
})();
</script>`;
  res.set('Content-Type', 'text/plain');
  res.send(script);
});

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Catch-all for SPA
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/') && !req.path.startsWith('/t/') && !req.path.startsWith('/postback/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.listen(PORT, () => {
  console.log(`🦅 Águia Tracker rodando em http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`📡 Tracking endpoint: http://localhost:${PORT}/t/{tagId}`);
  console.log(`💰 Postback endpoint: http://localhost:${PORT}/postback/{tagId}`);
});
