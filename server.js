const express = require('express');
const { Pool } = require('pg');
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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT DEFAULT 'Usuário Águia',
      plan TEXT DEFAULT 'free',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      active INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tags (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      project_id INTEGER REFERENCES projects(id),
      name TEXT NOT NULL,
      funnel TEXT DEFAULT 'Presell → Oferta',
      network TEXT DEFAULT 'Google Ads',
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      tag_id TEXT NOT NULL REFERENCES tags(id),
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
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      network TEXT DEFAULT '',
      payout REAL DEFAULT 0,
      url TEXT DEFAULT '',
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_tag ON events(tag_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_visitor ON events(visitor_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_id)`);
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Email já cadastrado' });
    const hash = bcrypt.hashSync(password, 10);
    const result = await pool.query('INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id', [email, hash, name || 'Usuário Águia']);
    const token = jwt.sign({ id: result.rows[0].id, email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('aguia_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ ok: true, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenciais inválidas' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('aguia_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ ok: true, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('aguia_token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, plan, created_at FROM users WHERE id = $1', [req.user.id]);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ TRACKING ENDPOINT ============

app.get('/t/:tagId', async (req, res) => {
  try {
    const { tagId } = req.params;
    const tag = await pool.query('SELECT id FROM tags WHERE id = $1', [tagId]);
    if (tag.rows.length === 0) { res.status(204).end(); return; }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const geo = geoip.lookup(ip) || {};
    const ua = new UAParser(req.headers['user-agent']);
    const device = ua.getDevice();
    const browser = ua.getBrowser();
    const os = ua.getOS();

    await pool.query(
      `INSERT INTO events (tag_id, type, ip, country, country_code, region, city, lat, lon, device, browser, os, referer, url, utm_source, utm_medium, utm_campaign, utm_content, utm_term, visitor_id, session_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
      [tagId, req.query.e || 'pageview', ip,
       geo.country || '', geo.country || '', geo.region || '', geo.city || '',
       geo.ll?.[0] || null, geo.ll?.[1] || null,
       [device.vendor, device.model, device.type].filter(Boolean).join(' ') || 'Desktop',
       [browser.name, browser.version].filter(Boolean).join(' '),
       [os.name, os.version].filter(Boolean).join(' '),
       req.query.ref || req.headers.referer || '', req.query.url || '',
       req.query.utm_source || '', req.query.utm_medium || '', req.query.utm_campaign || '',
       req.query.utm_content || '', req.query.utm_term || '',
       req.query.vid || '', req.query.sid || '']
    );

    const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    res.set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
    res.send(pixel);
  } catch (e) { res.status(204).end(); }
});

app.get('/postback/:tagId', async (req, res) => {
  try {
    const { tagId } = req.params;
    const tag = await pool.query('SELECT id FROM tags WHERE id = $1', [tagId]);
    if (tag.rows.length === 0) { res.status(404).json({ error: 'Tag não encontrada' }); return; }

    const ip = req.query.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const geo = geoip.lookup(ip) || {};

    await pool.query(
      `INSERT INTO events (tag_id, type, ip, country, country_code, region, city, lat, lon, visitor_id, revenue, metadata)
       VALUES ($1, 'conversion', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [tagId, ip, geo.country || '', geo.country || '', geo.region || '', geo.city || '',
       geo.ll?.[0] || null, geo.ll?.[1] || null,
       req.query.vid || req.query.clickid || '',
       parseFloat(req.query.amount || req.query.revenue || '0') || 0,
       JSON.stringify({ offer: req.query.offer || '', txid: req.query.txid || '', network: req.query.network || '' })]
    );

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ TAG ROUTES ============

app.get('/api/tags', auth, async (req, res) => {
  try {
    const tags = await pool.query('SELECT * FROM tags WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    const enriched = [];
    for (const tag of tags.rows) {
      const stats = await pool.query(`SELECT
        COUNT(*) as total_events,
        SUM(CASE WHEN type = 'pageview' THEN 1 ELSE 0 END) as visits,
        SUM(CASE WHEN type = 'click' THEN 1 ELSE 0 END) as clicks,
        SUM(CASE WHEN type = 'conversion' THEN 1 ELSE 0 END) as conversions,
        SUM(revenue) as revenue
      FROM events WHERE tag_id = $1`, [tag.id]);
      const s = stats.rows[0];
      enriched.push({ ...tag, total_events: +s.total_events, visits: +s.visits, clicks: +s.clicks, conversions: +s.conversions, revenue: +s.revenue });
    }
    res.json(enriched);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tags', auth, async (req, res) => {
  try {
    const { name, funnel, network, project_id } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
    const id = 'ag_' + crypto.randomBytes(8).toString('hex');
    await pool.query('INSERT INTO tags (id, user_id, project_id, name, funnel, network) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, req.user.id, project_id || null, name, funnel || 'Presell → Oferta', network || 'Google Ads']);
    res.json({ ok: true, id, name });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/tags/:id', auth, async (req, res) => {
  try {
    const { name, funnel, network, status } = req.body;
    await pool.query('UPDATE tags SET name = COALESCE($1, name), funnel = COALESCE($2, funnel), network = COALESCE($3, network), status = COALESCE($4, status) WHERE id = $5 AND user_id = $6',
      [name, funnel, network, status, req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tags/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM events WHERE tag_id = $1', [req.params.id]);
    await pool.query('DELETE FROM tags WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ DASHBOARD DATA ============

app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const { period, tag_id } = req.query;
    let interval = '1 day';
    if (period === '7d') interval = '7 days';
    if (period === '30d') interval = '30 days';
    if (period === '90d') interval = '90 days';
    if (period === 'today') interval = '0 days';

    const dateExpr = period === 'today' ? "DATE_TRUNC('day', NOW())" : `NOW() - INTERVAL '${interval}'`;

    const tagsResult = await pool.query('SELECT id FROM tags WHERE user_id = $1', [req.user.id]);
    const userTags = tagsResult.rows.map(t => t.id);
    if (userTags.length === 0) {
      return res.json({ visits: 0, clicks: 0, conversions: 0, revenue: 0, flee_rate: 0, countries: [], hourly: [], devices: [], recent: [] });
    }

    const placeholders = userTags.map((_, i) => `$${i + 1}`).join(',');
    const tagFilterIdx = userTags.length + 1;
    const tagFilter = tag_id ? `AND e.tag_id = $${tagFilterIdx}` : '';
    const params = tag_id ? [...userTags, tag_id] : [...userTags];

    const kpi = await pool.query(`SELECT
      SUM(CASE WHEN type = 'pageview' THEN 1 ELSE 0 END) as visits,
      SUM(CASE WHEN type = 'click' THEN 1 ELSE 0 END) as clicks,
      SUM(CASE WHEN type = 'conversion' THEN 1 ELSE 0 END) as conversions,
      SUM(revenue) as revenue,
      COUNT(DISTINCT visitor_id) as unique_visitors
    FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateExpr} ${tagFilter}`, params);
    const k = kpi.rows[0];

    const fleeRate = +k.visits > 0 ? Math.round(((+k.visits - +k.clicks) / +k.visits) * 100) : 0;

    const countries = await pool.query(`SELECT country_code as code, country as name, city,
      COUNT(*) as events, SUM(CASE WHEN type='conversion' THEN 1 ELSE 0 END) as conversions, SUM(revenue) as revenue
      FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateExpr} ${tagFilter}
      AND country_code != '' GROUP BY country_code, country, city ORDER BY events DESC LIMIT 20`, params);

    const hourly = await pool.query(`SELECT TO_CHAR(created_at, 'HH24') as hour,
      SUM(CASE WHEN type='pageview' THEN 1 ELSE 0 END) as visits,
      SUM(CASE WHEN type='click' THEN 1 ELSE 0 END) as clicks,
      SUM(CASE WHEN type='conversion' THEN 1 ELSE 0 END) as conversions,
      SUM(revenue) as revenue
      FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateExpr} ${tagFilter}
      GROUP BY hour ORDER BY hour`, params);

    const devices = await pool.query(`SELECT device, COUNT(*) as total
      FROM events e WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateExpr} ${tagFilter}
      GROUP BY device ORDER BY total DESC LIMIT 10`, params);

    const recent = await pool.query(`SELECT e.*, t.name as tag_name FROM events e
      JOIN tags t ON t.id = e.tag_id
      WHERE e.tag_id IN (${placeholders}) AND e.created_at >= ${dateExpr} ${tagFilter}
      ORDER BY e.created_at DESC LIMIT 50`, params);

    res.json({
      visits: +k.visits || 0,
      clicks: +k.clicks || 0,
      conversions: +k.conversions || 0,
      revenue: +k.revenue || 0,
      unique_visitors: +k.unique_visitors || 0,
      flee_rate: fleeRate,
      countries: countries.rows,
      hourly: hourly.rows,
      devices: devices.rows,
      recent: recent.rows
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/events/live', auth, async (req, res) => {
  try {
    const tagsResult = await pool.query('SELECT id FROM tags WHERE user_id = $1', [req.user.id]);
    const userTags = tagsResult.rows.map(t => t.id);
    if (userTags.length === 0) return res.json([]);
    const placeholders = userTags.map((_, i) => `$${i + 1}`).join(',');
    const events = await pool.query(`SELECT e.*, t.name as tag_name FROM events e
      JOIN tags t ON t.id = e.tag_id
      WHERE e.tag_id IN (${placeholders}) ORDER BY e.created_at DESC LIMIT 20`, userTags);
    res.json(events.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ PROJECT ROUTES ============

app.get('/api/projects', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects', auth, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
    const result = await pool.query('INSERT INTO projects (user_id, name, description) VALUES ($1, $2, $3) RETURNING id', [req.user.id, name, description || '']);
    res.json({ ok: true, id: result.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ PRODUCTS ============

app.get('/api/products', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    const { name, network, payout, url } = req.body;
    if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
    const result = await pool.query('INSERT INTO products (user_id, name, network, payout, url) VALUES ($1, $2, $3, $4, $5) RETURNING id', [req.user.id, name, network || '', payout || 0, url || '']);
    res.json({ ok: true, id: result.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/') && !req.path.startsWith('/t/') && !req.path.startsWith('/postback/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Águia Tracker rodando em http://localhost:${PORT}`);
    console.log(`Dashboard: http://localhost:${PORT}`);
    console.log(`Tracking endpoint: http://localhost:${PORT}/t/{tagId}`);
    console.log(`Postback endpoint: http://localhost:${PORT}/postback/{tagId}`);
  });
}).catch(err => {
  console.error('Erro ao inicializar banco:', err);
  process.exit(1);
});
