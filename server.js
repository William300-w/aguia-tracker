const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
let webpush = null;
let webpushError = '';
try { webpush = require('web-push'); } catch (e) { webpushError = e.message; console.log('web-push not available:', e.message); }

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

let VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY || '';
let VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
if (webpush) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
    const vapidKeys = webpush.generateVAPIDKeys();
    VAPID_PUBLIC = vapidKeys.publicKey;
    VAPID_PRIVATE = vapidKeys.privateKey;
    console.log('VAPID keys generated. Set these as env vars for persistence:');
    console.log('VAPID_PUBLIC_KEY=' + VAPID_PUBLIC);
    console.log('VAPID_PRIVATE_KEY=' + VAPID_PRIVATE);
  }
  webpush.setVapidDetails('mailto:noreply@aguia-ads.com', VAPID_PUBLIC, VAPID_PRIVATE);
}

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

    CREATE TABLE IF NOT EXISTS notification_settings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      telegram_bot_token TEXT DEFAULT '',
      telegram_chat_id TEXT DEFAULT '',
      telegram_enabled BOOLEAN DEFAULT false,
      email_enabled BOOLEAN DEFAULT false,
      email_to TEXT DEFAULT '',
      email_api_key TEXT DEFAULT '',
      notify_on_sale BOOLEAN DEFAULT true,
      notify_on_click BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      endpoint TEXT NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, endpoint)
    );
  `);

  const emailCols = ['email_to','email_api_key'];
  for (const col of emailCols) {
    await pool.query(`ALTER TABLE notification_settings ADD COLUMN IF NOT EXISTS ${col} TEXT DEFAULT ''`).catch(() => {});
  }

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

function sendTelegram(botToken, chatId, message) {
  return new Promise((resolve) => {
    const data = JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${botToken}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => { res.resume(); resolve(); });
    req.on('error', () => resolve());
    req.write(data);
    req.end();
  });
}

function sendTelegramAudio(botToken, chatId) {
  return new Promise((resolve) => {
    const audioPath = path.join(__dirname, 'public', 'som_da_alegria.mp3');
    const audioData = fs.readFileSync(audioPath);
    const boundary = '----AguiaAds' + Date.now();
    const parts = [];
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}`);
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="audio"; filename="som_da_alegria.mp3"\r\nContent-Type: audio/mpeg\r\n\r\n`);
    const body = Buffer.concat([
      Buffer.from(parts[0] + '\r\n'),
      Buffer.from(parts[1]),
      audioData,
      Buffer.from(`\r\n--${boundary}--\r\n`)
    ]);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${botToken}/sendAudio`,
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length }
    }, (res) => { res.resume(); resolve(); });
    req.on('error', () => resolve());
    req.write(body);
    req.end();
  });
}

function sendEmail(settings, subject, html) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      from: 'Águia Ads <onboarding@resend.dev>',
      to: [settings.email_to],
      subject,
      html
    });
    const req = https.request({
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${settings.email_api_key}`,
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(body);
        else reject(new Error(body || `HTTP ${res.statusCode}`));
      });
    });
    req.on('error', (e) => reject(e));
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(data);
    req.end();
  });
}

app.get('/postback/:tagId', async (req, res) => {
  try {
    const { tagId } = req.params;
    const tag = await pool.query('SELECT t.id, t.name, t.user_id FROM tags t WHERE t.id = $1', [tagId]);
    if (tag.rows.length === 0) { res.status(404).json({ error: 'Tag não encontrada' }); return; }

    const ip = req.query.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const geo = geoip.lookup(ip) || {};
    const revenue = parseFloat(req.query.amount || req.query.revenue || '0') || 0;
    const network = req.query.network || '';
    const offer = req.query.offer || '';

    await pool.query(
      `INSERT INTO events (tag_id, type, ip, country, country_code, region, city, lat, lon, visitor_id, revenue, metadata)
       VALUES ($1, 'conversion', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [tagId, ip, geo.country || '', geo.country || '', geo.region || '', geo.city || '',
       geo.ll?.[0] || null, geo.ll?.[1] || null,
       req.query.vid || req.query.clickid || '',
       revenue,
       JSON.stringify({ offer, txid: req.query.txid || '', network })]
    );

    const userId = tag.rows[0].user_id;
    const tagName = tag.rows[0].name;
    const ns = await pool.query('SELECT * FROM notification_settings WHERE user_id = $1', [userId]);
    if (ns.rows.length > 0) {
      const settings = ns.rows[0];
      if (settings.telegram_enabled && settings.telegram_bot_token && settings.telegram_chat_id && settings.notify_on_sale) {
        const msg = `<b>Águia Ads - Venda Aprovada</b>\n${network || offer || 'Venda'} - USD ${revenue.toFixed(2)}`;
        sendTelegram(settings.telegram_bot_token, settings.telegram_chat_id, msg).catch(() => {});
      }
      sendPushToUser(userId, {
        title: '🦅 Venda Aprovada!',
        body: `${network || offer || 'Venda'} — USD ${revenue.toFixed(2)}`,
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        data: { url: '/' }
      }).catch(() => {});
      if (settings.email_enabled && settings.email_to && settings.email_api_key && settings.notify_on_sale) {
        const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#0d0d0d;color:#fff;padding:24px;border-radius:12px;border:1px solid #f5a623">
          <div style="text-align:center;margin-bottom:16px"><span style="font-size:40px">🦅</span><h2 style="color:#f5a623;margin:8px 0">VENDA DETECTADA!</h2></div>
          <table style="width:100%;font-size:14px;color:#ccc"><tr><td style="padding:6px 0">💰 <strong>Valor:</strong></td><td style="text-align:right;color:#4ade80;font-weight:700">$${revenue.toFixed(2)}</td></tr>
          <tr><td style="padding:6px 0">📋 <strong>Tag:</strong></td><td style="text-align:right">${tagName}</td></tr>
          <tr><td style="padding:6px 0">🌐 <strong>Rede:</strong></td><td style="text-align:right">${network || 'N/A'}</td></tr>
          <tr><td style="padding:6px 0">📦 <strong>Oferta:</strong></td><td style="text-align:right">${offer || 'N/A'}</td></tr>
          <tr><td style="padding:6px 0">🌍 <strong>País:</strong></td><td style="text-align:right">${geo.country || 'N/A'}</td></tr>
          <tr><td style="padding:6px 0">🏙️ <strong>Cidade:</strong></td><td style="text-align:right">${geo.city || 'N/A'}</td></tr>
          <tr><td style="padding:6px 0">⏰ <strong>Data:</strong></td><td style="text-align:right">${new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })}</td></tr></table>
          <div style="text-align:center;margin-top:16px;font-size:11px;color:#888">Águia Ads — Sistema de Rastreamento</div></div>`;
        sendEmail(settings, `🦅 Venda $${revenue.toFixed(2)} — ${tagName}`, emailHtml).catch(() => {});
      }
    }

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

// ============ NOTIFICATION SETTINGS ============

app.get('/api/notifications/settings', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notification_settings WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      await pool.query('INSERT INTO notification_settings (user_id) VALUES ($1)', [req.user.id]);
      const fresh = await pool.query('SELECT * FROM notification_settings WHERE user_id = $1', [req.user.id]);
      res.json(fresh.rows[0]);
    } else {
      res.json(result.rows[0]);
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/notifications/settings', auth, async (req, res) => {
  try {
    const { telegram_bot_token, telegram_chat_id, telegram_enabled, email_enabled, email_to, email_api_key, notify_on_sale, notify_on_click } = req.body;
    const exists = await pool.query('SELECT id FROM notification_settings WHERE user_id = $1', [req.user.id]);
    if (exists.rows.length === 0) {
      await pool.query('INSERT INTO notification_settings (user_id, telegram_bot_token, telegram_chat_id, telegram_enabled, email_enabled, email_to, email_api_key, notify_on_sale, notify_on_click) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [req.user.id, telegram_bot_token || '', telegram_chat_id || '', telegram_enabled || false, email_enabled || false, email_to || '', email_api_key || '', notify_on_sale !== false, notify_on_click || false]);
    } else {
      await pool.query('UPDATE notification_settings SET telegram_bot_token=$1, telegram_chat_id=$2, telegram_enabled=$3, email_enabled=$4, email_to=$5, email_api_key=$6, notify_on_sale=$7, notify_on_click=$8 WHERE user_id=$9',
        [telegram_bot_token || '', telegram_chat_id || '', telegram_enabled || false, email_enabled || false, email_to || '', email_api_key || '', notify_on_sale !== false, notify_on_click || false, req.user.id]);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/test-telegram', auth, async (req, res) => {
  try {
    const { telegram_bot_token, telegram_chat_id } = req.body;
    if (!telegram_bot_token || !telegram_chat_id) return res.status(400).json({ error: 'Token e Chat ID obrigatórios' });
    const msg = '<b>Águia Ads - Teste</b>\nNotificações configuradas com sucesso! ✅';
    await sendTelegram(telegram_bot_token, telegram_chat_id, msg);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/test-email', auth, async (req, res) => {
  try {
    const { email_to, email_api_key } = req.body;
    if (!email_to || !email_api_key) return res.status(400).json({ error: 'Preencha o email e a API Key do Resend' });
    const html = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#0d0d0d;color:#fff;padding:24px;border-radius:12px;border:1px solid #f5a623">
      <div style="text-align:center;margin-bottom:16px"><span style="font-size:40px">🦅</span><h2 style="color:#f5a623;margin:8px 0">Teste Águia Ads</h2></div>
      <p style="text-align:center;font-size:14px;color:#ccc">✅ Notificações por email configuradas com sucesso!<br>Você receberá alertas de vendas neste email.</p>
      <div style="text-align:center;margin-top:16px;font-size:11px;color:#888">Águia Ads — Sistema de Rastreamento</div></div>`;
    await sendEmail({ email_to, email_api_key }, '🦅 Teste Águia Ads — Email Configurado!', html);
    res.json({ ok: true });
  } catch (e) {
    console.error('Email test error:', e.message);
    res.status(500).json({ error: e.message || 'Erro ao enviar email' });
  }
});

// ============ TRACKING SCRIPT GENERATOR ============

// ============ PUSH NOTIFICATIONS ============

app.get('/api/push/vapid-key', auth, (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC, webpushLoaded: !!webpush, error: webpushError || undefined });
});

app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Subscription inválida' });
    await pool.query(
      `INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh = $3, auth = $4`,
      [req.user.id, endpoint, keys.p256dh, keys.auth]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

async function sendPushToUser(userId, payload) {
  if (!webpush) return;
  try {
    const subs = await pool.query('SELECT * FROM push_subscriptions WHERE user_id = $1', [userId]);
    for (const sub of subs.rows) {
      const pushSub = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
      try {
        await webpush.sendNotification(pushSub, JSON.stringify(payload));
      } catch (err) {
        if (err.statusCode === 410 || err.statusCode === 404) {
          await pool.query('DELETE FROM push_subscriptions WHERE id = $1', [sub.id]);
        }
      }
    }
  } catch (e) { console.error('Push error:', e.message); }
}

app.get('/api/script/:tagId', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const script = `<!-- Águia Ads - Tag: ${req.params.tagId} -->
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

app.get('/manifest.json', (req, res) => {
  res.json({
    name: 'Águia Ads',
    short_name: 'Águia',
    description: 'Sistema de rastreamento profissional para afiliados',
    start_url: '/',
    display: 'standalone',
    background_color: '#0d0d0d',
    theme_color: '#f5a623',
    orientation: 'portrait-primary',
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'maskable' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
    ]
  });
});

app.get('/sw.js', (req, res) => {
  res.set('Content-Type', 'application/javascript');
  res.send(`
const CACHE_NAME = 'aguia-v1';
const OFFLINE_URLS = ['/', '/eagle.webp'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(OFFLINE_URLS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(r => {
      if (r.ok) {
        const clone = r.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
      }
      return r;
    }).catch(() => caches.match(e.request))
  );
});

self.addEventListener('push', e => {
  if (!e.data) return;
  const d = e.data.json();
  e.waitUntil(
    self.registration.showNotification(d.title || 'Águia Ads', {
      body: d.body || '',
      icon: d.icon || '/icon-192.png',
      badge: d.badge || '/icon-192.png',
      data: d.data || {}
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.notification.data?.url || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) { if (c.url.includes(url) && 'focus' in c) return c.focus(); }
      return clients.openWindow(url);
    })
  );
});
  `);
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
    console.log(`Águia Ads rodando em http://localhost:${PORT}`);
    console.log(`Dashboard: http://localhost:${PORT}`);
    console.log(`Tracking endpoint: http://localhost:${PORT}/t/{tagId}`);
    console.log(`Postback endpoint: http://localhost:${PORT}/postback/{tagId}`);
  });
}).catch(err => {
  console.error('Erro ao inicializar banco:', err);
  process.exit(1);
});
