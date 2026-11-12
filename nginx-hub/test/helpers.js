'use strict';
/** Utilitaires de test : application en mémoire, client HTTP avec cookies/CSRF, faux dashboard. */
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp } = require('../lib/app');
const { loadConfig, deepMerge } = require('../lib/config');
const { generateKey } = require('../lib/crypto');
const { createUsers } = require('../features/auth/users');
const { generateSecret, totpAt } = require('../lib/totp');

const KEY = Buffer.from(generateKey(), 'base64');
const SILENT = { debug() {}, info() {}, warn() {}, error() {} };

let pgSeq = 0;
/** Mode HUB_TEST_PG=1 : mêmes tests sur un vrai PostgreSQL (une base éphémère par application). Paquet « pg » via NODE_PATH. */
async function pgEphemeral() {
  const pg = require('pg');
  const admin = new pg.Client({ host: process.env.HUB_TEST_PG_HOST || '127.0.0.1', port: Number(process.env.HUB_TEST_PG_PORT || 5432), user: process.env.HUB_TEST_PG_USER || 'postgres', database: 'postgres', password: process.env.HUB_DB_PASSWORD });
  await admin.connect();
  const name = `hubtest_${process.pid}_${++pgSeq}`;
  await admin.query(`CREATE DATABASE ${name}`);
  return { name, drop: async () => { await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`); await admin.end(); } };
}

async function makeApp(overrides = {}, opts = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hub-test-')); // répertoire isolé par application (archives, etc.)
  let pgDb = null;
  if (process.env.HUB_TEST_PG) {
    pgDb = await pgEphemeral();
    overrides = deepMerge({ storage: { driver: 'postgres', postgres: { host: process.env.HUB_TEST_PG_HOST || '127.0.0.1', port: Number(process.env.HUB_TEST_PG_PORT || 5432), database: pgDb.name, user: process.env.HUB_TEST_PG_USER || 'postgres', pool_max: 4 } } }, overrides);
  }
  const config = loadConfig({
    file: '/nonexistent.yml',
    overrides: deepMerge({
      server: { port: 0, host: '127.0.0.1', cookie_secure: false, data_dir: dataDir },
      collector: { enabled: false, timeout_ms: 1500 },
      security: { allow_insecure_http: true, allow_private_networks: true, mfa_policy: 'optional', bootstrap_admin: false },
    }, overrides),
  });
  const app = await createApp({ config, key: KEY, log: SILENT, dbFile: pgDb ? undefined : ':memory:', banner: opts.banner || (() => {}) });
  { const stop0 = app.stop.bind(app); app.stop = async () => { await stop0(); fs.rmSync(dataDir, { recursive: true, force: true }); }; }
  if (pgDb) { const stop = app.stop.bind(app); app.stop = async () => { await stop(); await pgDb.drop(); }; }
  const addr = await app.start();
  const users = createUsers(app.ctx.db, KEY);
  return { app, users, base: `http://127.0.0.1:${addr.port}`, config };
}

/** Client HTTP minimal avec jar de cookies et en-tête CSRF automatique. */
function client(base) {
  const st = { cookie: '', csrf: '' };
  async function call(method, path, body, extra = {}) {
    const headers = { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...extra };
    if (st.cookie) headers.Cookie = st.cookie;
    if (st.csrf && !headers['X-CSRF-Token'] && method !== 'GET') headers['X-CSRF-Token'] = st.csrf;
    const res = await fetch(base + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
    const sc = res.headers.getSetCookie?.() || [];
    for (const c of sc) { const [kv] = c.split(';'); if (kv.startsWith('hub_sid=')) st.cookie = /=$/.test(kv) ? '' : kv; }
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* non JSON */ }
    if (json && json.csrf) st.csrf = json.csrf;
    return { status: res.status, json, headers: res.headers, text };
  }
  return { call, get: (p, h) => call('GET', p, undefined, h), post: (p, b, h) => call('POST', p, b ?? {}, h), patch: (p, b) => call('PATCH', p, b), del: (p) => call('DELETE', p), st };
}

async function login(base, username, password) {
  const c = client(base);
  const r = await c.post('/api/hub/v1/auth/login', { username, password });
  return { c, r };
}

/** Faux dashboard : renvoie un résumé valide si le token est bon. */
function fakeDashboard({ token, summary, status = 200, headers = {}, delayMs = 0 } = {}) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push({ url: req.url, token: req.headers['x-hub-token'] });
    const send = () => {
      if (req.url === '/redir') { res.writeHead(302, { Location: 'http://127.0.0.1:1/' }); return res.end(); }
      if (req.url !== '/api/hub/v1/summary') { res.writeHead(404); return res.end(); }
      if (req.headers['x-hub-token'] !== token) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end('{}'); }
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(typeof summary === 'string' ? summary : JSON.stringify(summary));
    };
    delayMs ? setTimeout(send, delayMs) : send();
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({
    srv, hits, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); }),
  })));
}

const GOOD_SUMMARY = {
  schema: 1,
  generated_at: new Date().toISOString(),
  instance: { id: 'srv-1', name: 'Paris', version: '12.74.0', hostname: 'ngx1' },
  nginx: { status: 'running', version: '1.27.2', uptime_s: 1234, config_ok: true, connections: 42 },
  vhosts: { count: 12 },
  traffic_24h: { requests: 1500, errors: 30, bytes: 123456789, humans: 1000, robots: 400, blocked: 25 },
  alerts: { active: 2, critical: 1, items: [{ id: 'a1', severity: 'critical', title: 'Pic de 5xx', since: new Date().toISOString() }] },
  top_vhosts: [{ name: 'a.example', requests: 900, bytes: 5000, errors: 12, humans: 700, robots: 200 }],
  top_countries: [{ country: 'FR', requests: 800 }, { country: 'US', requests: 300 }],
  security: { crowdsec: { active: 5 }, waf: { blocked_24h: 17 }, blocklists: { ips: 1200, hits_24h: 44 } },
  certs_expiring: [{ name: 'a.example', daysLeft: 9, notAfter: new Date(Date.now() + 9 * 86400e3).toISOString() }],
  mfa: { accounts: 3 },
  components: { analyzer: { state: 'ok' }, waf: { state: 'degraded', detail: 'règles en retard' }, challenge: { state: 'disabled' } },
  champ_futur: { x: 1 },
};

async function enrolledAdmin(ctxApp, name = 'root') {
  const { users, base } = ctxApp;
  const id = await users.create({ username: name, password: 'correct horse battery', role: 'admin' });
  return { id, base };
}

module.exports = { makeApp, client, login, fakeDashboard, GOOD_SUMMARY, enrolledAdmin, generateSecret, totpAt, KEY };
