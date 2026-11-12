#!/usr/bin/env node
// Banc de charge du log store (#60) : ingestion synthétique + latence des requêtes. Zéro dépendance (Node >= 18).
// Usage : node bench.mjs --url http://127.0.0.1:18443 --admin-token <jeton> [--events 2000000] [--batch 2000]
//         [--conc 4] [--days 14] [--instances 3] [--queries 15] [--skip-ingest] [--json out.json]
// Les jetons créés (write/read) sont libellés « bench-… » et révoqués en fin de banc.
import { gzipSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i < 0 ? d : (process.argv[i + 1] ?? true); };
const URL_ = String(arg('url', 'http://127.0.0.1:18443')).replace(/\/$/, '');
const ADMIN = arg('admin-token', process.env.LOGSTORE_ADMIN_TOKEN || '');
const TOTAL = +arg('events', 2000000), BATCH = +arg('batch', 2000), CONC = +arg('conc', 4);
const DAYS = +arg('days', 14), NINST = +arg('instances', 3), QRUNS = +arg('queries', 15);
const SKIP = process.argv.includes('--skip-ingest');
if (!ADMIN) { console.error('--admin-token (ou LOGSTORE_ADMIN_TOKEN) requis'); process.exit(2); }

const api = async (method, path, { token, body, headers = {} } = {}) => {
  const r = await fetch(URL_ + path, { method, headers: { Authorization: 'Bearer ' + token, ...headers }, body });
  const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { j = txt; }
  return { status: r.status, json: j };
};

// jeu de données synthétique reproductible (PRNG mulberry32)
let seed = 42;
const rnd = () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (a) => a[Math.floor(rnd() * a.length)];
const zipf = (n) => Math.min(n - 1, Math.floor(Math.pow(rnd(), 2.5) * n)); // queue lourde
const SITES = Array.from({ length: 40 }, (_, i) => `site${i}.example.com`);
const PATHS = Array.from({ length: 5000 }, (_, i) => `/p/${i}/index.html`);
const SCAN = ['/.env', '/wp-admin/setup.php', '/.git/config', '/phpmyadmin/', '/xmlrpc.php', '/vendor/phpunit/x.php'];
const UAS = ['Mozilla/5.0 (X11; Linux x86_64) Chrome/126', 'Mozilla/5.0 (Windows NT 10.0) Firefox/127', 'curl/8.5', 'python-requests/2.31', 'Googlebot/2.1', 'Go-http-client/1.1', 'Mozilla/5.0 (iPhone) Safari/604'];
const COUNTRIES = ['FR', 'US', 'DE', 'CN', 'RU', 'NL', 'GB', 'BR', 'IN', 'SG'];
const IPS = Array.from({ length: 30000 }, (_, i) => `${1 + (i * 7) % 223}.${(i * 13) % 256}.${(i * 29) % 256}.${1 + (i * 31) % 254}`);

function event(tsMs) {
  const scanner = rnd() < 0.04, blocked = scanner && rnd() < 0.7;
  return {
    ts: new Date(tsMs).toISOString(), source: blocked ? 'waf' : 'access', action: blocked ? 'blocked' : 'allowed',
    site: SITES[zipf(SITES.length)], ip: IPS[zipf(IPS.length)], method: rnd() < 0.9 ? 'GET' : 'POST',
    path: scanner ? pick(SCAN) : PATHS[zipf(PATHS.length)], query: rnd() < 0.2 ? 'a=' + Math.floor(rnd() * 1e6) : undefined,
    status: scanner ? (blocked ? 403 : 404) : (rnd() < 0.93 ? 200 : pick([301, 304, 404, 500, 502])),
    bytes: Math.floor(200 + rnd() * 50000), rt_ms: Math.floor(1 + Math.pow(rnd(), 3) * 800), ua: pick(UAS),
    referer: rnd() < 0.3 ? 'https://ref' + Math.floor(rnd() * 50) + '.example.org/x' : undefined, country: pick(COUNTRIES),
    bot_class: rnd() < 0.15 ? pick(['good', 'bad', 'ia']) : undefined, rule: blocked ? pick(['scanner-env', 'scanner-wp', 'rate-limit']) : undefined,
  };
}

const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.min(s.length - 1, Math.floor(p * s.length))] : NaN; };
const out = { when: new Date().toISOString(), params: { TOTAL, BATCH, CONC, DAYS, NINST, QRUNS } };
const created = [];
const mk = async (body) => {
  const r = await api('POST', '/v1/tokens', { token: ADMIN, body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } });
  if (r.status >= 300) throw new Error('création jeton : ' + JSON.stringify(r));
  created.push(r.json.id ?? r.json.token_id ?? r.json.token?.id); return r.json.token?.token ?? r.json.token;
};

try {
  const tag = 'bench-' + Date.now().toString(36);
  const writers = []; for (let i = 0; i < NINST; i++) writers.push(await mk({ label: `${tag}-w${i}`, role: 'write', instance_id: `bench${i}` }));
  const reader = await mk({ label: `${tag}-r`, role: 'read' });

  if (!SKIP) {
    const now = Date.now(), span = DAYS * 864e5 * 0.98;
    const batches = Math.ceil(TOTAL / BATCH); let next = 0, accepted = 0, rejected = 0, errors = 0; const lat = [];
    const t0 = process.hrtime.bigint();
    const send = (w, gz, b) => api('POST', '/v1/ingest', { token: writers[w % NINST], body: gz, headers: { 'Content-Encoding': 'gzip', 'Content-Type': 'application/x-ndjson', 'Idempotency-Key': `${tag}-${b}` } });
    const worker = async (w) => {
      for (;;) {
        const b = next++; if (b >= batches) return;
        const base = now - span + (span * b) / batches, step = span / batches / BATCH;
        const lines = []; for (let i = 0; i < BATCH; i++) lines.push(JSON.stringify(event(base + i * step)));
        const gz = gzipSync(lines.join('\n') + '\n');
        const t = process.hrtime.bigint();
        let r = await send(w, gz, b);
        for (let k = 0; r.status === 429 && k < 50; k++) { await new Promise((s) => setTimeout(s, 100)); r = await send(w, gz, b); }
        lat.push(Number(process.hrtime.bigint() - t) / 1e6);
        if (r.status === 200) { accepted += r.json.accepted; rejected += r.json.rejected_total || 0; } else { errors++; if (errors < 4) console.error('ingest', r.status, JSON.stringify(r.json)); }
        if (b % 50 === 0) process.stderr.write(`\r  lots ${b}/${batches}  ${Math.round(accepted / (Number(process.hrtime.bigint() - t0) / 1e9))} ev/s   `);
      }
    };
    await Promise.all(Array.from({ length: CONC }, (_, w) => worker(w)));
    const secs = Number(process.hrtime.bigint() - t0) / 1e9;
    out.ingest = { events: accepted, rejected, errors, seconds: +secs.toFixed(1), events_per_s: Math.round(accepted / secs), batch_ms_p50: +pct(lat, .5).toFixed(0), batch_ms_p95: +pct(lat, .95).toFixed(0), batch_ms_max: +Math.max(...lat).toFixed(0) };
    console.error('\n  ingestion', out.ingest);
  }

  const Q = {
    'events 1h': '/v1/events?since=1h&limit=100',
    'events 24h site+status': `/v1/events?since=24h&site=${SITES[0]}&status=404&limit=100`,
    'events 7j source=waf': '/v1/events?since=168h&source=waf&limit=100',
    'stats visits 24h': '/v1/stats/visits?since=24h',
    'stats visits 7j': '/v1/stats/visits?since=168h',
    'stats visits 14j': `/v1/stats/visits?since=${Math.max(1, DAYS * 24 - 1)}h`,
    'top path 24h': '/v1/stats/top?dimension=path&since=24h&limit=20',
    'top ua 7j': '/v1/stats/top?dimension=ua&since=168h&limit=20',
    'top ip 24h': '/v1/stats/top?dimension=ip&since=24h&limit=20',
    'security 24h': '/v1/stats/security?since=24h',
    'security 7j': '/v1/stats/security?since=168h',
    'ips corrélées 24h': '/v1/stats/ips?since=24h&min_instances=2',
    'ips corrélées 7j': '/v1/stats/ips?since=168h&min_instances=2',
    'campagnes 24h': '/v1/stats/campaigns?since=24h',
    'campagnes 7j': '/v1/stats/campaigns?since=168h',
    'fiche IP': `/v1/ips/${IPS[0]}?since=168h`,
  };
  out.queries = {};
  for (const [name, path] of Object.entries(Q)) {
    const lat = []; let status = 0;
    for (let i = 0; i < QRUNS; i++) {
      const t = process.hrtime.bigint(); const r = await api('GET', path, { token: reader });
      lat.push(Number(process.hrtime.bigint() - t) / 1e6); status = r.status;
      await new Promise((s) => setTimeout(s, 60));
    }
    out.queries[name] = { status, p50_ms: +pct(lat, .5).toFixed(1), p95_ms: +pct(lat, .95).toFixed(1), max_ms: +Math.max(...lat).toFixed(1) };
  }
  console.log('\nLatence des requêtes (ms), ' + QRUNS + ' passages');
  console.table(out.queries);
  if (out.ingest) console.log('\nIngestion :', out.ingest);
} finally {
  for (const id of created) if (id != null) await api('DELETE', '/v1/tokens/' + id, { token: ADMIN }).catch(() => {});
  const f = arg('json', null); if (f && f !== true) writeFileSync(f, JSON.stringify(out, null, 2));
}
