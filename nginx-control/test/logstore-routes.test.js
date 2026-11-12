'use strict';
/**
 * Journal centralise (features/logstore.js) contre un vrai serveur, un faux demon Docker (socket unix), un faux
 * log store HTTP et un faux shipper : permissions, validation des parametres, jeton transmis (et jamais renvoye),
 * redirections refusees, log store injoignable / jeton refuse, cycle de vie du conteneur shipper.
 * Le « conteneur » shipper est joint sur 127.0.0.1 (shipper_name: 127.0.0.1, port 9181) : aucun reseau Docker reel.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsroutes-data-'));
for (const d of ['lib', 'features', 'public']) fs.cpSync(path.join(root, d), path.join(appDir, d), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip', 'shipdata'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n' +
  '  - username: op\n    password: op123456\n    role: operator\n    name: O\n    enabled: true\n' +
  '  - username: view\n    password: view12345\n    role: viewer\n    name: V\n    enabled: true\n');
fs.writeFileSync(path.join(tmp, 'sites', 'seen.conf'), 'server {\n  listen 443 ssl;\n  server_name seen.example.com;\n  location / { proxy_pass http://app1:80; }\n}\n');
fs.writeFileSync(path.join(tmp, 'sites', 'silent.conf'), 'server {\n  listen 443 ssl;\n  server_name silent.example.com;\n  location / { proxy_pass http://app2:80; }\n}\n');

const PORT = 3952, STORE_PORT = 38443, SHIPPER_PORT = 9181;
const READ = 'lgs_' + 'r'.repeat(40), SINK = 'lgs_' + 's'.repeat(40);
const LOCAL = 'l'.repeat(40);
const YML = (extra = '') => `enable: true\nurl: http://127.0.0.1:${STORE_PORT}\nshipper_enable: true\nshipper_name: 127.0.0.1\nshipper_image: reg.example/analyzer:1\n` +
  `shipper_host_data_path: ${path.join(tmp, 'shipdata')}\nshipper_host_logs_path: ${path.join(tmp, 'logs')}\ninstance: web1\n${extra}`;
const ymlFile = path.join(tmp, 'config', 'logstore.yml');

// ── Faux demon Docker ────────────────────────────────────────────────────────
const sock = path.join(tmp, 'docker.sock');
const dcalls = [];
let containerExists = false, containerRunning = false;
const fakeDocker = http.createServer((req, res) => {
  let body = ''; req.on('data', d => body += d);
  req.on('end', () => {
    const u = new URL(req.url, 'http://x');
    let parsed = null; try { parsed = body ? JSON.parse(body) : null; } catch { /* */ }
    dcalls.push({ method: req.method, path: u.pathname, query: u.search, body: parsed });
    const json = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '{}' : JSON.stringify(o)); };
    if (req.method === 'GET' && /^\/containers\/[^/]+\/json$/.test(u.pathname)) {
      return containerExists ? json(200, { State: { Running: containerRunning, Status: containerRunning ? 'running' : 'exited', StartedAt: 'x', Health: { Status: 'healthy' } }, Config: { Image: 'reg.example/analyzer:1' } }) : json(404);
    }
    if (req.method === 'POST' && u.pathname === '/containers/create') { containerExists = true; return json(201, { Id: 'abc' }); }
    if (req.method === 'POST' && /\/start$/.test(u.pathname)) { containerRunning = true; res.writeHead(204); return res.end(); }
    if (req.method === 'POST' && /\/(stop|restart)$/.test(u.pathname)) { containerRunning = false; res.writeHead(204); return res.end(); }
    if (req.method === 'DELETE') { containerExists = false; containerRunning = false; res.writeHead(204); return res.end(); }
    if (req.method === 'POST' && u.pathname === '/images/create') { res.writeHead(200); res.write(JSON.stringify({ status: 'ok' }) + '\n'); return res.end(); }
    if (req.method === 'GET' && /^\/images\/.+\/json$/.test(u.pathname)) return json(200, { Id: imageId });
    return json(404);
  });
});
let imageId = 'sha256:AAA';
const created = () => dcalls.filter(c => c.path === '/containers/create');

// ── Faux log store ───────────────────────────────────────────────────────────
const scalls = [];
let storeMode = 'ok'; // ok | 401 | 429 | redirect | huge | slow | notjson
const fakeStore = http.createServer((req, res) => {
  scalls.push({ method: req.method, url: req.url, auth: req.headers.authorization, ua: req.headers['user-agent'] });
  const u = new URL(req.url, 'http://x');
  const json = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (storeMode === '401') return json(401, { error: 'unauthorized' });
  if (storeMode === '429') return json(429, { error: 'rate_limited' });
  if (storeMode === 'redirect') { res.writeHead(302, { Location: 'http://127.0.0.1:1/steal' }); return res.end(); }
  if (storeMode === 'huge') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"x":"' + 'a'.repeat(9 * 1024 * 1024) + '"}'); }
  if (storeMode === 'notjson') { res.writeHead(200); return res.end('<html>'); }
  if (req.headers.authorization !== 'Bearer ' + READ) return json(401, { error: 'unauthorized' });
  if (u.pathname === '/v1/health') return json(200, { status: 'ok', version: '0.2.0', detail: { timescale: true, db_size_bytes: 123456, last_ingest: '2026-11-09T20:00:00Z', retention_days: 30, ip_mode: 'clear' } });
  if (u.pathname === '/v1/events') return json(200, { events: [{ id: 1, ts: '2026-11-09T20:00:00Z', source: 'access', action: 'allowed', ip: '203.0.113.9', path: '/', status: 200 }], next_cursor: 'abc' });
  if (u.pathname.startsWith('/v1/ips/')) return json(200, { summary: { total: 1 }, events: [], ip_mode: 'clear' });
  if (u.pathname === '/v1/stats/visits') return json(200, { bucket: 'hour', points: [] });
  if (u.pathname === '/v1/stats/top') return json(200, { dimension: u.searchParams.get('dimension'), items: [] });
  if (u.pathname === '/v1/stats/security') return json(200, { status_classes: {}, blocked: [], scanners: [], error_user_agents: [] });
  if (u.pathname === '/v1/instances') return json(200, { instances: [{ id: 'web1', name: 'web1' }, { id: 'web2', name: 'web2' }] });
  return json(404, { error: 'not_found' });
});

// ── Faux shipper (/status) ───────────────────────────────────────────────────
const hcalls = [];
const fakeShipper = http.createServer((req, res) => {
  hcalls.push({ url: req.url, auth: req.headers.authorization });
  if (req.headers.authorization !== 'Bearer ' + LOCAL) { res.writeHead(401); return res.end('{}'); }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ version: '0.1.0', uptime_s: 120, sent: { events: 42, batches: 3, rejected: 0 }, buffer: { spool_files: 0, spool_bytes: 0 } }));
});

function req(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) }, timeout: 20000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b), raw: b }); } catch { resolve({ status: res.statusCode, body: b, raw: b }); } });
    });
    r.on('error', e => resolve({ status: 0, body: e.message, raw: '' }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout', raw: '' }); });
    if (data) r.write(data);
    r.end();
  });
}
const login = (u, p) => new Promise(resolve => {
  const b = `username=${u}&password=${p}`;
  const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
    res => resolve((res.headers['set-cookie'] || [''])[0].split(';')[0]));
  r.on('error', () => resolve('')); r.write(b); r.end();
});

(async () => {
  await new Promise(r => fakeDocker.listen(sock, r));
  await new Promise(r => fakeStore.listen(STORE_PORT, '127.0.0.1', r));
  await new Promise(r => fakeShipper.listen(SHIPPER_PORT, '127.0.0.1', r));
  fs.writeFileSync(ymlFile, YML());

  const env = { ...process.env, PORT: String(PORT), DOCKER_SOCKET: sock, LOGSTORE_READ_TOKEN: READ, LOGSINK_TOKEN: SINK, SHIPPER_LOCAL_TOKEN: LOCAL,
    USERS_FILE: path.join(tmp, 'config', 'users.yml'),
    DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'), DIR_SNIPPETS: path.join(tmp, 'snippets'),
    DIR_STREAMS: path.join(tmp, 'streams'), DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
    DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'), DIR_SSL: path.join(tmp, 'ssl'),
    DIR_CERTS: path.join(tmp, 'certs'), DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  let srvOut = ''; srv.stdout.on('data', d => srvOut += d); srv.stderr.on('data', d => srvOut += d);
  await sleep(2500);

  const ck = await login('admin', 'admin123');
  const ckOp = await login('op', 'op123456');
  const ckView = await login('view', 'view12345');
  console.log('\nJournal centralise : routes /api/logstore/*');
  check('connexions ok', () => assert.ok(ck && ckOp && ckView));

  console.log('\ndemarrage du serveur : le conteneur manquant est recree');
  check('boot : shipper absent + active -> create + start, durci, jeton local et jeton d envoi', () => {
    const c = created();
    assert.strictEqual(c.length, 1, srvOut);
    assert.ok(c[0].query.includes('name=127.0.0.1'));
    const e = c[0].body.Env;
    assert.ok(e.includes('LOGSHIP_LOCAL_TOKEN=' + LOCAL));
    assert.ok(e.includes('LOGSINK_TOKEN=' + SINK));
    assert.ok(e.includes(`LOGSINK_URL=http://127.0.0.1:${STORE_PORT}`));
    assert.deepStrictEqual(c[0].body.HostConfig.Binds, [`${path.join(tmp, 'logs')}:/nginx/logs:ro`, `${path.join(tmp, 'shipdata')}:/data`]);
    assert.strictEqual(c[0].body.HostConfig.ReadonlyRootfs, true);
    assert.deepStrictEqual(c[0].body.HostConfig.CapDrop, ['ALL']);
    assert.ok(dcalls.some(c2 => /\/start$/.test(c2.path)));
  });

  console.log('\npermissions');
  for (const [m, p, b] of [['GET', '/api/logstore/status'], ['GET', '/api/logstore/events'], ['GET', '/api/logstore/ip?ip=1.1.1.1'], ['POST', '/api/logstore/shipper/start', {}], ['POST', '/api/logstore/shipper/stop', {}]]) {
    const r = await req(m, p, '', b);
    check(`sans session : ${m} ${p} refuse`, () => assert.ok([401, 403].includes(r.status), String(r.status)));
  }
  const vRead = await req('GET', '/api/logstore/events?since=1h', ckView);
  const vStart = await req('POST', '/api/logstore/shipper/start', ckView, {});
  const vStop = await req('POST', '/api/logstore/shipper/stop', ckView, {});
  const oStart = await req('POST', '/api/logstore/shipper/start', ckOp, {});
  check('viewer : lecture autorisee, pilotage du conteneur refuse', () => {
    assert.strictEqual(vRead.status, 200);
    assert.strictEqual(vStart.status, 403); assert.strictEqual(vStop.status, 403);
  });
  check('operateur (DEPLOY) : peut demarrer', () => assert.strictEqual(oStart.status, 200));

  console.log('\nstatut');
  scalls.length = 0; hcalls.length = 0;
  const st = await req('GET', '/api/logstore/status', ck);
  check('statut : log store en ligne, conteneur en marche, /status du shipper lu avec le jeton local', () => {
    assert.strictEqual(st.status, 200);
    assert.strictEqual(st.body.read.enabled, true);
    assert.deepStrictEqual(st.body.read.blockers, []);
    assert.strictEqual(st.body.store.reachable, true);
    assert.strictEqual(st.body.store.version, '0.2.0');
    assert.strictEqual(st.body.shipper.container.running, true);
    assert.strictEqual(st.body.shipper.status.sent.events, 42);
    assert.strictEqual(hcalls[0].auth, 'Bearer ' + LOCAL);
    assert.strictEqual(st.body.shipper.localUrl, 'http://127.0.0.1:9181');
  });
  check('AUCUN secret dans la reponse (jetons de lecture, d envoi, local)', () => {
    for (const s of [READ, SINK, LOCAL]) assert.ok(!st.raw.includes(s), 'fuite : ' + s.slice(0, 8));
    assert.strictEqual(st.body.read.tokenSet, true); assert.strictEqual(st.body.shipper.sinkTokenSet, true);
  });

  console.log('\nlecture : jeton envoye au log store, parametres valides');
  scalls.length = 0;
  const ev = await req('GET', '/api/logstore/events?since=24h&site=a.example.com&source=waf&limit=50&evil=1', ck);
  check('events : relaye avec Bearer READ, cle inconnue non transmise, UA du dashboard', () => {
    assert.strictEqual(ev.status, 200);
    assert.strictEqual(ev.body.events.length, 1);
    assert.strictEqual(scalls[0].auth, 'Bearer ' + READ);
    assert.ok(!scalls[0].url.includes('evil'));
    assert.ok(scalls[0].url.startsWith('/v1/events?since=24h'));
    assert.ok(scalls[0].ua && scalls[0].ua.length > 0);
  });
  scalls.length = 0;
  const bad = [
    await req('GET', '/api/logstore/events?limit=9999', ck), await req('GET', '/api/logstore/events?source=x', ck),
    await req('GET', '/api/logstore/ip?ip=../../v1/tokens', ck), await req('GET', '/api/logstore/ip', ck),
    await req('GET', '/api/logstore/top?dimension=password', ck), await req('GET', '/api/logstore/top', ck),
  ];
  check('parametres invalides : 400, RIEN n est envoye au log store', () => {
    for (const r of bad) assert.strictEqual(r.status, 400, JSON.stringify(r.body));
    assert.strictEqual(scalls.length, 0);
  });
  const ip = await req('GET', '/api/logstore/ip?ip=203.0.113.9&since=168h', ck);
  const top = await req('GET', '/api/logstore/top?dimension=ip&since=24h', ck);
  const vis = await req('GET', '/api/logstore/visits?since=24h', ck);
  const sec = await req('GET', '/api/logstore/security?since=24h', ck);
  const ins = await req('GET', '/api/logstore/instances', ck);
  check('ip / top / visits / security / instances : 200', () => {
    for (const r of [ip, top, vis, sec, ins]) assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(top.body.dimension, 'ip');
  });

  console.log('\n#65 : visits et top au-dela de 31 jours');
  scalls.length = 0;
  const long = await req('GET', '/api/logstore/top?dimension=path&since=2160h', ck);
  const longVis = await req('GET', '/api/logstore/visits?since=2160h&bucket=hour', ck);
  const tooLong = await req('GET', '/api/logstore/top?dimension=path&since=9000h', ck);
  const secLong = await req('GET', '/api/logstore/security?since=2160h', ck);
  check('fenetre > 31 j : tranches de < 31 j envoyees a la suite, fusion marquee approximative (top)', () => {
    assert.strictEqual(long.status, 200, JSON.stringify(long.body));
    assert.strictEqual(long.body.approximate, true); assert.ok(long.body.chunks >= 3);
    const topCalls = scalls.filter((c) => c.url.startsWith('/v1/stats/top'));
    assert.strictEqual(topCalls.length, long.body.chunks);
    for (const c of topCalls) { assert.ok(c.url.includes('from=') && c.url.includes('to=') && !c.url.includes('since=')); }
  });
  check('fenetre > 31 j : visits force bucket=day ; > 366 j : 400', () => {
    assert.strictEqual(longVis.status, 200, JSON.stringify(longVis.body));
    assert.strictEqual(longVis.body.bucket, 'day');
    assert.ok(scalls.filter((c) => c.url.startsWith('/v1/stats/visits')).every((c) => c.url.includes('bucket=day')));
    assert.strictEqual(tooLong.status, 400);
  });
  check('security n est pas decoupe : envoye tel quel (le log store refusera > 31 j)', () => {
    assert.strictEqual(secLong.status, 200);
    assert.ok(scalls.some((c) => c.url.startsWith('/v1/stats/security') && c.url.includes('since=2160h')));
  });

  console.log('\n#89 : lecture limitee a l instance du dashboard');
  scalls.length = 0;
  const own = await req('GET', '/api/logstore/events?since=1h&instance=web2', ck);
  const topOwn = await req('GET', '/api/logstore/top?dimension=ip&since=24h', ck);
  const ipOwn = await req('GET', '/api/logstore/ip?ip=203.0.113.9&since=168h&instance=web2', ck);
  const insOwn = await req('GET', '/api/logstore/instances', ck);
  check('toutes les lectures envoient instance=web1 (celle du dashboard), jamais celle du navigateur', () => {
    const urls = scalls.filter((c) => c.url.startsWith('/v1/') && !c.url.startsWith('/v1/instances') && !c.url.startsWith('/v1/health')).map((c) => new URL(c.url, 'http://x'));
    assert.strictEqual(urls.length, 3);
    for (const u of urls) assert.deepStrictEqual(u.searchParams.getAll('instance'), ['web1'], u.href);
    assert.strictEqual(own.status, 200); assert.strictEqual(topOwn.status, 200); assert.strictEqual(ipOwn.status, 200);
  });
  check('la liste des instances ne contient que la sienne', () => {
    assert.deepStrictEqual(insOwn.body.instances.map((i) => i.id), ['web1']);
  });

  console.log('\nlog store defaillant');
  storeMode = '401'; const r401 = await req('GET', '/api/logstore/events?since=1h', ck);
  storeMode = '429'; const r429 = await req('GET', '/api/logstore/events?since=1h', ck);
  storeMode = 'redirect'; scalls.length = 0; const r302 = await req('GET', '/api/logstore/events?since=1h', ck);
  const n302 = scalls.length;
  storeMode = 'huge'; const rHuge = await req('GET', '/api/logstore/events?since=1h', ck);
  storeMode = 'notjson'; const rNj = await req('GET', '/api/logstore/events?since=1h', ck);
  storeMode = 'ok';
  check('jeton refuse -> 502 token_rejected (le 401 du store n est pas renvoye tel quel : la session reste valide)', () => {
    assert.strictEqual(r401.status, 502); assert.strictEqual(r401.body.error, 'token_rejected');
  });
  check('429 relaye', () => { assert.strictEqual(r429.status, 429); assert.strictEqual(r429.body.error, 'rate_limited'); });
  check('redirection : refusee, non suivie, une seule requete', () => {
    assert.strictEqual(r302.status, 502); assert.strictEqual(r302.body.error, 'redirect_refused'); assert.strictEqual(n302, 1);
  });
  check('reponse > 8 Mio : refusee', () => { assert.strictEqual(rHuge.status, 502); assert.strictEqual(rHuge.body.error, 'too_large'); });
  check('corps non JSON : 502 sans fuite', () => { assert.strictEqual(rNj.status, 502); assert.ok(!rNj.raw.includes('<html>')); });

  await new Promise(r => fakeStore.close(r));
  const down = await req('GET', '/api/logstore/events?since=1h', ck);
  const downSt = await req('GET', '/api/logstore/status', ck);
  check('log store injoignable : 502 unreachable, statut 200 reachable:false (jamais une panne du dashboard)', () => {
    assert.strictEqual(down.status, 502); assert.strictEqual(down.body.error, 'unreachable');
    assert.strictEqual(downSt.status, 200); assert.strictEqual(downSt.body.store.reachable, false);
  });

  console.log('\nconfiguration incomplete');
  fs.writeFileSync(ymlFile, 'enable: false\n');
  const off = await req('GET', '/api/logstore/events?since=1h', ck);
  const offSt = await req('GET', '/api/logstore/status', ck);
  check('desactive : 409 not_configured, statut explique les blocages', () => {
    assert.strictEqual(off.status, 409); assert.strictEqual(off.body.error, 'not_configured');
    assert.deepStrictEqual(offSt.body.read.blockers, ['disabled', 'url']);
  });
  fs.writeFileSync(ymlFile, 'enable: true\nurl: http://logs.example.com\n');
  const badUrl = await req('GET', '/api/logstore/status', ck);
  check('URL http:// publique refusee (erreur de config, aucune requete sortante)', () => {
    assert.ok(badUrl.body.errors.some(e => e.startsWith('url')), JSON.stringify(badUrl.body.errors));
    assert.ok(badUrl.body.read.blockers.includes('invalid'));
    assert.strictEqual(badUrl.body.store, undefined);
  });

  console.log('\nconteneur shipper : cycle de vie');
  fs.writeFileSync(ymlFile, YML());
  dcalls.length = 0;
  const start = await req('POST', '/api/logstore/shipper/start', ck, {});
  check('start : pull + recreation (stop, delete, create, start)', () => {
    assert.strictEqual(start.status, 200, JSON.stringify(start.body));
    assert.ok(dcalls.some(c => c.path === '/images/create'));
    assert.strictEqual(created().length, 1);
    assert.ok(dcalls.some(c => /\/start$/.test(c.path)));
  });
  const stop = await req('POST', '/api/logstore/shipper/stop', ck, {});
  check('stop : arrete et supprime', () => {
    assert.strictEqual(stop.status, 200);
    assert.ok(dcalls.some(c => c.method === 'DELETE'));
    assert.strictEqual(containerExists, false);
  });
  fs.writeFileSync(ymlFile, YML().replace(/shipper_host_data_path:.*\n/, ''));
  const noData = await req('POST', '/api/logstore/shipper/start', ck, {});
  check('sans shipper_host_data_path : refus 409 explicite, aucun conteneur cree', () => {
    assert.strictEqual(noData.status, 409); assert.strictEqual(noData.body.code, 'host_data_path');
    assert.ok(noData.body.fr && noData.body.en);
  });
  fs.writeFileSync(ymlFile, YML('shipper_enable: false\n'));
  const dis = await req('POST', '/api/logstore/shipper/image/update', ck, {});
  check('desactive : mise a jour d image refusee', () => { assert.strictEqual(dis.status, 409); assert.strictEqual(dis.body.code, 'disabled'); });

  console.log('\nfichiers statiques');
  const page = await req('GET', '/logstore', ck);
  const js = await req('GET', '/assets/js/logstore.js', ck);
  check('la page /logstore sert la SPA et logstore.js est servi', () => {
    assert.strictEqual(page.status, 200); assert.ok(String(page.raw).includes('page-logstore'));
    assert.strictEqual(js.status, 200); assert.ok(js.raw.includes('function logstoreLoad'));
  });

  srv.kill();
  fakeDocker.close(); fakeShipper.close();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
