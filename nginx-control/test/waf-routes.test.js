'use strict';
/**
 * WAF emule (features/waf.js) contre un vrai serveur, un faux demon Docker (socket unix) et un faux
 * serveur WAF HTTP : permissions, validation des parametres, jeton transmis, WAF injoignable,
 * refus sans accept_limits, cycle de vie Docker, vhosts fusionnes, diagnostics.
 * Le « conteneur » WAF est joint sur 127.0.0.1 (container_name: 127.0.0.1) : aucun reseau Docker reel.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wafroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wafroutes-data-'));
for (const d of ['lib', 'features', 'public']) fs.cpSync(path.join(root, d), path.join(appDir, d), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip', 'wafdata', 'wafrules'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n' +
  '  - username: op\n    password: op123456\n    role: operator\n    name: O\n    enabled: true\n' +
  '  - username: view\n    password: view12345\n    role: viewer\n    name: V\n    enabled: true\n');
fs.writeFileSync(path.join(tmp, 'sites', 'seen.conf'), 'server {\n  listen 443 ssl;\n  server_name seen.example.com;\n  location / { proxy_pass http://app1:80; }\n}\n');
fs.writeFileSync(path.join(tmp, 'sites', 'silent.conf'), 'server {\n  listen 443 ssl;\n  server_name silent.example.com;\n  location / { proxy_pass http://app2:80; }\n}\n');

const PORT = 3951, WAF_PORT = 39101, TOKEN = 'test-waf-token-0123456789abcdef0123';
const WAF_YML = (extra = '') => `enable: true\naccept_limits: true\ncontainer_name: 127.0.0.1\nport: ${WAF_PORT}\ncontainer_image: reg.example/waf:1\n` +
  `host_data_path: ${path.join(tmp, 'wafdata')}\nhost_rules_path: ${path.join(tmp, 'wafrules')}\nhost_logs_path: ${path.join(tmp, 'logs')}\n${extra}`;
const wafYml = path.join(tmp, 'config', 'waf.yml');

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
      return containerExists ? json(200, { State: { Running: containerRunning, Status: containerRunning ? 'running' : 'exited', StartedAt: 'x' }, Config: { Image: 'reg.example/waf:1' } }) : json(404);
    }
    if (req.method === 'POST' && u.pathname === '/containers/create') { containerExists = true; return json(201, { Id: 'abc' }); }
    if (req.method === 'POST' && /\/start$/.test(u.pathname)) { containerRunning = true; res.writeHead(204); return res.end(); }
    if (req.method === 'POST' && /\/(stop|restart)$/.test(u.pathname)) { containerRunning = /restart/.test(u.pathname); res.writeHead(204); return res.end(); }
    if (req.method === 'DELETE') { containerExists = false; containerRunning = false; res.writeHead(204); return res.end(); }
    if (req.method === 'POST' && u.pathname === '/images/create') { res.writeHead(200); res.write(JSON.stringify({ status: 'ok' }) + '\n'); return res.end(); }
    if (req.method === 'GET' && /^\/images\/.+\/json$/.test(u.pathname)) return json(200, { Id: imageId });
    return json(404);
  });
});
let imageId = 'sha256:AAA';
const created = () => dcalls.filter(c => c.path === '/containers/create');

// ── Faux WAF ─────────────────────────────────────────────────────────────────
const wcalls = [];
let wafStatusBody = { engine: { ready: true }, crs: { installed: true, version: 'v4.8.0', rulesLoaded: 700 }, logs: { formats: { waf_json: 1 }, dropped: 0 } };
const fakeWaf = http.createServer((req, res) => {
  let body = ''; req.on('data', d => body += d);
  req.on('end', () => {
    wcalls.push({ method: req.method, url: req.url, token: req.headers['x-waf-token'], body });
    if (req.headers['x-waf-token'] !== TOKEN) { res.writeHead(401); return res.end('{"error":"bad token"}'); }
    const u = new URL(req.url, 'http://x');
    const json = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/api/health') return json(200, { ok: true });
    if (u.pathname === '/api/status') return json(200, wafStatusBody);
    if (u.pathname === '/api/settings') return json(200, req.method === 'PUT' ? JSON.parse(body) : { mode: 'observe', paranoia: 1, vhostMode: 'all' });
    if (u.pathname === '/api/vhosts') return json(200, { vhosts: [{ name: 'seen.example.com', lines: 10, hits24h: 2, lastSeen: 1, format: 'waf_json', analyzed: true, mode: 'observe', paranoia: 1 }] });
    if (u.pathname === '/api/lists') return json(200, { list: u.searchParams.get('list') || '', count: 1, ips: [{ ip: '203.0.113.5', score: 12, hits: 3 }] });
    if (u.pathname === '/api/lists/ips') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('203.0.113.5\n'); }
    return json(200, { total: 0, items: [], echo: u.pathname });
  });
});

function req(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) }, timeout: 15000 }, res => {
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
  await new Promise(r => fakeWaf.listen(WAF_PORT, '127.0.0.1', r));
  fs.writeFileSync(wafYml, WAF_YML());

  const env = { ...process.env, PORT: String(PORT), DOCKER_SOCKET: sock, WAF_TOKEN: TOKEN,
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
  console.log('\nWAF emule : routes /api/waf/*');
  check('connexions ok', () => assert.ok(ck && ckOp && ckView));

  console.log('\ndemarrage du serveur : le conteneur manquant est recree');
  check('boot : conteneur absent + WAF active -> create + start avec les montages HOTE et le jeton', () => {
    const c = created();
    assert.strictEqual(c.length, 1, srvOut);
    assert.ok(c[0].query.includes('name=127.0.0.1'));
    assert.ok(c[0].body.Env.includes('WAF_TOKEN=' + TOKEN));
    assert.deepStrictEqual(c[0].body.HostConfig.Binds, [`${path.join(tmp, 'logs')}:/nginx/logs:ro`, `${path.join(tmp, 'wafdata')}:/waf`, `${path.join(tmp, 'wafrules')}:/waf-rules`]);
    assert.ok(dcalls.some(c2 => /\/start$/.test(c2.path)));
  });

  console.log('\npermissions');
  for (const [m, p, b] of [['GET', '/api/waf/status'], ['GET', '/api/waf/hits'], ['PUT', '/api/waf/settings', {}], ['POST', '/api/waf/container/start', {}]]) {
    const r = await req(m, p, '', b);
    check(`sans session : ${m} ${p} refuse`, () => assert.ok([401, 403].includes(r.status), String(r.status)));
  }
  const vRead = await req('GET', '/api/waf/rules', ckView);
  check('viewer : lecture autorisee', () => assert.strictEqual(vRead.status, 200));
  for (const [m, p, b] of [['PUT', '/api/waf/settings', { mode: 'observe' }], ['POST', '/api/waf/container/start', {}], ['POST', '/api/waf/container/stop', {}],
    ['POST', '/api/waf/container/restart', {}], ['POST', '/api/waf/image/update', {}], ['POST', '/api/waf/simulate', { uri: '/' }],
    ['POST', '/api/waf/lists/unlist', { ip: '203.0.113.5' }], ['POST', '/api/waf/alerts/ack', { ids: [1] }], ['POST', '/api/waf/engine/reload', {}],
    ['POST', '/api/waf/rules/update', {}], ['PUT', '/api/waf/custom-rules', { text: '' }]]) {
    const r = await req(m, p, ckView, b);
    check(`viewer : ${m} ${p} -> 403`, () => assert.strictEqual(r.status, 403, String(r.status)));
  }
  const opSet = await req('PUT', '/api/waf/settings', ckOp, { mode: 'observe' });
  check('operateur : PUT settings -> 200', () => assert.strictEqual(opSet.status, 200));

  console.log('\nstatut agrege');
  const st = await req('GET', '/api/waf/status', ck);
  check('config + conteneur + WAF joignable, aucun secret', () => {
    assert.strictEqual(st.status, 200);
    assert.strictEqual(st.body.enabled, true); assert.strictEqual(st.body.reachable, true);
    assert.strictEqual(st.body.container.running, true);
    assert.deepStrictEqual(st.body.blockers, []);
    assert.ok(!st.raw.includes(TOKEN), 'le jeton ne doit jamais atteindre le navigateur');
    assert.ok(!st.raw.includes(path.join(tmp, 'wafdata')), 'les chemins hote ne sont pas exposes');
  });

  console.log('\nproxy GET : liste blanche + bornes + jeton');
  wcalls.length = 0;
  const hits = await req('GET', '/api/waf/hits?limit=5&evil=1&ip=203.0.113.9&mode=remediate', ck);
  check('parametres connus relayes, inconnus supprimes, jeton envoye', () => {
    assert.strictEqual(hits.status, 200); assert.strictEqual(hits.body.reachable, true);
    assert.strictEqual(wcalls.length, 1);
    const u = new URL(wcalls[0].url, 'http://x');
    assert.strictEqual(u.pathname, '/api/hits');
    assert.strictEqual(u.searchParams.get('limit'), '5'); assert.strictEqual(u.searchParams.get('ip'), '203.0.113.9');
    assert.strictEqual(u.searchParams.get('evil'), null);
    assert.strictEqual(wcalls[0].token, TOKEN);
  });
  const lst = await req('GET', '/api/waf/lists?list=block', ck);
  check('listes : chaque IP porte son etat d application par les Blocklists', () => {
    assert.strictEqual(lst.status, 200);
    assert.strictEqual(lst.body.ips[0].ip, '203.0.113.5');
    assert.strictEqual(lst.body.ips[0].score, 12);
    assert.ok(lst.body.ips[0].application && typeof lst.body.ips[0].application.state === 'string', lst.raw);
  });
  wcalls.length = 0;
  for (const q of ['/api/waf/hits?limit=9999', '/api/waf/hits?ip=1.2.3.4/8', '/api/waf/hits?mode=x', '/api/waf/hits/stats?hours=99999', '/api/waf/rules?category=../x', '/api/waf/lists?list=zzz', '/api/waf/alerts?limit=0']) {
    const r = await req('GET', q, ck);
    check(`parametre invalide -> 400 sans appel au WAF : ${q}`, () => assert.strictEqual(r.status, 400, String(r.status)));
  }
  check('aucun appel WAF pour les requetes refusees', () => assert.strictEqual(wcalls.length, 0));
  const ssrf = await req('GET', '/api/waf/hits?host=evil.example&url=http://evil/', ck);
  check('aucun parametre ne peut changer la destination (pas de SSRF)', () => {
    assert.strictEqual(ssrf.status, 200);
    assert.ok(!wcalls.some(c => /evil/.test(c.url)));
  });

  console.log('\nproxy ecriture : validation + relais');
  wcalls.length = 0;
  const badSet = await req('PUT', '/api/waf/settings', ck, { mode: 'block' });
  const unkSet = await req('PUT', '/api/waf/settings', ck, { surprise: 1 });
  check('reglages invalides -> 400, rien relaye', () => { assert.strictEqual(badSet.status, 400); assert.strictEqual(unkSet.status, 400); assert.strictEqual(wcalls.length, 0); });
  const okSet = await req('PUT', '/api/waf/settings', ck, { mode: 'remediate', paranoia: 2, thresholds: { challenge: 5, block: 10 } });
  check('reglages valides relayes tels quels, reponse sous settings', () => {
    assert.strictEqual(okSet.status, 200);
    assert.strictEqual(okSet.body.settings.mode, 'remediate');
    assert.strictEqual(wcalls[0].method, 'PUT'); assert.strictEqual(wcalls[0].token, TOKEN);
    assert.deepStrictEqual(JSON.parse(wcalls[0].body), { mode: 'remediate', paranoia: 2, thresholds: { challenge: 5, block: 10 } });
  });
  const badSim = await req('POST', '/api/waf/simulate', ck, { uri: 'http://evil/' });
  const okSim = await req('POST', '/api/waf/simulate', ck, { uri: '/?q=1', method: 'get' });
  check('simulation : uri invalide -> 400 ; valide -> relayee', () => { assert.strictEqual(badSim.status, 400); assert.strictEqual(okSim.status, 200); });
  const badUnlist = await req('POST', '/api/waf/lists/unlist', ck, { ip: 'not-an-ip' });
  const okUnlist = await req('POST', '/api/waf/lists/unlist', ck, { ip: '203.0.113.5', list: 'block' });
  check('deslistage : IP invalide -> 400 ; valide -> 200', () => { assert.strictEqual(badUnlist.status, 400); assert.strictEqual(okUnlist.status, 200); });
  const badAck = await req('POST', '/api/waf/alerts/ack', ck, { ids: ['x'] });
  check('acquittement : ids invalides -> 400', () => assert.strictEqual(badAck.status, 400));

  console.log('\nvhosts : WAF + vhosts nginx connus');
  const vh = await req('GET', '/api/waf/vhosts', ck);
  check('un vhost nginx sans aucune ligne de log apparait avec seen:false', () => {
    assert.strictEqual(vh.body.reachable, true);
    const by = Object.fromEntries(vh.body.vhosts.map(v => [v.name, v]));
    assert.strictEqual(by['seen.example.com'].seen, true);
    assert.strictEqual(by['silent.example.com'].seen, false);
    assert.strictEqual(by['silent.example.com'].lines, 0);
  });

  console.log('\ndiagnostics');
  const dg = await req('GET', '/api/waf/diagnostics', ck);
  check('conseils structures (cles i18n), waf_json actif', () => {
    assert.strictEqual(dg.status, 200);
    const ids = dg.body.advice.map(a => a.id);
    assert.ok(ids.includes('crs_ok') && ids.includes('waf_json_active') && ids.includes('vhost_no_traffic'), ids.join(','));
    assert.ok(dg.body.advice.every(a => /^wafemu\.diag\./.test(a.titleKey)));
  });

  console.log('\ncycle de vie Docker (faux demon)');
  dcalls.length = 0;
  const stop = await req('POST', '/api/waf/container/stop', ck, {});
  check('stop -> 200, appel docker stop', () => { assert.strictEqual(stop.status, 200); assert.ok(dcalls.some(c => /\/stop/.test(c.path))); });
  const start = await req('POST', '/api/waf/container/start', ck, {});
  check('start -> pull + recreation, jeton dans l env du conteneur', () => {
    assert.strictEqual(start.status, 200, JSON.stringify(start.body));
    assert.ok(dcalls.some(c => c.path === '/images/create'));
    assert.strictEqual(created().length, 1);
    assert.ok(created()[0].body.Env.includes('WAF_TOKEN=' + TOKEN));
  });
  dcalls.length = 0;
  const rst = await req('POST', '/api/waf/container/restart', ck, {});
  check('restart -> docker restart puis attend /api/health', () => {
    assert.strictEqual(rst.status, 200, JSON.stringify(rst.body));
    assert.ok(dcalls.some(c => /\/restart/.test(c.path)));
    assert.strictEqual(rst.body.healthy, true);
  });
  dcalls.length = 0; imageId = 'sha256:AAA';
  const upd = await req('POST', '/api/waf/image/update', ck, {});
  check('mise a jour d image : tirage, pas de recreation si deja a jour', () => {
    assert.strictEqual(upd.status, 200); assert.strictEqual(upd.body.ok, true);
    assert.strictEqual(upd.body.updated, false); assert.strictEqual(created().length, 0);
  });

  console.log('\nrefus : limites non acceptees / chemins manquants');
  for (const [label, yml, code] of [
    ['sans accept_limits', WAF_YML().replace('accept_limits: true', 'accept_limits: false'), 'accept_limits_required'],
    ['sans host_data_path', WAF_YML().replace(/host_data_path: .*\n/, ''), 'host_data_path_required'],
    ['sans host_rules_path', WAF_YML().replace(/host_rules_path: .*\n/, ''), 'host_rules_path_required'],
    ['config invalide', WAF_YML('port: 99999\n'), 'invalid_config'],
  ]) {
    fs.writeFileSync(wafYml, yml);
    dcalls.length = 0;
    const r = await req('POST', '/api/waf/container/start', ck, {});
    check(`${label} -> 400 ${code}, messages FR+EN, aucun appel Docker`, () => {
      assert.strictEqual(r.status, 400); assert.strictEqual(r.body.code, code);
      assert.ok(r.body.messageFr && r.body.messageEn);
      assert.strictEqual(dcalls.length, 0);
    });
  }
  fs.writeFileSync(wafYml, WAF_YML().replace('accept_limits: true', 'accept_limits: false'));
  const stNoLimits = await req('GET', '/api/waf/status', ck);
  check('statut : blocker accept_limits expose pour l interface', () => assert.ok(stNoLimits.body.blockers.includes('accept_limits')));

  console.log('\nWAF desactive');
  fs.writeFileSync(wafYml, 'enable: false\n');
  wcalls.length = 0;
  const dis = await req('GET', '/api/waf/hits', ck);
  const disSet = await req('PUT', '/api/waf/settings', ck, { mode: 'observe' });
  const disStart = await req('POST', '/api/waf/container/start', ck, {});
  const disSt = await req('GET', '/api/waf/status', ck);
  check('lecture degradee, ecritures refusees (code disabled), aucun appel WAF', () => {
    assert.strictEqual(dis.status, 200); assert.strictEqual(dis.body.enabled, false); assert.strictEqual(dis.body.reachable, false);
    assert.strictEqual(disSet.status, 400); assert.strictEqual(disSet.body.code, 'disabled');
    assert.strictEqual(disStart.status, 400); assert.strictEqual(disStart.body.code, 'disabled');
    assert.strictEqual(disSt.body.enabled, false);
    assert.strictEqual(wcalls.length, 0);
  });

  console.log('\nWAF injoignable');
  fs.writeFileSync(wafYml, WAF_YML());
  await new Promise(r => fakeWaf.close(r));
  const un = await req('GET', '/api/waf/hits', ck);
  const unSt = await req('GET', '/api/waf/status', ck);
  const unVh = await req('GET', '/api/waf/vhosts', ck);
  const unDg = await req('GET', '/api/waf/diagnostics', ck);
  const unSet = await req('PUT', '/api/waf/settings', ck, { mode: 'observe' });
  check('lectures : 200 reachable:false (jamais une panne du dashboard)', () => {
    assert.strictEqual(un.status, 200); assert.strictEqual(un.body.reachable, false); assert.strictEqual(un.body.enabled, true);
    assert.strictEqual(unSt.status, 200); assert.strictEqual(unSt.body.reachable, false);
    assert.strictEqual(unVh.status, 200); assert.strictEqual(unVh.body.reachable, false);
    assert.deepStrictEqual(unDg.body.advice.map(a => a.id), ['unreachable']);
  });
  check('ecriture : 503', () => assert.strictEqual(unSet.status, 503));

  srv.kill();
  fakeDocker.close();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
