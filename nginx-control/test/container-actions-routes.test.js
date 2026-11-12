'use strict';
/**
 * Routes du cycle de vie des conteneurs (features/container-actions.js, #104/#105), contre un vrai
 * serveur sans Docker : droits, validation des entrees, reponse structuree (aucun etat invente).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctlroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ctlroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3961, BASE = `http://127.0.0.1:${PORT}`;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

function req(method, p, cookie, body) {
  return new Promise(resolve => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) },
      timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, body: b }); } });
    });
    r.on('error', e => resolve({ status: 0, body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
    if (data) r.write(data);
    r.end();
  });
}

function login(username, password) {
  return new Promise(resolve => {
    const b = `username=${username}&password=${password}`;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } },
      res => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    r.on('error', () => resolve({ status: 0, cookie: '' }));
    r.write(b); r.end();
  });
}

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));
  const ck = (await login('admin', 'admin123')).cookie;
  const vk = (await login('viewer', 'viewer123')).cookie;
  console.log('\nroutes du cycle de vie des conteneurs, contre un vrai serveur');

  const paths = [['GET', '/api/managed-containers/overview'], ['GET', '/api/managed-containers/status?id=waf'],
    ['POST', '/api/managed-containers/action', { id: 'waf', action: 'stop' }], ['POST', '/api/managed-containers/update-all', {}]];
  for (const [m, p, b] of paths) {
    const a = await req(m, p, '', b), v = await req(m, p, vk, b);
    check(`${m} ${p.split('?')[0]} : sans session / viewer -> refuse`, () => {
      assert.ok([401, 403].includes(a.status)); assert.ok([401, 403].includes(v.status));
    });
  }

  const ov = await req('GET', '/api/managed-containers/overview', ck);
  check('overview : liste toutes les integrations declarees', () => {
    assert.strictEqual(ov.status, 200);
    const ids = ov.body.containers.map((c) => c.id);
    for (const id of ['waf', 'analyzer', 'shipper', 'certbot', 'certbot-dns', 'geoipupdate', 'error-pages', 'challenge', 'godns']) assert.ok(ids.includes(id), id);
  });
  const un = await req('GET', '/api/managed-containers/status?id=nexiste-pas', ck);
  const pr = await req('GET', '/api/managed-containers/status?id=__proto__', ck);
  check('status : id inconnu / __proto__ -> 400', () => { assert.strictEqual(un.status, 400); assert.strictEqual(pr.status, 400); });
  const badId = await req('POST', '/api/managed-containers/action', ck, { id: 'nexiste-pas', action: 'stop' });
  const noId = await req('POST', '/api/managed-containers/action', ck, { action: 'stop' });
  const badAct = await req('POST', '/api/managed-containers/action', ck, { id: 'waf', action: 'rm -rf' });
  check('action : id inconnu, id absent, action inconnue -> 400', () => {
    assert.strictEqual(badId.status, 400); assert.strictEqual(noId.status, 400); assert.strictEqual(badAct.status, 400);
  });
  const dis = await req('POST', '/api/managed-containers/action', ck, { id: 'waf', action: 'start' });
  check('action sur integration desactivee -> refus explicite (409 ou 503 sans Docker), jamais 200', () => {
    assert.ok([409, 503].includes(dis.status), String(dis.status));
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
