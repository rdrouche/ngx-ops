'use strict';
/**
 * Routes des formulaires de configuration (features/config-forms.js, #102/#103), contre un
 * vrai serveur — meme convention que les autres *-routes.test.js. Point
 * central a verifier ici : une cle inconnue ne doit jamais resoudre un
 * chemin, et le contenu ecrit doit reellement se retrouver sur le disque
 * (contrairement aux autres features, celle-ci n a pas de garde-fou
 * "not enabled" — le test porte sur le fichier, pas sur un conteneur).
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgformsroutes-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgformsroutes-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: viewer\n    password: viewer123\n    role: viewer\n    name: V\n    enabled: true\n');

const PORT = 3953, BASE = `http://127.0.0.1:${PORT}`;
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
  console.log('\nroutes des formulaires de configuration, contre un vrai serveur');
  const file = path.join(tmp, 'config', 'certbot.yml');

  const noAuth = await req('GET', '/api/config-forms?key=certbot', '');
  check('sans session -> refuse', () => assert.ok([401, 403].includes(noAuth.status)));
  const viewer = await req('GET', '/api/config-forms?key=certbot', vk);
  check('role viewer -> refuse', () => assert.ok([401, 403].includes(viewer.status)));
  const viewerPaths = await req('GET', '/api/system/paths', vk);
  check('chemins : role viewer -> refuse', () => assert.ok([401, 403].includes(viewerPaths.status)));

  const unk = await req('GET', '/api/config-forms?key=nexiste-pas', ck);
  const proto = await req('GET', '/api/config-forms?key=__proto__', ck);
  const unkPut = await req('PUT', '/api/config-forms', ck, { key: '../../etc/passwd', values: {} });
  check('cle inconnue -> 400', () => assert.strictEqual(unk.status, 400));
  check('__proto__ -> 400', () => assert.strictEqual(proto.status, 400));
  check('ecriture cle inconnue -> 400', () => assert.strictEqual(unkPut.status, 400));

  const g = await req('GET', '/api/config-forms?key=certbot', ck);
  check('schema certbot : champs, valeurs vides, fichier absent', () => {
    assert.strictEqual(g.status, 200); assert.strictEqual(g.body.exists, false);
    assert.ok(g.body.fields.some((f) => f.key === 'webroot_host_path' && f.suggest === 'webroot'));
    assert.ok(!JSON.stringify(g.body.fields).includes('pattern'));
  });

  fs.writeFileSync(file, '# mon commentaire\nenable: false\nautre_cle: garde\n');
  const put = await req('PUT', '/api/config-forms', ck, { key: 'certbot', values: { enable: true, email: 'a@b.fr', webroot_host_path: '/containers/ngx-ops/nginx/webroot' } });
  check('ecriture ok, commentaires et cles inconnues conserves, mode 0600', () => {
    assert.strictEqual(put.status, 200);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), '# mon commentaire\nenable: true\nautre_cle: garde\nemail: a@b.fr\nwebroot_host_path: /containers/ngx-ops/nginx/webroot\n');
    if (process.platform !== 'win32' && !/^\/mnt\//.test(file)) assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  });
  const before = fs.readFileSync(file, 'utf8');
  const bad = await req('PUT', '/api/config-forms', ck, { key: 'certbot', values: { webroot_host_path: 'relatif', email: 'pas-un-mail' } });
  check('valeurs invalides -> 400 avec erreurs par champ, fichier intact', () => {
    assert.strictEqual(bad.status, 400); assert.ok(bad.body.errors.webroot_host_path && bad.body.errors.email);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), before);
  });

  const ksFile = path.join(tmp, 'config', 'geoipupdate.yml');
  const sec = await req('PUT', '/api/config-forms', ck, { key: 'geoipupdate', values: { license_key: 'cle-secrete-123456', account_id: '12345' } });
  const gs = await req('GET', '/api/config-forms?key=geoipupdate', ck);
  check('secret ecrit mais jamais renvoye', () => {
    assert.strictEqual(sec.status, 200); assert.ok(fs.readFileSync(ksFile, 'utf8').includes('license_key: cle-secrete-123456'));
    assert.strictEqual(gs.body.secretSet.license_key, true); assert.ok(!JSON.stringify(gs.body).includes('cle-secrete-123456'));
  });

  const ded = await req('GET', '/api/config-forms?key=logstore', ck);
  const pend = await req('GET', '/api/config-forms?key=deploy-tokens', ck);
  const pendPut = await req('PUT', '/api/config-forms', ck, { key: 'deploy-tokens', values: {} });
  check('dedie / en attente : pas de champs, ecriture refusee', () => {
    assert.strictEqual(ded.body.dedicated, 'logstore'); assert.strictEqual(pend.body.pending, true); assert.strictEqual(pendPut.status, 400);
  });

  const ch1 = await req('PUT', '/api/config-forms', ck, { key: 'challenge', values: { challenge_enable: true, difficulty_bits: 18 } });
  const ch2 = await req('PUT', '/api/config-forms', ck, { key: 'challenge', values: { difficulty_bits: 20 } });
  check('challenge : cle challenge_* modifiee -> regenerateChallenge ; cle du conteneur seule -> pas de rappel', () => {
    assert.strictEqual(ch1.body.regenerateChallenge, true); assert.strictEqual(ch2.body.regenerateChallenge, undefined);
  });
  const chBad = await req('PUT', '/api/config-forms', ck, { key: 'challenge', values: { difficulty_bits: 99, challenge_engine: 'x' } });
  check('challenge : bornes et enum refuses', () => { assert.strictEqual(chBad.status, 400); assert.ok(chBad.body.errors.difficulty_bits && chBad.body.errors.challenge_engine); });

  const paths = await req('GET', '/api/system/paths', ck);
  check('chemins : reponse structuree meme sans Docker (aucune valeur inventee)', () => {
    assert.strictEqual(paths.status, 200); assert.ok(Array.isArray(paths.body.mounts)); assert.strictEqual(typeof paths.body.available, 'boolean');
    if (!paths.body.available) assert.deepStrictEqual(paths.body.suggestions, {});
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
