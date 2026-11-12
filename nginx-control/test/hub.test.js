'use strict';
/** Hub (v12.76.0) : résumé, sauvegarde pull/push, secrets exclus, chiffrement, tar valide. */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');
const { spawn, execFileSync } = require('child_process');
const http = require('http');
const backup = require('../lib/hub-backup');
const hubSettings = require('../lib/hub-settings');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hub-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hub-data-'));
for (const d of ['lib', 'features', 'public']) fs.cpSync(path.join(root, d), path.join(appDir, d), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip']) fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'), 'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');
fs.writeFileSync(path.join(tmp, 'config', 'challenge.yml'), 'challenge_enable: true\n');
fs.writeFileSync(path.join(tmp, 'config', 'smtp.yml'), 'password: SUPERSECRET\n');
fs.writeFileSync(path.join(tmp, 'config', 'mfa.json'), '{"users":{"a":{"totp":{"secret":"TOPSECRET"}}}}');
fs.writeFileSync(path.join(tmp, 'sites', 'a.conf'), 'server { listen 80; server_name a.example.com; }\n');
fs.writeFileSync(path.join(tmp, 'ssl', 'x.key'), 'PRIVATEKEY');
fs.symlinkSync('/etc/passwd', path.join(tmp, 'sites', 'evil.conf'));

const dirs = { nginx: [path.join(tmp, 'sites'), path.join(tmp, 'conf')], config: path.join(tmp, 'config'), ssl: path.join(tmp, 'ssl') };
const unpack = (buf) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hub-x-')); const f = path.join(d, 'a.tgz'); fs.writeFileSync(f, buf); execFileSync('tar', ['-xzf', f, '-C', d]); return d; };

const PORT = 3941, HUBPORT = 3942, TOKEN = 'tok-' + crypto.randomBytes(8).toString('hex'), BTOKEN = 'btok-' + crypto.randomBytes(8).toString('hex');
const env = { ...process.env, PORT: String(PORT), USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'), DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'), DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'), DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip'),
  HUB_TOKEN_SHA256: sha(TOKEN), HUB_BACKUP_TOKEN_SHA256: sha(BTOKEN), HUB_PUSH_TOKEN: 'push-secret', HUB_BACKUP_PASSPHRASE: '' };

function req(method, p, { headers, body, port = PORT, raw } = {}) {
  return new Promise(resolve => {
    const r = http.request({ host: '127.0.0.1', port, path: p, method, headers: { ...(headers || {}), ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) }, timeout: 8000 }, res => {
      const ch = []; res.on('data', d => ch.push(d));
      res.on('end', () => { const b = Buffer.concat(ch); let j = null; try { j = JSON.parse(b.toString()); } catch { /* binaire */ } resolve({ status: res.statusCode, json: j, buf: b, headers: res.headers }); });
    });
    r.on('error', e => resolve({ status: 0, json: { error: e.message } }));
    if (body) r.write(body); r.end();
  });
}
const writeHubYml = (t) => fs.writeFileSync(path.join(tmp, 'config', 'hub.yml'), t);

(async () => {
  await check('collecte : secrets exclus par défaut, symlink ignoré, env masqué', () => {
    const b = backup.build({ dirs, include: ['nginx', 'ngxops', 'env', 'ssl'], includeSecrets: false, passphrase: '', retentionDays: 30, instance: { id: 'x' } });
    const names = b.manifest.files.map(f => f.path);
    assert.ok(names.includes('nginx/sites/a.conf') && names.includes('ngxops/challenge.yml') && names.includes('env/effective-env.json'));
    for (const n of ['ngxops/users.yml', 'ngxops/smtp.yml', 'ngxops/mfa.json', 'ssl/x.key']) assert.ok(!names.includes(n), n + ' ne doit pas être inclus');
    assert.ok(b.manifest.excluded_secrets.includes('ngxops/users.yml'));
    assert.ok(!names.some(n => n.includes('evil.conf')) && b.manifest.skipped.some(s => s.reason === 'symlink'));
  });
  await check('aucun secret en clair dans l\'archive par défaut', () => {
    const b = backup.build({ dirs, include: ['nginx', 'ngxops', 'env', 'ssl'], includeSecrets: false, passphrase: '', retentionDays: 30, instance: {} });
    const x = unpack(b.archive);
    let found = ''; try { found = execFileSync('grep', ['-r', '-l', 'SUPERSECRET\\|TOPSECRET\\|PRIVATEKEY', x]).toString(); } catch { /* aucun */ }
    assert.strictEqual(found, '');
    const man = JSON.parse(fs.readFileSync(path.join(x, 'manifest.json'), 'utf8'));
    assert.strictEqual(man.files.length, b.manifest.files.length);
    for (const f of man.files) assert.strictEqual(sha(fs.readFileSync(path.join(x, f.path))), f.sha256);
  });
  await check('include_secrets exige une phrase de passe ; archive chiffrée et déchiffrable', () => {
    assert.throws(() => backup.build({ dirs, include: ['ngxops'], includeSecrets: true, passphrase: '', retentionDays: 30, instance: {} }), /PASSPHRASE/);
    const b = backup.build({ dirs, include: ['ngxops', 'ssl'], includeSecrets: true, passphrase: 'correct horse', retentionDays: 7, instance: {} });
    assert.ok(b.manifest.encrypted && b.manifest.includes_secrets);
    assert.ok(!b.archive.toString('latin1').includes('SUPERSECRET'));
    assert.throws(() => backup.decrypt(b.archive, 'mauvaise'));
    const x = unpack(backup.decrypt(b.archive, 'correct horse'));
    assert.ok(fs.readFileSync(path.join(x, 'ngxops/smtp.yml'), 'utf8').includes('SUPERSECRET'));
    assert.ok(fs.existsSync(path.join(x, 'ssl/x.key')));
  });
  await check('réglages : URL du Hub validée, rétention bornée, défauts sûrs', () => {
    assert.strictEqual(hubSettings.validHubUrl('https://user:pw@hub/'), null);
    assert.strictEqual(hubSettings.validHubUrl('file:///etc/passwd'), null);
    assert.strictEqual(hubSettings.validHubUrl('https://hub.example.com/'), 'https://hub.example.com');
    assert.strictEqual(hubSettings.parseHashes('zz,' + sha('a')).length, 1);
  });

  // — faux Hub (push) —
  let received = null;
  const hub = http.createServer((q, s) => {
    const ch = []; q.on('data', d => ch.push(d));
    q.on('end', () => { received = { headers: q.headers, url: q.url, body: Buffer.concat(ch) }; s.writeHead(q.headers.authorization === 'Bearer push-secret' ? 201 : 401, { 'Content-Type': 'application/json' }); s.end(JSON.stringify({ id: 'bk_1' })); });
  });
  await new Promise(r => hub.listen(HUBPORT, '127.0.0.1', r));

  const srv = spawn('node', [path.join(appDir, 'server.js')], { env, stdio: 'ignore' });
  for (let i = 0; i < 50; i++) { const r = await req('GET', '/auth/login'); if (r.status === 200) break; await new Promise(r => setTimeout(r, 200)); }
  try {
    await check('résumé : 401 sans jeton, 200 avec, schéma et pas de secret', async () => {
      assert.strictEqual((await req('GET', '/api/hub/v1/summary')).status, 401);
      assert.strictEqual((await req('GET', '/api/hub/v1/summary', { headers: { 'X-Hub-Token': 'faux' } })).status, 401);
      const r = await req('GET', '/api/hub/v1/summary', { headers: { 'X-Hub-Token': TOKEN } });
      assert.strictEqual(r.status, 200); assert.strictEqual(r.json.schema, 1);
      assert.ok(r.json.instance.version && r.json.nginx && r.json.alerts);
      assert.ok(!JSON.stringify(r.json).includes('push-secret'));
    });
    await check('alertes / sécurité : jeton requis, forme stable, aucune IP par défaut', async () => {
      assert.strictEqual((await req('GET', '/api/hub/v1/alerts')).status, 401);
      assert.strictEqual((await req('GET', '/api/hub/v1/security', { headers: { 'X-Hub-Token': 'faux' } })).status, 401);
      const a = await req('GET', '/api/hub/v1/alerts?limit=5&severity=high&acked=0', { headers: { 'X-Hub-Token': TOKEN } });
      assert.strictEqual(a.status, 200); assert.strictEqual(a.json.schema, 1); assert.strictEqual(a.json.expose_ips, false);
      assert.ok(Array.isArray(a.json.alerts));
      assert.strictEqual((await req('GET', '/api/hub/v1/alerts', { headers: { 'X-Hub-Token': BTOKEN } })).status, 401);
    });
    await check('modules : jeton requis, forme stable, aucun secret, IP absentes par défaut', async () => {
      for (const m of ['inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports']) {
        assert.strictEqual((await req('GET', '/api/hub/v1/' + m)).status, 401, m);
        const r = await req('GET', '/api/hub/v1/' + m + '?hours=6', { headers: { 'X-Hub-Token': TOKEN } });
        assert.strictEqual(r.status, 200, m + ' ' + r.raw);
        assert.strictEqual(r.json.module, m); assert.strictEqual(r.json.schema, 1); assert.ok(r.json.data && r.json.errors && r.json.instance.id);
        assert.ok(!/SUPERSECRET|TOPSECRET|push-secret|PRIVATEKEY/.test(JSON.stringify(r.json)), m);
      }
      const inv = await req('GET', '/api/hub/v1/inventory', { headers: { 'X-Hub-Token': TOKEN } });
      assert.ok(JSON.stringify(inv.json.data.vhosts).includes('a.example.com'), 'vhost de l inventaire');
      assert.ok(inv.json.data.nginx && 'running' in inv.json.data.nginx);
      assert.strictEqual((await req('GET', '/api/hub/v1/indicators', { headers: { 'X-Hub-Token': TOKEN } })).status, 403);   // expose_ips: false
      assert.strictEqual((await req('GET', '/api/hub/v1/inconnu', { headers: { 'X-Hub-Token': TOKEN } })).status, 404);
      assert.strictEqual((await req('GET', '/api/hub/v1/inventory', { headers: { 'X-Hub-Token': BTOKEN } })).status, 401);
    });
    await check('expose_ips + expose_modules : indicators ouvert, module retiré = 404', async () => {
      writeHubYml('expose_ips: true\nexpose_modules: [inventory, indicators]\n');
      await new Promise(r => setTimeout(r, 100));
      const ind = await req('GET', '/api/hub/v1/indicators?hours=1', { headers: { 'X-Hub-Token': TOKEN } });
      assert.strictEqual(ind.status, 200); assert.strictEqual(ind.json.expose_ips, true); assert.ok(Array.isArray(ind.json.data.indicators));
      assert.strictEqual((await req('GET', '/api/hub/v1/traffic', { headers: { 'X-Hub-Token': TOKEN } })).status, 404);
      assert.strictEqual((await req('GET', '/api/hub/v1/alerts', { headers: { 'X-Hub-Token': TOKEN } })).json.expose_ips, true);
      writeHubYml('');
    });
    await check('le jeton de résumé ne donne pas accès aux sauvegardes (et inversement)', async () => {
      assert.strictEqual((await req('GET', '/api/hub/v1/backup/manifest', { headers: { 'X-Hub-Token': TOKEN } })).status, 404); // backup_enable=false
      writeHubYml('backup_enable: true\nbackup_include: [nginx, ngxops, env]\nretention_days: 14\n');
      assert.strictEqual((await req('GET', '/api/hub/v1/backup/manifest', { headers: { 'X-Hub-Token': TOKEN } })).status, 401);
      assert.strictEqual((await req('GET', '/api/hub/v1/summary', { headers: { 'X-Hub-Token': BTOKEN } })).status, 401);
    });
    await check('pull : manifeste + archive cohérents (sha256), secrets absents', async () => {
      const m = await req('GET', '/api/hub/v1/backup/manifest', { headers: { 'X-Hub-Token': BTOKEN } });
      assert.strictEqual(m.status, 200); assert.strictEqual(m.json.retention_days, 14); assert.ok(m.json.excluded_secrets.length >= 3);
      const a = await req('GET', '/api/hub/v1/backup/archive', { headers: { 'X-Hub-Token': BTOKEN } });
      assert.strictEqual(a.status, 200); assert.strictEqual(sha(a.buf), m.json.archive_sha256); assert.strictEqual(a.headers['x-backup-encrypted'], '0');
      assert.ok(!a.buf.length || !zlib.gunzipSync(a.buf).toString('latin1').includes('SUPERSECRET'));
    });
    await check('méthode non GET et chemin inconnu → 404', async () => {
      assert.strictEqual((await req('POST', '/api/hub/v1/summary', { headers: { 'X-Hub-Token': TOKEN } })).status, 404);
      assert.strictEqual((await req('GET', '/api/hub/v1/nope', { headers: { 'X-Hub-Token': TOKEN } })).status, 404);
    });
    await check('push : refusé tant que non configuré, puis envoyé au Hub avec en-têtes attendus', async () => {
      const login = await new Promise(res => { const b = 'username=admin&password=admin123'; const r = http.request({ host: '127.0.0.1', port: PORT, path: '/auth/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': b.length } }, x => res((x.headers['set-cookie'] || [''])[0].split(';')[0])); r.write(b); r.end(); });
      const p0 = await req('POST', '/api/hub/backup/push', { headers: { Cookie: login, 'Content-Type': 'application/json' }, body: '{}' });
      assert.strictEqual(p0.status, 502); assert.ok(/hub_url/.test(p0.json.message));
      writeHubYml(`backup_enable: true\nhub_url: http://127.0.0.1:${HUBPORT}\nretention_days: 14\n`);
      const p1 = await req('POST', '/api/hub/backup/push', { headers: { Cookie: login, 'Content-Type': 'application/json' }, body: '{}' });
      assert.strictEqual(p1.status, 200, JSON.stringify(p1.json)); assert.strictEqual(p1.json.id, 'bk_1');
      assert.strictEqual(received.url, '/api/hub/v1/backups'); assert.strictEqual(received.headers['x-backup-sha256'], sha(received.body));
      assert.strictEqual(received.headers['x-retention-days'], '14');
      const st = await req('GET', '/api/hub/status', { headers: { Cookie: login, 'Content-Type': 'application/json' }, body: '{}' });
      assert.strictEqual(st.json.lastPush.ok, true); assert.ok(!JSON.stringify(st.json).includes('push-secret'));
      assert.strictEqual((await req('POST', '/api/hub/backup/push', { headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
    });
  } finally { srv.kill(); hub.close(); }
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
