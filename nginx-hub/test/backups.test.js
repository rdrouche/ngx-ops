'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const zlib = require('node:zlib');
const fs = require('node:fs');
const { createHash, randomBytes } = require('node:crypto');
const { makeApp, client } = require('./helpers');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const sha = (b) => createHash('sha256').update(b).digest('hex');

/** tar ustar minimal : manifest.json en premier, puis un fichier de conf. */
function tarEntry(name, content) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 'latin1'); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(content.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
  let sum = 0; for (const b of h) sum += b; h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (content.length % 512)) % 512);
  return Buffer.concat([h, content, pad]);
}
function makeArchive(extra = 'x') {
  const manifest = { schema: 1, generated_at: new Date().toISOString(), instance: { id: 'srv-1' }, retention_days: 90, encrypted: false, includes_secrets: false,
    files: [{ path: 'nginx/conf/a.conf', size: 10, sha256: 'a'.repeat(64), category: 'nginx', secret: false }, { path: 'ngxops/x.yml', size: 5, sha256: 'b'.repeat(64), category: 'ngxops', secret: false }],
    excluded_secrets: ['users.yml'], skipped: [] };
  const tar = Buffer.concat([tarEntry('manifest.json', Buffer.from(JSON.stringify(manifest))), tarEntry('nginx/conf/a.conf', Buffer.from('server {} ' + extra)), Buffer.alloc(1024)]);
  return zlib.gzipSync(tar);
}
function makeEncrypted() { return Buffer.concat([Buffer.from('NGXB1'), randomBytes(16 + 12 + 200 + 16)]); }

async function setup(over = {}) {
  const env = await makeApp(over);
  await env.users.create({ username: 'root', password: PW, role: 'admin' });
  await env.users.create({ username: 'lecteur', password: PW, role: 'viewer' });
  const admin = client(env.base); await admin.post(`${P}/auth/login`, { username: 'root', password: PW });
  const viewer = client(env.base); await viewer.post(`${P}/auth/login`, { username: 'lecteur', password: PW });
  const inst = (await admin.post(`${P}/instances`, { name: 'Paris', url: 'http://127.0.0.1:9' })).json.instance;
  return { ...env, admin, viewer, inst };
}
const push = (base, token, body, h = {}) => fetch(base + `${P}/backups`, {
  method: 'POST', body,
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream', 'X-Backup-Sha256': sha(body), 'X-Backup-Encrypted': '0', 'X-Backup-Files': '2', 'X-Retention-Days': '90', 'X-Dashboard-Version': '12.76.0', 'X-Instance-Id': 'srv-1', ...h },
});

test('push : jeton généré une fois, archive stockée, doublon dédupliqué, rétention plafonnée par le Hub', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const tk = await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`);
  assert.equal(tk.status, 201); assert.match(tk.json.token_once, /^hubp_/);
  const token = tk.json.token_once;
  const body = makeArchive();

  const r1 = await push(e.base, token, body);
  assert.equal(r1.status, 201); const j1 = await r1.json(); assert.match(j1.id, /^bk_/); assert.equal(j1.duplicate, false);
  const r2 = await push(e.base, token, body);
  assert.equal(r2.status, 200); assert.equal((await r2.json()).id, j1.id, 'même archive → même enregistrement');

  const list = await e.admin.get(`${P}/instances/${e.inst.id}/backups`);
  assert.equal(list.json.items.length, 1);
  const b = list.json.items[0];
  assert.equal(b.sha256, sha(body)); assert.equal(b.size_bytes, body.length); assert.equal(b.encrypted, false); assert.equal(b.dashboard_version, '12.76.0');
  assert.equal(b.manifest.files, 2); assert.deepEqual(b.manifest.categories, { nginx: 1, ngxops: 1 });
  // rétention demandée 90 j, plafond Hub 30 j → 30 j
  assert.ok(Math.abs((b.expires_at - b.received_at) - 30 * 86400e3) < 5000);
  assert.ok(!JSON.stringify(list.json).includes(token), 'le jeton n\'est jamais renvoyé');
  assert.equal(list.json.instance.push_enabled, true); assert.ok(list.json.instance.last_backup_at);
});

test('push : refus (jeton, SHA-256, format, taille, type, chiffrement incohérent)', async (t) => {
  const e = await setup({ backups: { max_archive_mb: 1 } }); t.after(() => e.app.stop());
  const token = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`)).json.token_once;
  const body = makeArchive();

  assert.equal((await push(e.base, 'hubp_mauvaisjetonmauvaisjeton', body)).status, 401);
  assert.equal((await fetch(e.base + `${P}/backups`, { method: 'POST', body })).status, 401);
  assert.equal((await push(e.base, token, body, { 'X-Backup-Sha256': 'a'.repeat(64) })).status, 422, 'SHA-256 différent');
  assert.equal((await push(e.base, token, body, { 'X-Backup-Sha256': 'zz' })).status, 400);
  assert.equal((await push(e.base, token, Buffer.from('pas une archive'))).status, 422, 'ni gzip ni NGXB1');
  assert.equal((await push(e.base, token, body, { 'X-Backup-Encrypted': '1' })).status, 422, 'déclaré chiffré mais gzip');
  assert.equal((await push(e.base, token, makeEncrypted(), { 'X-Backup-Encrypted': '0' })).status, 422, 'chiffré non déclaré');
  assert.equal((await push(e.base, token, body, { 'Content-Type': 'application/json' })).status, 415);
  assert.equal((await push(e.base, token, Buffer.alloc(2 * 1024 * 1024, 1))).status, 413, 'au-delà de max_archive_mb');
  assert.equal((await e.admin.get(`${P}/instances/${e.inst.id}/backups`)).json.items.length, 0, 'rien de stocké après les refus');
  assert.deepEqual(fs.readdirSync(e.app.ctx.services.get('backups').blobs.tmpDir), [], 'aucun temporaire résiduel');
});

test('archive chiffrée : stockée opaque, sans manifeste lisible ; téléchargement admin identique, viewer refusé', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const token = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`)).json.token_once;
  const enc = makeEncrypted();
  const r = await push(e.base, token, enc, { 'X-Backup-Encrypted': '1' });
  assert.equal(r.status, 201); const { id } = await r.json();
  const meta = (await e.admin.get(`${P}/backups/${id}`)).json;
  assert.equal(meta.encrypted, true); assert.equal(meta.manifest, null);

  const dl = await fetch(e.base + `${P}/backups/${id}/download`, { headers: { Cookie: e.admin.st.cookie } });
  assert.equal(dl.status, 200);
  assert.equal(dl.headers.get('x-backup-sha256'), sha(enc)); assert.equal(dl.headers.get('x-backup-encrypted'), '1');
  assert.match(dl.headers.get('content-disposition'), /paris-\d{8}-\d{6}\.ngxb/);
  assert.ok(Buffer.from(await dl.arrayBuffer()).equals(enc));

  assert.equal((await e.viewer.get(`${P}/backups/${id}/download`)).status, 403, 'viewer : pas de téléchargement');
  assert.equal((await e.viewer.get(`${P}/backups/${id}`)).status, 200, 'viewer : consultation des métadonnées');
  assert.equal((await e.admin.get(`${P}/backups/bk_../download`)).status, 404);
  assert.equal((await e.admin.get(`${P}/backups/..%2f..%2fetc%2fpasswd/download`)).status, 404);
  const audit = (await e.admin.get(`${P}/audit`)).json.items.map((a) => a.action);
  assert.ok(audit.includes('backup.download') && audit.includes('backup.received'));
});

test('suppression : le blob n\'est retiré qu\'à la dernière référence ; jeton révoqué → push refusé', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const bk = e.app.ctx.services.get('backups');
  const inst2 = (await e.admin.post(`${P}/instances`, { name: 'Lyon', url: 'http://127.0.0.1:9' })).json.instance;
  const t1 = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`)).json.token_once;
  const t2 = (await e.admin.post(`${P}/instances/${inst2.id}/backups/push-token`)).json.token_once;
  const body = makeArchive('commun');
  const a = await (await push(e.base, t1, body)).json(); const b = await (await push(e.base, t2, body)).json();
  assert.notEqual(a.id, b.id, 'un enregistrement par instance');
  assert.equal(fs.readdirSync(`${bk.blobs.dir}/${sha(body).slice(0, 2)}`).length, 1, 'un seul blob pour deux instances');

  assert.equal((await e.admin.del(`${P}/backups/${a.id}`)).status, 200);
  assert.ok(await bk.blobs.has(sha(body)), 'encore référencé par Lyon');
  assert.equal((await e.admin.del(`${P}/backups/${b.id}`)).status, 200);
  assert.ok(!(await bk.blobs.has(sha(body))), 'plus aucune référence → supprimé');

  assert.equal((await e.admin.del(`${P}/instances/${e.inst.id}/backups/push-token`)).status, 200);
  assert.equal((await push(e.base, t1, body)).status, 401, 'jeton révoqué');
  assert.equal((await e.viewer.del(`${P}/backups/${a.id}`)).status, 403);
});

test('rétention : expirées purgées, blobs orphelins ramassés', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const bk = e.app.ctx.services.get('backups');
  const token = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`)).json.token_once;
  const body = makeArchive('vieux');
  await push(e.base, token, body);
  await e.app.ctx.db.run('UPDATE backups SET expires_at = ?', [Date.now() - 1000]);
  await bk.blobs.gc(await bk.repo.referencedShas(), 0); // encore référencé (ligne non purgée)
  assert.ok(await bk.blobs.has(sha(body)));
  await bk.repo.deleteExpired(Date.now());
  assert.equal(await bk.blobs.gc(await bk.repo.referencedShas(), 0), 1, 'blob orphelin supprimé');
  assert.equal((await e.admin.get(`${P}/instances/${e.inst.id}/backups`)).json.items.length, 0);
});

test('alerte d\'absence : en retard après N heures, levée par un nouvel envoi ; visible dans la vue d\'ensemble', async (t) => {
  const e = await setup({ backups: { alert_after_hours: 36 } }); t.after(() => e.app.stop());
  const token = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/push-token`)).json.token_once;
  let ov = (await e.admin.get(`${P}/overview`)).json.backups;
  assert.equal(ov.expected, 1); assert.equal(ov.late.length, 0, 'délai de grâce depuis la configuration');

  await e.app.ctx.db.run('UPDATE instances SET backup_expected_since = ?', [Date.now() - 40 * 3600e3]);
  ov = (await e.admin.get(`${P}/overview`)).json.backups;
  assert.equal(ov.late.length, 1); assert.equal(ov.late[0].name, 'Paris');

  await push(e.base, token, makeArchive('frais'));
  ov = (await e.admin.get(`${P}/overview`)).json.backups;
  assert.equal(ov.late.length, 0); assert.equal(ov.ok, 1);
  await e.app.ctx.db.run('UPDATE instances SET last_backup_at = ?', [Date.now() - 37 * 3600e3]);
  assert.equal((await e.admin.get(`${P}/overview`)).json.backups.late.length, 1);
  assert.equal((await e.admin.get(`${P}/backups`)).json.items[0].late, true);
});

/** Faux dashboard : routes backup/manifest et backup/archive (jeton X-Hub-Token propre). */
function fakeBackupDashboard({ token, archive, encrypted = false, lie = false, status = 200 }) {
  const srv = http.createServer((req, res) => {
    if (req.headers['x-hub-token'] !== token) { res.writeHead(401); return res.end(); }
    if (status !== 200) { res.writeHead(status); return res.end(); }
    if (req.url === '/api/hub/v1/backup/manifest') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ archive_sha256: sha(archive), archive_bytes: archive.length, retention_days: 7 }));
    }
    if (req.url === '/api/hub/v1/backup/archive') {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'X-Backup-Sha256': lie ? 'f'.repeat(64) : sha(archive), 'X-Backup-Encrypted': encrypted ? '1' : '0' });
      return res.end(archive);
    }
    res.writeHead(404); return res.end();
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); }) })));
}

test('pull : manifeste + archive vérifiés, doublon sans retéléchargement, échecs normalisés', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const archive = makeArchive('pull');
  const dash = await fakeBackupDashboard({ token: 'placeholder', archive }); t.after(() => dash.close());
  await e.app.ctx.db.run('UPDATE instances SET base_url = ? WHERE id = ?', [dash.url, e.inst.id]);
  assert.equal((await e.admin.post(`${P}/instances/${e.inst.id}/backups/pull`)).status, 409, 'pas de jeton de pull configuré');

  const tk = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/pull-token`)).json;
  assert.match(tk.token_once, /^hubb_/); assert.equal(tk.token_sha256, sha(tk.token_once));
  const bk = e.app.ctx.services.get('backups');

  // mauvais jeton côté dashboard
  assert.equal((await e.admin.post(`${P}/instances/${e.inst.id}/backups/pull`)).json.error, 'auth_failed');
  assert.equal((await e.admin.get(`${P}/instances/${e.inst.id}/backups`)).json.instance.last_error, 'auth_failed');

  await dash.close();
  const dash2 = await fakeBackupDashboard({ token: tk.token_once, archive }); t.after(() => dash2.close());
  await e.app.ctx.db.run('UPDATE instances SET base_url = ? WHERE id = ?', [dash2.url, e.inst.id]);
  const r1 = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/pull`)).json;
  assert.equal(r1.ok, true); assert.equal(r1.duplicate, false);
  const r2 = await bk.pullOne(e.inst.id);
  assert.equal(r2.ok, true); assert.equal(r2.duplicate, true); assert.equal(r2.id, r1.id);
  const row = (await e.admin.get(`${P}/instances/${e.inst.id}/backups`)).json;
  assert.equal(row.items.length, 1); assert.equal(row.items[0].source, 'pull'); assert.equal(row.items[0].retention_days, 7); assert.equal(row.instance.last_error, null);
  assert.ok(!JSON.stringify(row).includes(tk.token_once));
});

test('pull : en-tête SHA-256 mensonger → rejeté, rien de stocké ; dashboard en 429 → rate_limited ; sans jeton de pull, pas de pull planifié', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const tk = (await e.admin.post(`${P}/instances/${e.inst.id}/backups/pull-token`)).json.token_once;
  const bk = e.app.ctx.services.get('backups');
  const liar = await fakeBackupDashboard({ token: tk, archive: makeArchive('menteur'), lie: true }); t.after(() => liar.close());
  await e.app.ctx.db.run('UPDATE instances SET base_url = ? WHERE id = ?', [liar.url, e.inst.id]);
  assert.equal((await bk.pullOne(e.inst.id)).error, 'checksum_mismatch');
  assert.equal((await e.admin.get(`${P}/instances/${e.inst.id}/backups`)).json.items.length, 0);
  assert.deepEqual(fs.readdirSync(bk.blobs.tmpDir), []);

  const busy = await fakeBackupDashboard({ token: tk, archive: makeArchive(), status: 429 }); t.after(() => busy.close());
  await e.app.ctx.db.run('UPDATE instances SET base_url = ? WHERE id = ?', [busy.url, e.inst.id]);
  assert.equal((await bk.pullOne(e.inst.id)).error, 'rate_limited');

  assert.equal((await e.admin.del(`${P}/instances/${e.inst.id}/backups/pull-token`)).status, 200);
  assert.deepEqual(await bk.repo.pullCandidates(), []);
});

test('la feature backups est désactivable : routes absentes, vue d\'ensemble sans bloc backups', async (t) => {
  const e = await makeApp({ features: { backups: false } }); t.after(() => e.app.stop());
  await e.users.create({ username: 'root', password: PW, role: 'admin' });
  const a = client(e.base); await a.post(`${P}/auth/login`, { username: 'root', password: PW });
  assert.equal((await a.get(`${P}/backups`)).status, 404);
  assert.equal((await a.get(`${P}/overview`)).json.backups, null);
});
