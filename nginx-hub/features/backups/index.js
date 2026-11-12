'use strict';
/**
 * Feature backups (contrat Hub ↔ dashboard v12.76.0, §2–§3) :
 *   - PUSH  : POST /api/hub/v1/backups (jeton Bearer par instance, flux borné, SHA-256 vérifié, déduplication, rétention) ;
 *   - PULL  : le Hub va chercher manifest + archive des instances qui ont un jeton de pull (planifié, ou à la demande) ;
 *   - alerte si une instance (sauvegarde attendue) n'a rien envoyé depuis N heures ;
 *   - consultation et TÉLÉCHARGEMENT (admin). Pas de restauration (phase 2 : écriture = confirmation, sauvegarde préalable, nginx -t).
 * Les archives sont stockées telles quelles, adressées par SHA-256, hors base. Le Hub ne connaît JAMAIS la phrase de passe :
 * une archive chiffrée est un blob opaque. Aucun fichier d'archive n'est extrait ni décompressé en entier.
 */
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { API_PREFIX } = require('../../lib/config');
const { randomToken, sha256: sha256hex, seal, open } = require('../../lib/crypto');
const { BlobStore } = require('./blobs');
const { createBackupsRepo } = require('./repo');
const { receiveToFile } = require('./ingest');
const { sniff, readManifest } = require('./archive');
const { backupGet } = require('./pull');

const BID_RE = /^bk_[0-9a-f]{20}$/;
const DAY = 86400e3;
const HOUR = 3600e3;
const aadPull = (slug) => `instance:${slug}:backup`;
const parseJson = (s) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };
const intHeader = (v, max) => { const n = Number.parseInt(String(v || ''), 10); return Number.isFinite(n) && n >= 0 ? Math.min(n, max) : null; };
// eslint-disable-next-line no-control-regex
const cleanHeader = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max) || null : null);

function dto(b) {
  return {
    id: b.id, instance_id: b.instance_id, source: b.source, received_at: b.received_at, expires_at: b.expires_at, sha256: b.sha256,
    size_bytes: b.size_bytes, encrypted: !!b.encrypted, files: b.files, dashboard_version: b.dashboard_version, retention_days: b.retention_days,
    manifest: parseJson(b.manifest),
  };
}

module.exports = {
  name: 'backups',
  version: '1',
  depends: ['instances'],
  async register(ctx) {
    const { router, config, audit, HttpError, reply, perms, log } = ctx;
    const cfg = config.backups;
    if (!cfg.enabled) return;
    const repo = createBackupsRepo(ctx.db);
    const blobs = new BlobStore(path.join(config.server.data_dir, cfg.dir));
    await blobs.init();
    const maxBytes = cfg.max_archive_mb * 1024 * 1024;
    const P = API_PREFIX;

    // ---- verrou par SHA-256 (un seul commit / suppression de blob à la fois pour une même archive)
    const locks = new Map();
    const withLock = (key, fn) => {
      const prev = locks.get(key) || Promise.resolve();
      const next = prev.catch(() => {}).then(fn);
      locks.set(key, next);
      return next.finally(() => { if (locks.get(key) === next) locks.delete(key); });
    };

    /** Valide la forme de l'archive reçue/téléchargée et la range (déduplication par instance + SHA-256). */
    async function commit({ inst, tmp, sha256, size, encrypted, files, version, remoteId, retentionHint, source }) {
      const kind = await sniff(tmp, size);
      if ((encrypted && kind !== 'encrypted') || (!encrypted && kind !== 'gzip')) {
        const e = new Error('bad_archive'); e.code = 'bad_archive'; throw e;
      }
      const now = Date.now();
      const retention = Math.max(1, Math.min(retentionHint || cfg.retention_days, cfg.retention_days));
      const expires = now + retention * DAY;
      return withLock(sha256, async () => {
        const existing = await repo.findBySha(inst.id, sha256);
        if (existing) {
          await blobs.adopt(tmp, sha256); // supprime le temporaire (le blob existe déjà)
          await repo.extend(existing.id, expires);
          await repo.markOk(inst.id, now);
          return { id: existing.id, duplicate: true };
        }
        const manifest = encrypted ? null : await readManifest(tmp);
        await blobs.adopt(tmp, sha256);
        const id = repo.newId();
        await repo.insert({
          id, instance_id: inst.id, source, received_at: now, expires_at: expires, sha256, size_bytes: size, encrypted, files: files ?? (manifest ? manifest.files : null),
          dashboard_version: version, remote_instance_id: remoteId, retention_days: retention, manifest: manifest ? JSON.stringify(manifest) : null,
        });
        await repo.markOk(inst.id, now);
        await repo.trim(inst.id, cfg.keep_max_per_instance);
        return { id, duplicate: false };
      });
    }

    // ---- PUSH --------------------------------------------------------------------------------------------------
    router.post(`${P}/backups`, { auth: false, raw: true, rate: { key: 'bk-push', max: cfg.push_rate_per_hour, windowMs: HOUR } }, async ({ req, ip }) => {
      const m = /^Bearer ([A-Za-z0-9_-]{16,200})$/.exec(String(req.headers.authorization || ''));
      const inst = m ? await repo.findInstanceByPushSha(sha256hex(m[1])) : null;
      if (!inst) {
        await audit(null, 'backup.push_denied', null, ip);
        throw new HttpError(401, 'Jeton invalide', 'unauthorized');
      }
      const declared = Number(req.headers['content-length']);
      if (!Number.isFinite(declared) || declared <= 0) throw new HttpError(411, 'Content-Length requis', 'length_required');
      if (declared > maxBytes) throw new HttpError(413, `Archive trop volumineuse (max ${cfg.max_archive_mb} Mo)`, 'payload_too_large');
      if (!/^application\/octet-stream\b/i.test(String(req.headers['content-type'] || ''))) throw new HttpError(415, 'application/octet-stream requis', 'unsupported_media_type');
      const claimed = String(req.headers['x-backup-sha256'] || '').toLowerCase();
      if (!BlobStore.valid(claimed)) throw new HttpError(400, 'X-Backup-Sha256 invalide', 'bad_request');
      req.setTimeout(30_000, () => req.destroy()); // un envoi qui n'avance plus pendant 30 s est coupé

      const tmp = blobs.tmpPath();
      let got;
      try { got = await receiveToFile(req, tmp, { maxBytes }); } catch (e) {
        if (e.code === 'too_large') throw new HttpError(413, 'Archive trop volumineuse', 'payload_too_large');
        throw new HttpError(400, 'Envoi interrompu', 'upload_failed');
      }
      const fail = async (status, msg, code) => { await require('node:fs/promises').rm(tmp, { force: true }); throw new HttpError(status, msg, code); };
      if (got.sha256 !== claimed) await fail(422, 'SHA-256 reçu différent de X-Backup-Sha256', 'checksum_mismatch');
      let res;
      try {
        res = await commit({
          inst, tmp, sha256: got.sha256, size: got.size, encrypted: String(req.headers['x-backup-encrypted']) === '1',
          files: intHeader(req.headers['x-backup-files'], 1e7), version: cleanHeader(req.headers['x-dashboard-version'], 32),
          remoteId: cleanHeader(req.headers['x-instance-id'], 64), retentionHint: intHeader(req.headers['x-retention-days'], 3650) || null, source: 'push',
        });
      } catch (e) {
        if (e.code === 'bad_archive') await fail(422, "Format d'archive inattendu (tar.gz ou NGXB1)", 'bad_archive');
        await require('node:fs/promises').rm(tmp, { force: true });
        throw e;
      }
      await audit(`instance:${inst.slug}`, 'backup.received', res.id, ip, { bytes: got.size, duplicate: res.duplicate });
      return reply(res.duplicate ? 200 : 201, { id: res.id, duplicate: res.duplicate });
    });

    // ---- PULL --------------------------------------------------------------------------------------------------
    const inflight = new Map();
    function pullOne(instanceId) {
      if (inflight.has(instanceId)) return inflight.get(instanceId);
      const p = (async () => {
        const row = await repo.getInstance(instanceId);
        if (!row || !row.backup_token_enc) return { ok: false, error: 'no_token' };
        let tmp = null;
        try {
          const token = open(row.backup_token_enc, ctx.key, aadPull(row.slug));
          const timeoutMs = cfg.upload_timeout_s * 1000;
          const man = await backupGet({ baseUrl: row.base_url, token, route: 'manifest', config, timeoutMs: Math.min(timeoutMs, 30_000) });
          const claimed = String(man.json.archive_sha256 || '').toLowerCase();
          if (!BlobStore.valid(claimed)) { const e = new Error('bad_manifest'); e.code = 'bad_manifest'; throw e; }
          const now = Date.now();
          const existing = await repo.findBySha(row.id, claimed);
          if (existing) { await repo.extend(existing.id, now + cfg.retention_days * DAY); await repo.markOk(row.id, now); return { ok: true, duplicate: true, id: existing.id }; }
          if (Number(man.json.archive_bytes) > maxBytes) { const e = new Error('too_large'); e.code = 'too_large'; throw e; }
          tmp = blobs.tmpPath();
          const got = await backupGet({ baseUrl: row.base_url, token, route: 'archive', config, tmp, maxBytes, timeoutMs });
          const hdr = String(got.headers['x-backup-sha256'] || claimed).toLowerCase();
          if (got.sha256 !== claimed || (hdr !== got.sha256)) { const e = new Error('checksum_mismatch'); e.code = 'checksum_mismatch'; throw e; }
          const res = await commit({
            inst: row, tmp, sha256: got.sha256, size: got.size, encrypted: String(got.headers['x-backup-encrypted']) === '1',
            files: null, version: null, remoteId: null, retentionHint: intHeader(man.json.retention_days, 3650) || null, source: 'pull',
          });
          tmp = null;
          await audit('system', 'backup.pulled', res.id, null, { instance: row.slug, bytes: got.size, duplicate: res.duplicate });
          return { ok: true, ...res };
        } catch (e) {
          const code = (e && e.code && /^[a-z_0-9]+$/i.test(e.code)) ? e.code : 'connection';
          await repo.markFail(row.id, Date.now(), code);
          log.warn('pull sauvegarde échoué', { instance: row.slug, reason: code });
          return { ok: false, error: code };
        } finally {
          if (tmp) await require('node:fs/promises').rm(tmp, { force: true });
        }
      })().finally(() => inflight.delete(instanceId));
      inflight.set(instanceId, p);
      return p;
    }

    async function pullDue() {
      if (!cfg.pull_enabled) return;
      const now = Date.now();
      const interval = cfg.pull_interval_hours * HOUR;
      for (const r of await repo.pullCandidates()) {
        const lastTry = r.last_backup_try_at || 0;
        if (now - (r.last_backup_at || 0) >= interval && now - lastTry >= Math.min(interval, HOUR)) await pullOne(r.id);
      }
    }

    // ---- état / alerte -----------------------------------------------------------------------------------------
    function view(r, now = Date.now()) {
      const expected = !!(r.push_on || r.pull_on);
      const ref = r.last_backup_at || r.backup_expected_since || null;
      const late = expected && ref !== null && now - ref > cfg.alert_after_hours * HOUR;
      return {
        instance_id: r.id, name: r.name, enabled: !!r.enabled,
        push_enabled: !!r.push_on, push_token_hint: r.push_token_hint || null,
        pull_enabled: !!r.pull_on, backup_token_hint: r.backup_token_hint || null,
        expected, late, last_backup_at: r.last_backup_at || null, last_try_at: r.last_backup_try_at || null, last_error: r.last_backup_error || null,
        count: Number(r.count), bytes: Number(r.bytes),
      };
    }
    async function overview() {
      const now = Date.now();
      const rows = (await repo.overviewRows()).map((r) => view(r, now));
      const expected = rows.filter((r) => r.expected && r.enabled);
      return {
        expected: expected.length,
        ok: expected.filter((r) => !r.late && r.last_backup_at).length,
        late: expected.filter((r) => r.late).map((r) => ({ instance_id: r.instance_id, name: r.name, last_backup_at: r.last_backup_at })),
        errors: expected.filter((r) => r.last_error).length,
        total_bytes: rows.reduce((a, r) => a + r.bytes, 0),
        alert_after_hours: cfg.alert_after_hours,
      };
    }

    // ---- purge / ramasse-miettes -------------------------------------------------------------------------------
    async function maintain() {
      try {
        const expired = await repo.deleteExpired(Date.now());
        const removed = await blobs.gc(await repo.referencedShas());
        if (expired || removed) log.info('purge sauvegardes', { expired, blobs_removed: removed });
      } catch (e) { log.error('purge sauvegardes', { err: e }); }
    }

    ctx.services.set('backups', { overview, pullOne, pullDue, maintain, commit, blobs, repo });

    // ---- API de consultation et d'administration ---------------------------------------------------------------
    const loadInstance = async (id) => {
      const n = Number(id);
      const row = Number.isInteger(n) ? (await repo.overviewRows()).find((r) => r.id === n) : null;
      if (!row) throw new HttpError(404, 'Instance inconnue', 'not_found');
      return row;
    };
    const loadBackup = async (id) => {
      const b = BID_RE.test(id) ? await repo.get(id) : null;
      if (!b) throw new HttpError(404, 'Sauvegarde inconnue', 'not_found');
      return b;
    };

    router.get(`${P}/backups`, { perm: perms.BACKUPS_VIEW }, async () => {
      const now = Date.now();
      return {
        items: (await repo.overviewRows()).map((r) => view(r, now)),
        policy: { retention_days: cfg.retention_days, alert_after_hours: cfg.alert_after_hours, pull_enabled: cfg.pull_enabled, pull_interval_hours: cfg.pull_interval_hours, max_archive_mb: cfg.max_archive_mb },
        push_url: config.server.public_base_url ? config.server.public_base_url.replace(/\/+$/, '') + `${P}/backups` : null,
      };
    });

    router.get(`${P}/instances/:id/backups`, { perm: perms.BACKUPS_VIEW }, async ({ params }) => {
      const row = await loadInstance(params.id);
      return { instance: view(row), items: (await repo.list(row.id)).map(dto) };
    });

    router.post(`${P}/instances/:id/backups/push-token`, { perm: perms.BACKUPS_MANAGE, rate: { key: 'bk-token', max: 20, windowMs: 60_000 } }, async ({ params, session, ip }) => {
      const row = await loadInstance(params.id);
      const token = 'hubp_' + randomToken(32);
      await repo.setPushToken(row.id, sha256hex(token), '…' + token.slice(-4), Date.now());
      await audit(session.username, 'backup.push_token', row.name, ip, { id: row.id });
      const base = config.server.public_base_url ? config.server.public_base_url.replace(/\/+$/, '') : null;
      return reply(201, { token_once: token, push_url: base ? `${base}${P}/backups` : null, env: { HUB_PUSH_TOKEN: token } });
    });
    router.delete(`${P}/instances/:id/backups/push-token`, { perm: perms.BACKUPS_MANAGE }, async ({ params, session, ip }) => {
      const row = await loadInstance(params.id);
      await repo.clearPushToken(row.id);
      await audit(session.username, 'backup.push_token_revoked', row.name, ip, { id: row.id });
      return { ok: true };
    });

    router.post(`${P}/instances/:id/backups/pull-token`, { perm: perms.BACKUPS_MANAGE, rate: { key: 'bk-token', max: 20, windowMs: 60_000 } }, async ({ params, session, ip }) => {
      const row = await loadInstance(params.id);
      const token = 'hubb_' + randomToken(32);
      await repo.setBackupToken(row.id, seal(token, ctx.key, aadPull(row.slug)), '…' + token.slice(-4), Date.now());
      await audit(session.username, 'backup.pull_token', row.name, ip, { id: row.id });
      return reply(201, { token_once: token, token_sha256: sha256hex(token), env: { HUB_BACKUP_TOKEN_SHA256: sha256hex(token) } });
    });
    router.delete(`${P}/instances/:id/backups/pull-token`, { perm: perms.BACKUPS_MANAGE }, async ({ params, session, ip }) => {
      const row = await loadInstance(params.id);
      await repo.clearBackupToken(row.id);
      await audit(session.username, 'backup.pull_token_revoked', row.name, ip, { id: row.id });
      return { ok: true };
    });

    router.post(`${P}/instances/:id/backups/pull`, { perm: perms.BACKUPS_MANAGE, rate: { key: 'bk-pull', max: 6, windowMs: 60_000 } }, async ({ params, session, ip }) => {
      const row = await loadInstance(params.id);
      if (!row.pull_on) throw new HttpError(409, 'Aucun jeton de pull configuré pour cette instance', 'no_pull_token');
      const r = await pullOne(row.id);
      await audit(session.username, 'backup.pull_requested', row.name, ip, { ok: r.ok, error: r.error || null });
      return r;
    });

    router.get(`${P}/backups/:bid`, { perm: perms.BACKUPS_VIEW }, async ({ params }) => dto(await loadBackup(params.bid)));

    router.get(`${P}/backups/:bid/download`, { perm: perms.BACKUPS_DOWNLOAD, rate: { key: 'bk-dl', max: 30, windowMs: 60_000 } }, async ({ params, res, session, ip }) => {
      const b = await loadBackup(params.bid);
      if (!(await blobs.has(b.sha256))) throw new HttpError(410, 'Archive absente du disque', 'blob_missing');
      const inst = await repo.getInstance(b.instance_id);
      const stamp = new Date(b.received_at).toISOString().replace(/[-:]/g, '').replace(/\..*$/, '').replace('T', '-');
      const name = `${(inst && inst.slug) || 'instance'}-${stamp}.${b.encrypted ? 'ngxb' : 'tar.gz'}`;
      await audit(session.username, 'backup.download', b.id, ip, { bytes: b.size_bytes, encrypted: !!b.encrypted });
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream', 'Content-Length': b.size_bytes,
        'Content-Disposition': `attachment; filename="${name}"`, 'X-Backup-Sha256': b.sha256, 'X-Backup-Encrypted': b.encrypted ? '1' : '0',
      });
      await pipeline(blobs.stream(b.sha256), res);
    });

    router.delete(`${P}/backups/:bid`, { perm: perms.BACKUPS_MANAGE }, async ({ params, session, ip }) => {
      const b = await loadBackup(params.bid);
      await withLock(b.sha256, async () => { await repo.remove(b.id); if ((await repo.countRefs(b.sha256)) === 0) await blobs.remove(b.sha256); });
      await audit(session.username, 'backup.delete', b.id, ip, { instance_id: b.instance_id });
      return { ok: true };
    });

    // ---- planification ------------------------------------------------------------------------------------------
    let ticks = 0;
    const first = setTimeout(() => { pullDue().catch((e) => log.error('pull planifié', { err: e })); }, 30_000);
    const timer = setInterval(() => {
      pullDue().catch((e) => log.error('pull planifié', { err: e }));
      if (++ticks % 6 === 0) maintain();
    }, 10 * 60_000);
    first.unref(); timer.unref();
    ctx.onStop(() => { clearTimeout(first); clearInterval(timer); });
    log.info('sauvegardes actives', { retention_days: cfg.retention_days, alert_after_hours: cfg.alert_after_hours, pull: cfg.pull_enabled });
  },
};
