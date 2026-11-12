'use strict';
/**
 * Test de contrat dashboard -> Hub (ticket #58, API v1 rév. 12.78.0).
 *
 * Producteur : le VRAI code du dashboard (nginx-dashboard/lib/hub-modules.js, features/hub.js).
 * Consommateur : les VRAIS assainisseurs du Hub (features/modules/sanitize.js, collector/summary-schema.js).
 * Référence des noms contractuels : contracts/hub/contract.json (reflet de Docs/contrat-hub-dashboard-v1.md).
 * Un renommage de partie ou de champ d'un côté sans l'autre fait échouer ce test.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const DASH = path.join(__dirname, '..', '..', 'nginx-dashboard');
// Le dashboard écrit ses secrets générés à côté de users.yml : on le confine à un répertoire jetable.
const TMP = require('node:fs').mkdtempSync(path.join(require('node:os').tmpdir(), 'contract-dash-'));
process.env.USERS_FILE = path.join(TMP, 'users.yml');
process.env.SESSION_SECRET = 'contract-test-session-secret-0123456789';
const CONTRACT = require('../../contracts/hub/contract.json');
const { Router, send } = require(path.join(DASH, 'lib', 'http'));
const M = require(path.join(DASH, 'lib', 'hub-modules'));
const hubFeature = require(path.join(DASH, 'features', 'hub'));
const { normEnvelope, normAlert } = require('../features/modules/sanitize');
const { sanitizeSummary, deriveHealth } = require('../features/collector/summary-schema');

const IP = '203.0.113.9';
const SECRET = 'S3CR3T-VALUE';

/** Faux dashboard interne : chaque API consultée par les modules répond avec une charge utile « sale » (IP, secret). */
function fakeCtx() {
  const router = new Router();
  const dirty = {
    ok: true, note: `bloqué ${IP} hier`, ip: IP, apiToken: SECRET,
    rows: [{ vhost: 'a.fr', name: 'a.fr', requests: 5, bytes: 10, errors: 1, ip: IP }],
    vhosts: [{ vhost: 'a.fr', name: 'a.fr', requests: 5 }], series: [{ ts: 1, requests: 5 }],
    offenders: [{ ip: IP, attempts: 40, lastSeen: 1 }], bans: [{ ip: IP, since: 1, until: 2, attempts: 40 }],
    decisions: [{ value: IP, scenario: 'http-probing', type: 'ban', origin: 'crowdsec', duration: '4h' }],
    ips: [{ ip: IP, count: 5, blocked: 2 }], targets: [{ key: 'a.fr', name: 'a.fr' }], incidents: [{ ts: 1 }],
    agents: [{ id: 'ag1', hostnameProposed: 'edge1', status: 'active', online: true, tunnelConnected: true, lastManifestAt: 1, lastManifestOk: true, vhostCount: 2, protocolVersion: 1, createdAt: 1 }],
    certificates: [{ domain: 'a.fr', notAfter: '2027-01-01', daysLeft: 50 }], reachable: true, container: 'x',
  };
  for (const p of M.ALLOWED) router.get(p, async ({ res }) => send(res, 200, dirty));
  const alert = { id: 7, ts: 1730000000000, type: 'scan', severity: 'high', summary: `scan depuis ${IP}`, vhost: 'a.fr', country: 'FR', acked: false, ip_count: 1,
    evidence: { ip: IP, vhost: 'a.fr', requests: 50 }, ips: [IP] };
  return {
    router, instanceId: '3df7919e-94f5-4635-91c6-8189f6475ebf', version: '12.81.0',
    fetchVTS: async () => ({ nginxVersion: '1.30.1', connections: 12, serverZones: { 'a.fr': {}, '*': {} } }),
    execNginx: async () => ({ stderr: 'nginx version: nginx/1.30.1\nbuilt with OpenSSL 3.0.15\nconfigure arguments: --with-http_v2_module', stdout: '' }),
    queryEvents: () => ({ total: 1, events: [{ id: 1, ts: 1, type: 'login', source: 'admin', data: { note: `depuis ${IP}`, password: SECRET } }] }),
    analyzerApi: async (p) => (p.startsWith('/api/alerts') ? { data: { total: 1, alerts: [alert] } } : { data: { topIps: [{ ip: IP, hits: 3 }] } }),
  };
}

const settings = (exposeIps) => ({ expose: M.MODULE_IDS, exposeIps });

test('le dashboard expose exactement les modules du contrat', () => {
  assert.deepEqual([...M.MODULE_IDS].sort(), Object.keys(CONTRACT.modules).sort());
  assert.deepEqual(CONTRACT.routes.filter((r) => !['summary', 'alerts'].includes(r)).sort(), Object.keys(CONTRACT.modules).sort());
});

for (const exposeIps of [false, true]) {
  for (const id of Object.keys(CONTRACT.modules)) {
    if (id === 'indicators' && !exposeIps) continue;
    test(`module ${id} (expose_ips=${exposeIps}) : enveloppe, parties du contrat, assainissement côté Hub`, async () => {
      const ctx = fakeCtx();
      const r = await M.buildModule(ctx, id, new URLSearchParams('hours=24'), settings(exposeIps));
      assert.equal(r.status, 200);
      for (const k of CONTRACT.envelope) assert.ok(k in r.body, `enveloppe : ${k} manquant`);
      assert.equal(r.body.schema, 1); assert.equal(r.body.module, id); assert.equal(r.body.expose_ips, exposeIps);
      assert.equal(r.body.instance.id, ctx.instanceId); assert.equal(r.body.instance.version, ctx.version);
      // Chaque partie du contrat est présente côté dashboard (aucune dans `errors` : le faux dashboard répond partout).
      assert.deepEqual(r.body.errors, {});
      for (const part of CONTRACT.modules[id]) assert.ok(part in r.body.data, `${id} : partie « ${part} » absente de la réponse du dashboard`);
      // Le Hub relit l'enveloppe sans perdre une seule partie.
      const env = normEnvelope(JSON.parse(JSON.stringify(r.body)));
      assert.ok(env);
      assert.equal(env.expose_ips, exposeIps);
      for (const part of CONTRACT.modules[id]) assert.ok(part in env.data, `${id} : le Hub a perdu la partie « ${part} »`);
      const dumped = JSON.stringify(env.data);
      assert.ok(!dumped.includes(SECRET), 'aucun secret ne doit survivre');
      if (!exposeIps) assert.ok(!dumped.includes(IP), 'aucune IP de visiteur ne doit survivre sans expose_ips');
      else if (id === 'indicators') assert.ok(dumped.includes(IP));
    });
  }
}

test('indicators : 403 expose_ips_disabled sans expose_ips ; types de sources du contrat', async () => {
  const ctx = fakeCtx();
  const denied = await M.buildModule(ctx, 'indicators', new URLSearchParams(), settings(false));
  assert.equal(denied.status, 403); assert.equal(denied.body.error, 'expose_ips_disabled');
  const ok = await M.buildModule(ctx, 'indicators', new URLSearchParams('hours=24'), settings(true));
  const top = ok.body.data.indicators[0];
  assert.equal(top.ip, IP);
  assert.deepEqual(top.kinds, [...CONTRACT.indicator_kinds].sort());
  assert.equal(top.score, CONTRACT.indicator_kinds.length);
});

test('module retiré de expose_modules : 404 indiscernible d\'une route inconnue', async () => {
  const ctx = fakeCtx();
  const r = await M.buildModule(ctx, 'traffic', new URLSearchParams(), { expose: ['inventory'], exposeIps: false });
  assert.equal(r.status, 404);
});

test('partie indisponible : listée dans errors, absente de data, le Hub la tolère', async () => {
  const ctx = fakeCtx();
  const empty = new Router(); // aucune API interne : toutes les parties sont indisponibles
  const r = await M.buildModule({ ...ctx, router: empty }, 'reports', new URLSearchParams(), settings(false));
  assert.equal(r.status, 200);
  for (const part of CONTRACT.modules.reports) assert.equal(r.body.errors[part], 'unavailable', part);
  const env = normEnvelope(JSON.parse(JSON.stringify(r.body)));
  assert.deepEqual(env.data, {}); assert.equal(Object.keys(env.errors).length, CONTRACT.modules.reports.length);
});

test('alerte détaillée : le Hub relit une alerte telle que l\'émet le dashboard (ips seulement avec expose_ips)', () => {
  const emitted = { id: 7, ts: 1730000000000, type: 'scan', severity: 'high', summary: `scan depuis ${IP}`, vhost: 'a.fr', country: 'FR', acked: false, ip_count: 1, evidence: { ip: IP, requests: 50 }, ips: [IP] };
  const hidden = normAlert(emitted, false);
  assert.equal(hidden.remote_id, 7); assert.equal(hidden.type, 'scan'); assert.equal(hidden.ips, null);
  assert.ok(!JSON.stringify(hidden).includes(IP));
  const shown = normAlert(emitted, true);
  assert.deepEqual(JSON.parse(shown.ips), [IP]);
});

test('résumé (schéma 1) : le vrai buildSummary du dashboard traverse sanitizeSummary sans perdre de champ du contrat', async () => {
  hubFeature.setDeps({
    fetchVTS: async () => ({ nginxVersion: '1.30.1', connections: 12, serverZones: { 'a.fr': {}, 'b.fr': {}, '*': {} } }),
    analyzerApi: async () => ({ data: { total: 2, alerts: [{ id: 1, type: 'scan', severity: 'high', ts: '2026-01-15T10:00:00Z' }, { id: 2, type: 'flood', severity: 'low', ts: '2026-01-15T10:01:00Z' }] } }),
  });
  const raw = JSON.parse(JSON.stringify(await hubFeature.buildSummary(Date.parse('2026-01-15T10:05:00Z'))));
  for (const k of CONTRACT.summary) assert.ok(k in raw, `résumé : « ${k} » absent de la réponse du dashboard`);
  assert.equal(raw.schema, 1);
  const s = sanitizeSummary(raw);
  for (const k of CONTRACT.summary) assert.ok(k in s, `résumé : « ${k} » perdu par le Hub`);
  assert.equal(s.schema, 1); assert.equal(s.schema_newer, false);
  assert.equal(s.instance.id, raw.instance.id); assert.equal(s.nginx.status, 'running'); assert.equal(s.nginx.version, '1.30.1');
  assert.equal(s.vhosts.count, 2); assert.equal(s.alerts.active, 2); assert.equal(s.alerts.items.length, 2);
  assert.equal(deriveHealth(s), 'online');
});
