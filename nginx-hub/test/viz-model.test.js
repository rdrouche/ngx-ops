'use strict';
// Modèles des vues graphiques (#67) : formes réelles des parties de modules (extraits anonymisés) + tolérance aux parties absentes.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const load = () => import(path.join(__dirname, '..', 'public', 'assets', 'js', 'viz', 'model.js'));

const SECURITY = {
  blocklists_status: { enable: true, totalUniqueIps: 122215, whitelist: ['10.0.0.0/24', '192.0.2.1'], sources: [
    { name: 'list-a', type: 'url', enable: true, count: 108135, lastError: null },
    { name: 'analyzer-auto', type: 'analyzer', enable: true, count: 14042, detectedCount: 6930, byRule: [{ id: 101, key: 'custom_101', name: 'scraper_lists', remediationType: 'block', detectedCount: 6867 }, { id: 3, key: 'flood', name: 'flood', remediationType: 'block', detectedCount: 0 }] },
    { name: 'broken', type: 'url', enable: true, count: 0, lastError: 'timeout' }] },
  blocklists_hits: { totalHits: 6448, uniqueHitIps: 2894, topIps: [{ ip: '198.51.100.7', count: 10 }], bySource: [{ name: 'analyzer-auto', hits: 4760 }, { name: 'list-a', hits: 96 }] },
  challenge_stats: { windowHours: 24, total: { pages: 22, started: 18, solved: 12, failed: 1 }, series: [{ hour: 1794229200, pages: 3, started: 3, solved: 2, failed: 0 }, { hour: 1794240000, pages: 1, started: 1, solved: 1, failed: 0 }] },
  challenge_status: { enabled: true, engine: 'builtin', container: { running: true }, errors: [], ips: { count: 39 } },
  challenge_blocks: { bans: [], offenders: [{ ip: '203.0.113.9', attempts: 1 }] },
  waf_status: { configured: true, enabled: true, reachable: true, errors: [], waf: { engine: { name: 'coraza', ready: true, paranoia: 1 }, crs: { rulesLoaded: 401 }, stats24h: { requests: 27550, hits: 984, ips: 95 } } },
  crowdsec_status: { configured: false },
  alerts: { total: 155, unacked: 150, by_type: { custom_101: 143, scan: 7 }, by_severity: { high: 148, medium: 7 } },
};

test('securityModel : KPI, composants et agrégats depuis la forme réelle', async () => {
  const { securityModel } = await load();
  const m = securityModel(SECURITY);
  assert.equal(m.kpis.blockedIps, 122215);
  assert.equal(m.kpis.hits, 6448);
  assert.equal(m.kpis.unacked, 150);
  assert.equal(m.kpis.solveRate, 66.7);
  assert.equal(m.whitelist, 2);
  const st = Object.fromEntries(m.components.map((c) => [c.id, c.state]));
  assert.deepEqual(st, { blocklists: 'warn', challenge: 'ok', waf: 'ok', crowdsec: 'off' });
  assert.equal(m.rules[0].name, 'scraper_lists');
  assert.equal(m.alertsByType[0].key, 'custom_101');
  assert.equal(m.challenge.series[0].t, 1794229200 * 1000);
  assert.equal(m.sources[0].name, 'list-a'); // triées par volume
});

test('securityModel : conteneur Challenge arrêté = panne ; WAF injoignable = panne', async () => {
  const { securityModel } = await load();
  const m = securityModel({ challenge_status: { enabled: true, container: { running: false } }, waf_status: { configured: true, reachable: false } });
  const st = Object.fromEntries(m.components.map((c) => [c.id, c.state]));
  assert.equal(st.challenge, 'err');
  assert.equal(st.waf, 'err');
});

test('modèles : parties absentes ou invalides → valeurs neutres, jamais d’exception', async () => {
  const { securityModel, trafficModel, inventoryModel } = await load();
  for (const bad of [undefined, {}, { alerts: 'x', vhosts: 3, certificates: null, nginx: [] }]) {
    assert.doesNotThrow(() => { securityModel(bad); trafficModel(bad); inventoryModel(bad); });
  }
  const s = securityModel({});
  assert.equal(s.kpis.alerts, null);
  assert.deepEqual(s.components.map((c) => c.state), ['off', 'off', 'off', 'off']);
});

test('trafficModel : totaux par vhost, humains/bots fusionnés, pays triés (série horaire vide tolérée)', async () => {
  const { trafficModel } = await load();
  const m = trafficModel({
    series_hourly: { series: [] },
    vhosts: { vhosts: [{ vhost: 'a.example', requests: 100, errors: 40, bytes: 1000 }, { vhost: 'b.example', requests: 300, errors: 0, bytes: 2000 }] },
    clients_by_vhost: { vhosts: [{ vhost: 'a.example', bots: 10, human: 90, total: 100 }] },
    countries: { countries: [{ country: 'US', requests: 5, errors: 1, bytes: 0 }, { country: 'FR', requests: 50, errors: 2, bytes: 9 }] },
    clients: { total: 400, human: 380, bots: 20, byCategory: [{ category: 'human', requests: 380 }, { category: 'bad', requests: 3 }] },
  });
  assert.equal(m.kpis.requests, 400);
  assert.equal(m.kpis.errorRate, 10);
  assert.equal(m.kpis.humanRate, 95);
  assert.equal(m.vhosts[0].name, 'b.example');
  assert.equal(m.vhosts[1].human, 90);
  assert.equal(m.vhosts[0].human, null);
  assert.equal(m.countries[0].code, 'FR');
  assert.deepEqual(m.hourly, []);
});

test('inventoryModel : certificats triés par échéance, blocs server et conteneur unique', async () => {
  const { inventoryModel } = await load();
  const m = inventoryModel({
    nginx: { running: true, version: '1.30', connections: { active: 9, reading: 0, writing: 3, waiting: 6, requests: 100 } },
    certificates: { certificates: [{ name: 'b.pem', daysLeft: 3000, totalDays: 3650, source: 'ssl' }, { name: 'x', domain: 'z.example', daysLeft: 12, totalDays: 90, warning: true, issuer: 'C=US\nO=Let\'s Encrypt\nCN=YE1' }], summary: { total: 2, expired: 0, warning: 1 } },
    vhosts: { vhosts: [{ enabled: true, serverBlocks: [{ ssl: true, locations: [{ kind: 'docker' }] }, { ssl: false, redirectsToHttps: true, monitoring: { enabled: true }, locations: [] }] }] },
    containers_managed: { container: { name: 'ngx-analyzer', running: true } },
    agents: { agents: [] },
  });
  assert.equal(m.certs[0].name, 'z.example');
  assert.equal(m.certs[0].issuer, 'Let\'s Encrypt');
  assert.deepEqual({ b: m.vhosts.blocks, s: m.vhosts.ssl, r: m.vhosts.redirects, m: m.vhosts.monitored }, { b: 2, s: 1, r: 1, m: 1 });
  assert.equal(m.vhosts.kinds[0].key, 'docker');
  assert.equal(m.nginx.conn.active, 9);
  assert.equal(m.containers[0].name, 'ngx-analyzer');
});

test('topN regroupe le reste', async () => {
  const { topN } = await load();
  const r = topN([{ value: 5 }, { value: 1 }, { value: 9 }, { value: 2 }], 2);
  assert.deepEqual(r.top.map((x) => x.value), [9, 5]);
  assert.equal(r.rest, 3);
  assert.equal(r.restCount, 2);
});
