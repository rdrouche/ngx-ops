'use strict';
/**
 * Test de contrat client -> Intelligence (ticket #58, schéma 1).
 *
 * Le VRAI client (lib/intel-client.js) fabrique des lots à partir d'alertes d'analyseur réalistes ;
 * ils sont comparés aux fixtures versionnées de `contracts/intelligence/batches/`. Le test Go
 * `nginx-intelligence/core/tests/contract_test.go` envoie ces MÊMES fichiers au VRAI serveur
 * Intelligence (PostgreSQL) et vérifie `contracts/intelligence/expectations.json`.
 * Si le client change de format : ce test échoue tant que les fixtures ne sont pas régénérées
 * (`UPDATE_CONTRACTS=1 node test/contract-intelligence.test.js`) ; le test Go dit alors si le serveur suit.
 *
 * Ce test vérifie aussi, avec les mêmes statuts HTTP que ceux qui sont provoqués côté serveur,
 * la décision du client (classifyResponse) : 200 / 429 + Retry-After / 401 / 403 / 413 / autre 4xx / 5xx.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const S = require('../lib/intel-settings');
const C = require('../lib/intel-client');

const DIR = path.join(__dirname, '..', '..', 'contracts', 'intelligence');
const UPDATE = process.env.UPDATE_CONTRACTS === '1';
let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const NOW = Date.parse('2026-01-15T10:00:00Z');
const MIN = 60_000;
const instance = { id: '3df7919e-94f5-4635-91c6-8189f6475ebf', version: '12.81.0' };
const URL_ = 'https://ti.example.org/api/v1/events';
const settingsOf = (yml) => S.normalizeIntelSettings(`enable: true\napi_url: ${URL_}\nshare_user_agents: true\nshare_paths: true\nshare_vhost: true\n${yml}`, {}).settings;

// Alertes brutes de l'analyseur (même forme que celles lues sur /api/alerts).
const RAW = {
  scan: { id: 101, ts: NOW - 5 * MIN, type: 'scan', severity: 'high', ip: '198.51.100.20', vhost: 'shop.example.com',
    evidence: { ip: '198.51.100.20', windowMinutes: 10, requests: 140, distinctPaths: 90, notFound: 80, firstSeen: NOW - 15 * MIN, lastSeen: NOW - 5 * MIN,
      statuses: { 404: 80, 200: 60 }, userAgents: ['sqlmap/1.7'], samples: [{ path: '/admin' }, { path: '/.env' }] } },
  bruteforce: { id: 102, ts: NOW - 4 * MIN, type: 'bruteforce', severity: 'critical', ip: '198.51.100.21',
    evidence: { ip: '198.51.100.21', windowMinutes: 5, requests: 60, authFailures: 55, statuses: { 401: 55, 200: 5 } } },
  campaign: { id: 103, ts: NOW - 3 * MIN, type: 'scraping', severity: 'medium',
    evidence: { campaign: true, windowMinutes: 30, requests: 900, globalIps: 3, ips: [['198.51.100.30', 400], ['198.51.100.31', 300], ['198.51.100.32', 200]],
      topUserAgents: [{ ua: 'Scrapy/2.11' }], topPaths: [{ path: '/products' }] } },
  custom: { id: 104, ts: NOW - 2 * MIN, type: 'ua_attack_tools', severity: 'high', ip: '198.51.100.22',
    evidence: { ip: '198.51.100.22', ruleId: 7, ruleName: 'ua_attack_tools', matches: 4, userAgents: ['nikto/2.5'], samples: [{ path: '/?id=1%27' }] } },
  waf: { id: 7, ts: NOW - 2 * MIN, type: 'waf', severity: 'high', ip: '198.51.100.23', vhost: 'api.example.com',
    evidence: { ip: '198.51.100.23', windowMinutes: 10, requests: 12, score: 38, mode: 'observe',
      rules: [{ id: 942100, count: 3, severity: 'CRITICAL' }, { id: 941100, count: 1, severity: 'CRITICAL' }],
      tags: ['attack-sqli', 'attack-xss'], categories: ['sqli', 'xss'], userAgents: ['curl/8.5'], paths: ['/search'] } },
  challenge: { id: 3, ts: NOW - 1 * MIN, type: 'challenge', severity: 'medium', ip: '198.51.100.24', vhost: 'shop.example.com',
    evidence: { ip: '198.51.100.24', windowMinutes: 60, requests: 40, redirected: 38, failed: 2, rateLimited: 0, banHours: 24,
      firstSeen: NOW - 30 * MIN, lastSeen: NOW - 1 * MIN, userAgents: ['python-requests/2.31'] } },
};

// Ce que le client sait fabriquer (nom de fichier -> lot). Tout nouveau type d'alerte émis par le client doit apparaître ici.
function fixtures() {
  const anon = settingsOf('');
  const ident = settingsOf('mode: identified\nuser: contract@example.org\ntoken: TOKEN-PLACEHOLDER\n');
  const make = (settings, alerts, batchId) => {
    const body = C.buildBatch({ settings, instance, alerts, now: NOW, batchId });
    return { headers: C.buildHeaders({ settings, instance, body, userAgent: 'NGXOps' }), body };
  };
  return {
    'anonymous-builtin': make(anon, [RAW.scan, RAW.bruteforce], 'contract-anon-builtin-0001'),
    'anonymous-campaign': make(anon, [RAW.campaign], 'contract-anon-campaign-001'),
    'anonymous-custom': make(anon, [RAW.custom], 'contract-anon-custom-0001'),
    'anonymous-waf': make(anon, [RAW.waf], 'contract-anon-waf-00000001'),
    'anonymous-challenge': make(anon, [RAW.challenge], 'contract-anon-challenge-01'),
    'anonymous-minimal-sharing': make(settingsOf('share_user_agents: false\nshare_paths: false\nshare_vhost: false\n'), [RAW.scan], 'contract-anon-minimal-01'),
    'identified-mixed': make(ident, [RAW.scan, RAW.waf, RAW.challenge, RAW.custom], 'contract-ident-mixed-0001'),
  };
}

const read = (f) => JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));

(async () => {
  const expectations = read('expectations.json');

  console.log('\nlots fabriqués par le client = fixtures du contrat');
  const all = fixtures();
  for (const [name, fx] of Object.entries(all)) {
    await check(name, () => {
      const file = path.join('batches', name + '.json');
      if (UPDATE) fs.writeFileSync(path.join(DIR, file), JSON.stringify(fx, null, 2) + '\n');
      assert.deepStrictEqual(JSON.parse(JSON.stringify(fx)), read(file),
        `${file} diffère de ce que produit le client : si le changement est voulu, régénérer (UPDATE_CONTRACTS=1) et vérifier que le test Go du serveur passe`);
      assert.ok(expectations.batches[name], `${name} : attendu serveur absent de expectations.json`);
    });
  }
  await check('chaque fixture du dossier est produite par le client et attendue par le serveur', () => {
    const files = fs.readdirSync(path.join(DIR, 'batches')).filter(f => f.endsWith('.json')).map(f => f.replace(/\.json$/, '')).sort();
    assert.deepStrictEqual(files, Object.keys(all).sort());
    assert.deepStrictEqual(Object.keys(expectations.batches).sort(), files);
  });

  console.log('\nen-têtes et corps du schéma 1');
  await check('en-têtes obligatoires, Idempotency-Key = batch_id, jeton seulement en identifié', () => {
    for (const [name, fx] of Object.entries(all)) {
      const h = fx.headers;
      assert.strictEqual(h['X-NC-Schema'], '1'); assert.strictEqual(fx.body.schema, 1);
      assert.strictEqual(h['X-NC-Instance-Id'], fx.body.instance.id);
      assert.strictEqual(h['X-NC-Client-Version'], instance.version);
      assert.strictEqual(h['Idempotency-Key'], fx.body.batch_id);
      assert.ok(/^[A-Za-z0-9-]{8,64}$/.test(fx.body.batch_id), name + ' : batch_id');
      if (name.startsWith('identified')) {
        assert.strictEqual(h.Authorization, 'Bearer TOKEN-PLACEHOLDER'); assert.strictEqual(h['X-NC-User'], 'contract@example.org'); assert.strictEqual(fx.body.user, 'contract@example.org');
      } else {
        assert.strictEqual(h.Authorization, undefined); assert.strictEqual(h['X-NC-User'], undefined); assert.strictEqual(fx.body.user, undefined);
      }
    }
  });
  await check('types d\'alertes émis : builtin, custom, waf, challenge', () => {
    const kinds = new Set();
    for (const fx of Object.values(all)) for (const a of fx.body.alerts) kinds.add(a.rule.kind);
    assert.deepStrictEqual([...kinds].sort(), ['builtin', 'challenge', 'custom', 'waf']);
  });
  await check('un type inconnu de l\'analyseur part en « custom » (jamais un kind inconnu du serveur)', () => {
    const o = C.shapeAlert({ id: 9, ts: NOW, type: 'quantum', severity: 'low', ip: '198.51.100.9', evidence: {} }, settingsOf(''));
    assert.strictEqual(o.rule.kind, 'custom');
  });
  await check('partage minimal : ni user_agents, ni paths, ni vhost', () => {
    const a = all['anonymous-minimal-sharing'].body.alerts[0];
    assert.strictEqual(a.user_agents, undefined); assert.strictEqual(a.paths, undefined); assert.strictEqual(a.vhost, undefined);
  });
  await check('aucun secret hors en-tête Authorization (jeton absent des corps)', () => {
    for (const fx of Object.values(all)) assert.ok(!JSON.stringify(fx.body).includes('TOKEN-PLACEHOLDER'));
  });

  console.log('\ncodes de retour : décision du client (mêmes statuts que ceux provoqués côté serveur)');
  for (const c of expectations.responses) {
    await check(`HTTP ${c.status}${c.retryAfter ? ' + Retry-After ' + c.retryAfter : ''} -> ${c.client}`, () => {
      const r = C.classifyResponse({ status: c.status, headers: c.retryAfter ? { 'retry-after': String(c.retryAfter) } : {}, body: {} }, NOW);
      assert.strictEqual(r.kind, c.client);
      if (c.retryAfter) assert.strictEqual(r.retryAfterMs, c.retryAfter * 1000);
    });
  }
  await check('erreur réseau -> retry', () => assert.strictEqual(C.classifyResponse({ error: 'ECONNRESET' }).kind, 'retry'));

  console.log('\nidempotence : rejouer un lot = même Idempotency-Key');
  await check('un lot rejoué (413 réduit, 5xx) garde le batch_id du corps', async () => {
    const st = C.initialState(); st.cursor = 0;
    const seen = [];
    const settings = settingsOf('');
    const deps = {
      fetchAlerts: async () => ({ alerts: [RAW.scan], latestId: 101 }),
      post: async (req) => { seen.push(req.headers['Idempotency-Key'] + '|' + req.body.batch_id); return { status: 503, headers: {}, body: {} }; },
    };
    const r = await C.runCycle({ settings, state: st, instance, now: NOW, deps, force: true });
    assert.strictEqual(r.outcome, 'retry_later');
    assert.strictEqual(r.state.cursor, 0, 'le curseur n\'avance pas : le lot sera rejoué');
    const [k, b] = seen[0].split('|'); assert.strictEqual(k, b);
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
