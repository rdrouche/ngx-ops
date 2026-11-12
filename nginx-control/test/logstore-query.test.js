'use strict';
/** lib/logstore-query.js : liste blanche des parametres relayes vers le log store (v12.80.0). */
const assert = require('assert');
const Q = require('../lib/logstore-query');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const P = (o) => new URLSearchParams(o);

console.log('\nbuildRequest()');
check('chemins fixes sans parametre', () => {
  assert.deepStrictEqual(Q.buildRequest('health', P({})), { path: '/v1/health' });
  assert.deepStrictEqual(Q.buildRequest('instances', P({})), { path: '/v1/instances' });
  assert.deepStrictEqual(Q.buildRequest('events', P({})), { path: '/v1/events' });
});
check('events : filtres valides recopies et encodes', () => {
  const r = Q.buildRequest('events', P({ since: '24h', site: 'a.example.com', source: 'waf', action: 'blocked', status: '5xx', ip: '203.0.113.9', path: '/wp login', ua: 'curl/8', limit: '50', instance: 'web1' }));
  assert.ok(!r.error, r.error);
  const q = new URL('http://x' + r.path).searchParams;
  assert.strictEqual(r.path.split('?')[0], '/v1/events');
  assert.strictEqual(q.get('path'), '/wp login');
  assert.strictEqual(q.get('limit'), '50');
  assert.strictEqual(q.get('status'), '5xx');
  assert.ok(r.path.includes('path=%2Fwp+login') || r.path.includes('path=%2Fwp%20login'));
});
check('cles inconnues ignorees (jamais relayees)', () => {
  const r = Q.buildRequest('events', P({ since: '1h', admin: '1', 'x[]': 'y', token: 'abc', next: 'http://evil' }));
  assert.strictEqual(r.path, '/v1/events?since=1h');
});
check('valeurs invalides refusees', () => {
  const bad = [
    ['since', '1 h'], ['since', '10000h'], ['since', '7d'], ['since', '1d'], ['since', 'now'], ['from', 'hier'], ['to', '2026-13-45T00:00:00Z'], ['source', 'x'], ['action', 'ALLOWED'],
    ['status', '999'], ['status', '4xxx'], ['ip', 'not an ip'], ['ip', '1.2.3.4/../../x'], ['site', 'a b'], ['site', 'a/b'], ['instance', '../x'],
    ['limit', '0'], ['limit', '501'], ['limit', '-1'], ['limit', '5e2'], ['cursor', 'a b'], ['cursor', 'a&b=c'], ['ua', 'a\nb'], ['path', 'x\u0000y'],
  ];
  for (const [k, v] of bad) assert.ok(Q.buildRequest('events', P({ [k]: v })).error, `${k}=${v}`);
  assert.ok(Q.buildRequest('events', P({ ua: 'x'.repeat(201) })).error);
});
check('since incompatible avec from/to', () => {
  assert.ok(Q.buildRequest('events', P({ since: '1h', from: '2026-11-09T10:00:00Z' })).error);
  assert.ok(!Q.buildRequest('events', P({ from: '2026-11-09T10:00:00Z', to: '2026-11-09T11:00:00+01:00' })).error);
});
check('ip : chemin fixe, IP validee et encodee', () => {
  assert.strictEqual(Q.buildRequest('ip', P({ since: '168h' }), '203.0.113.9').path, '/v1/ips/203.0.113.9?since=168h');
  assert.strictEqual(Q.buildRequest('ip', P({}), '2001:db8::1').path, '/v1/ips/2001%3Adb8%3A%3A1');
  assert.strictEqual(Q.buildRequest('ip', P({}), 'a'.repeat(32)).path, '/v1/ips/' + 'a'.repeat(32));
  for (const bad of ['', 'x', '../../etc/passwd', '1.2.3.4/x', '1.2.3.4?x=1', '1.2.3.4#', 'a'.repeat(31), 'g'.repeat(32), '%2e%2e']) {
    assert.ok(Q.buildRequest('ip', P({}), bad).error, bad);
  }
});
check('ip : pas de filtre ip/ua/path libre', () => {
  assert.strictEqual(Q.buildRequest('ip', P({ ua: 'x', path: '/y', ip: '1.1.1.1' }), '203.0.113.9').path, '/v1/ips/203.0.113.9');
});
check('top : dimension obligatoire et en liste blanche', () => {
  assert.ok(Q.buildRequest('top', P({})).error);
  assert.ok(Q.buildRequest('top', P({ dimension: 'password' })).error);
  assert.ok(Q.buildRequest('top', P({ dimension: 'path; DROP' })).error);
  for (const d of Q.DIMENSIONS) assert.ok(!Q.buildRequest('top', P({ dimension: d })).error, d);
  assert.ok(Q.buildRequest('top', P({ dimension: 'path', limit: '101' })).error);
  assert.strictEqual(Q.buildRequest('top', P({ dimension: 'ip', limit: '100' })).path, '/v1/stats/top?limit=100&dimension=ip');
});
check('visits : bucket ; security : min_paths', () => {
  assert.strictEqual(Q.buildRequest('visits', P({ bucket: 'day', since: '168h' })).path, '/v1/stats/visits?since=168h&bucket=day');
  assert.ok(Q.buildRequest('visits', P({ bucket: 'minute' })).error);
  assert.strictEqual(Q.buildRequest('security', P({ min_paths: '30' })).path, '/v1/stats/security?min_paths=30');
  assert.ok(Q.buildRequest('security', P({ min_paths: '0' })).error);
  assert.ok(Q.buildRequest('security', P({ min_paths: '1001' })).error);
});
check('events/ip : cursor accepte, absent des stats', () => {
  assert.strictEqual(Q.buildRequest('events', P({ cursor: 'eyJ0IjoiMjAyNiJ9' })).path, '/v1/events?cursor=eyJ0IjoiMjAyNiJ9');
  assert.strictEqual(Q.buildRequest('visits', P({ cursor: 'abc', limit: '5' })).path, '/v1/stats/visits');
});
check('requete inconnue refusee', () => assert.ok(Q.buildRequest('tokens', P({})).error));


console.log('\nfenetres > 31 j (#65)');
check('planWindows : <= 31 j ou sans fenetre -> null ; > 366 j -> erreur', () => {
  assert.strictEqual(Q.planWindows(P({ since: '720h' }), Date.UTC(2026, 10, 11)), null);
  assert.strictEqual(Q.planWindows(P({}), Date.UTC(2026, 10, 11)), null);
  assert.ok(Q.planWindows(P({ since: '9000h' }), Date.UTC(2026, 10, 11)).error);
});
check('planWindows : tranches <= 30 j, coupures a minuit UTC, sans trou ni chevauchement', () => {
  const now = Date.UTC(2026, 10, 11, 10, 30);
  const { chunks } = Q.planWindows(P({ since: '2160h' }), now);
  assert.ok(chunks.length >= 3);
  chunks.forEach((c, i) => {
    assert.ok(Date.parse(c.to) - Date.parse(c.from) < 31 * 86400000);
    if (i) { const prevEnd = Date.parse(chunks[i - 1].to) + 1; assert.strictEqual(prevEnd, Date.parse(c.from)); assert.strictEqual(prevEnd % 86400000, 0); }
  });
  assert.strictEqual(Date.parse(chunks.at(-1).to), now);
  assert.strictEqual(Date.parse(chunks[0].from), now - 2160 * 3600000);
});
check('chunkParams : from/to, bucket=day, since retire ; les tranches passent buildRequest', () => {
  const p = Q.chunkParams(P({ since: '2160h', site: 'a.fr', bucket: 'hour' }), { from: '2026-08-01T00:00:00.000Z', to: '2026-08-30T23:59:59.999Z' });
  assert.ok(!p.has('since') && p.get('bucket') === 'day' && p.get('site') === 'a.fr');
  assert.ok(!Q.buildRequest('visits', p).error);
});
check('mergeVisits : concatene et trie ; doublon somme, visiteurs inconnus', () => {
  const m = Q.mergeVisits([{ points: [{ bucket: 'b2', requests: 2, bytes: 5, visitors: 1 }] }, { points: [{ bucket: 'b1', requests: 1, visitors: 3 }, { bucket: 'b2', requests: 3, bytes: 1, visitors: 1 }] }]);
  assert.deepStrictEqual(m.points.map((x) => x.bucket), ['b1', 'b2']);
  assert.strictEqual(m.points[1].requests, 5); assert.strictEqual(m.points[1].bytes, 6); assert.strictEqual(m.points[1].visitors, null);
  assert.strictEqual(m.chunks, 2); assert.strictEqual(m.bucket, 'day');
});
check('mergeTop : somme par cle, tri, limite, marque approximatif', () => {
  const m = Q.mergeTop([{ items: [{ key: 'a', count: 5 }, { key: 'b', count: 1 }] }, { items: [{ key: 'b', count: 6 }, { key: 'c', count: 2 }] }], 'path', 2);
  assert.deepStrictEqual(m.items, [{ key: 'b', count: 7 }, { key: 'a', count: 5 }]);
  assert.strictEqual(m.approximate, true);
});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
