'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('../lib/hub-detail');

const alert = { id: 7, ts: 1, type: 'bruteforce', severity: 'high', summary: 'x', acked: 0,
  evidence: { vhost: 'a.fr', country: 'FR', ip: '203.0.113.5', ips: ['203.0.113.5', '198.51.100.2'], paths: ['/wp-login.php'], nested: { topIps: [{ ip: '192.0.2.9' }] } } };

test('IP retirées par défaut, comptées quand même', () => {
  const a = d.shapeAlert(alert, false);
  const j = JSON.stringify(a);
  assert.ok(!/203\.0\.113|198\.51|192\.0\.2/.test(j), j);
  assert.equal(a.ip_count, 3); assert.equal(a.vhost, 'a.fr'); assert.equal(a.country, 'FR'); assert.equal(a.ips, undefined);
});
test('expose_ips : IP fournies pour la corrélation', () => {
  const a = d.shapeAlert(alert, true);
  assert.deepEqual(a.ips.sort(), ['192.0.2.9', '198.51.100.2', '203.0.113.5']);
  assert.deepEqual(d.topIps([a, a])[0].alerts, 2);
});
test('evidence énorme tronquée, entrées invalides tolérées', () => {
  const big = d.shapeAlert({ id: 1, type: 't', evidence: { x: Array.from({ length: 50 }, () => 'y'.repeat(300)) } }, false);
  assert.deepEqual(big.evidence, { truncated: true });
  assert.deepEqual(d.shapeAlerts(null, false), []);
  assert.equal(d.tally(d.shapeAlerts([alert, alert], false)).by_type.bruteforce, 2);
});
