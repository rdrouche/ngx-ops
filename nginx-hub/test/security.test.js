'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { blockedReason, parseInstanceUrl, RateLimiter, unmapV4 } = require('../lib/security');
const { createLogger, redact } = require('../lib/logger');
const { seal, open, hashPassword, verifyPassword, safeEqual, generateKey } = require('../lib/crypto');
const { generateSecret, totpAt, verifyTotp, base32Decode } = require('../lib/totp');
const { parseYaml } = require('../lib/yaml');
const { sanitizeSummary } = require('../features/collector/summary-schema');
const { order } = require('../lib/features');

test('blockedReason : métadonnées cloud toujours bloquées, privé selon politique', () => {
  assert.equal(blockedReason('169.254.169.254', { allow_private_networks: true }), 'blocked_address');
  assert.equal(blockedReason('::ffff:169.254.169.254', { allow_private_networks: true }), 'blocked_address');
  assert.equal(blockedReason('10.1.2.3', {}), 'private_address');
  assert.equal(blockedReason('10.1.2.3', { allow_private_networks: true }), null);
  assert.equal(blockedReason('10.1.2.3', { allowed_cidrs: ['10.1.0.0/16'] }), null);
  assert.equal(blockedReason('10.2.2.3', { allowed_cidrs: ['10.1.0.0/16'] }), 'private_address');
  assert.equal(blockedReason('::1', {}), 'private_address');
  assert.equal(blockedReason('fe80::1', { allow_private_networks: true }), 'blocked_address');
  assert.equal(blockedReason('93.184.216.34', {}), null);
  assert.equal(unmapV4('::ffff:7f00:1'), '127.0.0.1');
});

test('parseInstanceUrl : normalisation et refus', () => {
  assert.deepEqual(parseInstanceUrl('https://Dash.Example.org:8443/ngx/', {}), { ok: true, url: 'https://dash.example.org:8443/ngx', host: 'dash.example.org' });
  assert.equal(parseInstanceUrl('http://dash.example.org', {}).ok, false);
  assert.equal(parseInstanceUrl('http://dash.example.org', { allow_insecure_http: true }).ok, true);
  assert.equal(parseInstanceUrl('https://a.example.org#x', {}).ok, false);
});

test('limiteur de débit', () => {
  const rl = new RateLimiter();
  assert.ok(rl.hit('k', 2, 1000, 0).allowed); assert.ok(rl.hit('k', 2, 1000, 1).allowed);
  assert.equal(rl.hit('k', 2, 1000, 2).allowed, false);
  assert.ok(rl.hit('k', 2, 1000, 1500).allowed);
  rl.stop();
});

test('logger : secrets masqués (clés et motifs)', () => {
  const lines = [];
  const log = createLogger('debug', (l) => lines.push(l));
  log.info('appel avec hubt_ABCDEFGHIJKLMNOP et Bearer abcdefghijklmnop', { token: 'secret', nested: { password: 'x', ok: 1 }, cookie: 'hub_sid=zzz' });
  const out = lines[0];
  assert.ok(!out.includes('ABCDEFGHIJKLMNOP')); assert.ok(!out.includes('abcdefghijklmnop'));
  assert.ok(!out.includes('"secret"')); assert.ok(!out.includes('zzz'));
  assert.deepEqual(redact({ a: { api_key: 'k' } }), { a: { api_key: '[redacted]' } });
});

test('crypto : scellement AES-GCM lié au contexte, mots de passe scrypt, comparaison à temps constant', () => {
  const key = Buffer.from(generateKey(), 'base64');
  const s = seal('hubt_secret', key, 'instance:a');
  assert.equal(open(s, key, 'instance:a'), 'hubt_secret');
  assert.throws(() => open(s, key, 'instance:b'));
  assert.throws(() => open(s.slice(0, -2) + 'AA', key, 'instance:a'));
  const h = hashPassword('un mot de passe'); assert.ok(verifyPassword('un mot de passe', h)); assert.ok(!verifyPassword('autre', h));
  assert.ok(safeEqual('a', 'a')); assert.ok(!safeEqual('a', 'ab'));
});

test('TOTP : vecteur RFC 6238 (SHA-1) et fenêtre', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
  assert.equal(Buffer.from(base32Decode(secret)).toString(), '12345678901234567890');
  assert.equal(totpAt(secret, 59_000), '287082');
  assert.equal(totpAt(secret, 1111111109_000), '081804');
  const s = generateSecret();
  assert.ok(verifyTotp(s, totpAt(s), {}).ok);
  assert.ok(!verifyTotp(s, '12345', {}).ok);
});

test('YAML : sous-ensemble de configuration', () => {
  const y = parseYaml(`
server:
  port: 8090 # commentaire
  public_base_url: "https://hub.example.org"
  trusted_proxies: ['10.0.0.0/8', "::1/128"]
security:
  allow_private_networks: true
  allowed_cidrs:
    - 10.1.0.0/16
    - 192.168.0.0/24
features:
  audit: false
`);
  assert.equal(y.server.port, 8090);
  assert.deepEqual(y.server.trusted_proxies, ['10.0.0.0/8', '::1/128']);
  assert.deepEqual(y.security.allowed_cidrs, ['10.1.0.0/16', '192.168.0.0/24']);
  assert.equal(y.features.audit, false);
  assert.throws(() => parseYaml('a:\n\t b: 1'));
  assert.equal(parseYaml('__proto__:\n  x: 1\n').x, undefined);
});

test('résumé : assainissement strict (types, bornes, injection de HTML laissé inerte)', () => {
  const s = sanitizeSummary({ schema: 2, instance: { version: 12 }, traffic_24h: { humans: -5, robots: 'x' }, alerts: { active: 1e99, items: Array(50).fill({ title: '<img src=x onerror=1>', severity: 'bidon' }) }, components: { 'BAD KEY': { state: 'ok' }, waf: { state: 'pwned' } } });
  assert.equal(s.schema_newer, true);
  assert.equal(s.instance.version, null);
  assert.equal(s.traffic_24h.humans, 0); assert.equal(s.traffic_24h.robots, 0);
  assert.equal(s.alerts.items.length, 10); assert.equal(s.alerts.items[0].severity, 'warning');
  assert.deepEqual(Object.keys(s.components), ['waf']); assert.equal(s.components.waf.state, 'unknown');
  assert.throws(() => sanitizeSummary({ schema: 0 }));
});

test('features : ordre topologique et détection de dépendance manquante / circulaire', () => {
  const f = (name, depends) => ({ name, depends, register() {} });
  assert.deepEqual(order([f('b', ['a']), f('a')]).map((x) => x.name), ['a', 'b']);
  assert.throws(() => order([f('a', ['zz'])]), /dépend/);
  assert.throws(() => order([f('a', ['b']), f('b', ['a'])]), /circulaire/);
});

test('garde-fous du code : pas d\'innerHTML ni eval dans le front, aucune dépendance npm', () => {
  const root = path.join(__dirname, '..');
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(path.join(root, 'public')).filter((x) => x.endsWith('.js') || x.endsWith('.html'))) {
    const src = fs.readFileSync(f, 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(src), 'API dangereuse dans ' + path.relative(root, f));
    if (f.endsWith('.html')) assert.ok(!/<script(?![^>]*\bsrc=)/.test(src), 'script inline interdit (CSP) dans ' + path.relative(root, f));
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
});

test('résumé : états « configured » / « unreachable » des dashboards 12.78+ reconnus (#126)', () => {
  const s = sanitizeSummary({ schema: 1, components: { waf: { state: 'configured' }, crowdsec: { state: 'configured' }, analyzer: { state: 'unreachable' }, challenge: { state: 'off' } } });
  assert.equal(s.components.waf.state, 'ok'); assert.equal(s.components.crowdsec.state, 'ok');
  assert.equal(s.components.analyzer.state, 'down'); assert.equal(s.components.challenge.state, 'disabled');
});
