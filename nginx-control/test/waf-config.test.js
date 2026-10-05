'use strict';
/** lib/waf-config.js : lecture de waf.yml, blockers, specification du conteneur WAF emule. */
const assert = require('assert');
const WC = require('../lib/waf-config');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const ENV = { defaultImage: 'reg/waf:1', defaultLogsPath: '/srv/nginx/logs' };
const FULL = 'enable: true\naccept_limits: true\nhost_data_path: /srv/waf/data\nhost_rules_path: /srv/waf/rules\n';

console.log('\nnormalizeWafConfig()');
check('vide : defauts surs, desactive, aucune erreur', () => {
  const { config, errors, blockers } = WC.normalizeWafConfig('', ENV);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, false);
  assert.strictEqual(config.acceptLimits, false);
  assert.strictEqual(config.containerName, 'ngx-waf');
  assert.strictEqual(config.port, 9101);
  assert.strictEqual(config.containerImage, 'reg/waf:1');
  assert.strictEqual(config.hostLogsPath, '/srv/nginx/logs');
  assert.ok(blockers.includes('disabled') && blockers.includes('accept_limits'));
});
check('complet : aucun blocker', () => {
  const r = WC.normalizeWafConfig(FULL, ENV);
  assert.deepStrictEqual(r.blockers, []);
  assert.strictEqual(r.config.hostDataPath, '/srv/waf/data');
});
check('accept_limits absent : blocker accept_limits (meme active)', () => {
  const r = WC.normalizeWafConfig(FULL.replace('accept_limits: true\n', ''), ENV);
  assert.deepStrictEqual(r.blockers, ['accept_limits']);
});
check('chemins hote manquants : blockers dedies', () => {
  const r = WC.normalizeWafConfig('enable: true\naccept_limits: true\n', { defaultImage: 'i' });
  assert.deepStrictEqual(r.blockers, ['host_data_path', 'host_rules_path', 'host_logs_path']);
});
check('container_image : waf.yml > WAF_DEFAULT_IMAGE', () => {
  assert.strictEqual(WC.normalizeWafConfig(FULL + 'container_image: mine/waf:2\n', ENV).config.containerImage, 'mine/waf:2');
});
check('valeurs invalides : erreurs, defauts conserves, blocker invalid', () => {
  const r = WC.normalizeWafConfig(FULL + 'container_name: "a b"\ncontainer_image: "x;y"\nport: 99999\ncrs_version: master\nhit_retention_days: 0\nlog_pattern: "("\n', ENV);
  assert.ok(r.errors.length >= 6, r.errors.join(' | '));
  assert.ok(r.blockers.includes('invalid'));
  assert.strictEqual(r.config.containerName, 'ngx-waf');
  assert.strictEqual(r.config.port, 9101);
  assert.strictEqual(r.config.containerImage, 'reg/waf:1');
});
check('chemin hote : ":" (injection de bind), "..", relatif et controle refuses', () => {
  for (const bad of ['/a:/etc:rw', '/a/../b', 'rel/path', '/a\u0001b']) {
    assert.strictEqual(WC.validHostPath(bad), false, bad);
  }
  assert.strictEqual(WC.validHostPath('/srv/ok'), true);
  const r = WC.normalizeWafConfig('host_data_path: "/x:/etc"\n', ENV);
  assert.strictEqual(r.config.hostDataPath, '');
  assert.ok(r.blockers.includes('invalid'));
});
check('crs_version : "v" ajoute si absent ; slash final retire des chemins', () => {
  const r = WC.normalizeWafConfig(FULL + 'crs_version: 4.9.0\n', ENV);
  assert.strictEqual(r.config.crsVersion, 'v4.9.0');
  assert.strictEqual(WC.normalizeWafConfig('host_data_path: /d/\n', ENV).config.hostDataPath, '/d');
});

console.log('\nbuildContainerSpec()');
const cfg = () => WC.normalizeWafConfig(FULL, ENV).config;
check('jeton obligatoire', () => assert.throws(() => WC.buildContainerSpec(cfg(), {}), /jeton/));
check('env du contrat, jeton transmis au conteneur', () => {
  const s = WC.buildContainerSpec(cfg(), { token: 'tok123', network: 'net', tz: 'Europe/Paris' });
  assert.ok(s.Env.includes('WAF_TOKEN=tok123'));
  assert.ok(s.Env.includes('PORT=9101'));
  assert.ok(s.Env.includes('LOGS_DIR=/nginx/logs') && s.Env.includes('DATA_DIR=/waf') && s.Env.includes('RULES_DIR=/waf-rules'));
  assert.ok(s.Env.includes('CRS_VERSION=v4.8.0') && s.Env.includes('HIT_RETENTION_DAYS=30'));
  assert.ok(s.Env.includes('TZ=Europe/Paris'));
  assert.deepStrictEqual(s.Entrypoint, ['/usr/local/bin/waf']);
});
check('montages : logs en lecture seule, chemins HOTE, aucun port publie', () => {
  const s = WC.buildContainerSpec(cfg(), { token: 't', network: 'net' });
  assert.deepStrictEqual(s.HostConfig.Binds, ['/srv/nginx/logs:/nginx/logs:ro', '/srv/waf/data:/waf', '/srv/waf/rules:/waf-rules']);
  assert.strictEqual(s.HostConfig.PortBindings, undefined);
  assert.strictEqual(s.HostConfig.NetworkMode, 'net');
  assert.strictEqual(s.HostConfig.RestartPolicy.Name, 'unless-stopped');
});
check('TZ invalide ignore', () => {
  const s = WC.buildContainerSpec(cfg(), { token: 't', tz: 'a;b' });
  assert.ok(!s.Env.some(e => e.startsWith('TZ=')));
});

console.log('\ngetWafToken()');
check('ENV > genere ; stable entre appels ; jamais vide', () => {
  const fs = require('fs'), os = require('os'), path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waftoken-'));
  process.env.USERS_FILE = path.join(dir, 'users.yml'); delete process.env.WAF_TOKEN;
  for (const m of ['../lib/config', '../lib/waf-token']) delete require.cache[require.resolve(m)];
  const { getWafToken } = require('../lib/waf-token');
  const a = getWafToken();
  assert.ok(/^[a-f0-9]{48}$/.test(a));
  assert.strictEqual(getWafToken(), a);
  assert.ok(JSON.parse(fs.readFileSync(path.join(dir, '.generated-secrets.json'), 'utf8')).wafToken === a);
  process.env.WAF_TOKEN = 'from-env-token';
  for (const m of ['../lib/config', '../lib/waf-token']) delete require.cache[require.resolve(m)];
  assert.strictEqual(require('../lib/waf-token').getWafToken(), 'from-env-token');
  fs.rmSync(dir, { recursive: true, force: true });
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
