'use strict';
/** lib/logstore-config.js : formulaire de configuration du journal centralise (#63). */
const assert = require('assert');
const C = require('../lib/logstore-config');
const S = require('../lib/logstore-settings');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const TOKEN_A = 'lgs_readtokenreadtoken01', TOKEN_B = 'lgs_sinktokensinktoken02';
const base = { enable: true, url: 'https://logs.example.com', shipper_enable: true, shipper_host_data_path: '/srv/ngx/shipper', shipper_host_logs_path: '/srv/logs', shipper_image: 'registry.example/shipper:1', instance: 'web1', token: TOKEN_A, shipper_sink_token: TOKEN_B };

console.log('\nlib/logstore-config.js');
check('buildConfig : yaml relu a l identique par la lecture et le shipper', () => {
  const r = C.buildConfig({ ...base, shipper_country: true, timeout_seconds: 15 }, '', {});
  assert.ok(r.ok, r.errors.join('|'));
  const n = S.normalizeLogstoreConfig(r.yaml, {});
  assert.deepStrictEqual(n.errors, []);
  assert.strictEqual(n.config.url, 'https://logs.example.com'); assert.strictEqual(n.config.token, TOKEN_A);
  assert.strictEqual(n.config.sinkToken, TOKEN_B); assert.strictEqual(n.config.timeoutSeconds, 15);
  assert.strictEqual(n.config.shipperCountry, true); assert.strictEqual(n.config.instance, 'web1');
  assert.deepStrictEqual(n.readBlockers, []); assert.deepStrictEqual(n.shipperBlockers, []);
});
check('jetons : conserves si le champ est vide ou masque, remplaces si fournis, effaces sur demande', () => {
  const prev = C.buildConfig(base, '', {}).yaml;
  const keep = C.buildConfig({ ...base, token: '', shipper_sink_token: '****' }, prev, {});
  assert.ok(keep.yaml.includes(TOKEN_A) && keep.yaml.includes(TOKEN_B));
  const NEW = 'lgs_newnewnewnewnewnew03';
  const rep = C.buildConfig({ ...base, token: NEW, shipper_sink_token: '' }, prev, {});
  assert.ok(rep.yaml.includes(NEW) && !rep.yaml.includes(TOKEN_A) && rep.yaml.includes(TOKEN_B));
  const clr = C.buildConfig({ ...base, token: '', shipper_sink_token: '', clearToken: true, clearSinkToken: true }, prev, {});
  assert.ok(!clr.yaml.includes('token:') || !/^token:/m.test(clr.yaml));
  assert.ok(!clr.yaml.includes(TOKEN_A) && !clr.yaml.includes(TOKEN_B));
});
check('refus : jeton invalide, caracteres interdits, URL invalide, delai hors bornes, booleens non vrais = faux', () => {
  assert.ok(!C.buildConfig({ ...base, token: 'court' }, '', {}).ok);
  for (const bad of ['a"b', 'a\nb', 'a#b', 'a\\b']) assert.ok(!C.buildConfig({ ...base, instance: bad }, '', {}).ok, JSON.stringify(bad));
  assert.ok(!C.buildConfig({ ...base, url: 'http://logs.example.com' }, '', {}).ok, 'http vers un hote public');
  assert.ok(!C.buildConfig({ ...base, url: 'https://logs.example.com/v1' }, '', {}).ok, 'chemin interdit');
  assert.ok(!C.buildConfig({ ...base, timeout_seconds: 1 }, '', {}).ok);
  assert.ok(!C.buildConfig({ ...base, timeout_seconds: 'x' }, '', {}).ok);
  assert.ok(/enable: false/.test(C.buildConfig({ ...base, enable: 'yes' }, '', {}).yaml));
  assert.ok(!C.buildConfig({ ...base, shipper_host_data_path: '/srv/../etc' }, '', {}).ok);
});
check('formView : aucun jeton dans la vue, seulement tokenSet / sinkTokenSet', () => {
  const y = C.buildConfig(base, '', {}).yaml;
  const n = S.normalizeLogstoreConfig(y, {});
  const v = C.formView({ config: n.config, errors: n.errors, text: y, env: {} });
  const json = JSON.stringify(v);
  assert.ok(!json.includes(TOKEN_A) && !json.includes(TOKEN_B));
  assert.strictEqual(v.tokenSet, true); assert.strictEqual(v.sinkTokenSet, true);
  assert.strictEqual(v.values.url, 'https://logs.example.com'); assert.strictEqual(v.values.enable, true);
});
check('formView : jeton fourni par l\'environnement signale, valeur d\'env jamais recopiee', () => {
  const ENV = 'lgs_fromenvfromenvfrom9';
  const y = C.buildConfig({ ...base, token: '', shipper_sink_token: '' }, '', { readToken: ENV }).yaml;
  assert.ok(!y.includes(ENV));
  const n = S.normalizeLogstoreConfig(y, { readToken: ENV });
  const v = C.formView({ config: n.config, errors: n.errors, text: y, env: { readToken: ENV } });
  assert.strictEqual(v.tokenFromEnv, true); assert.strictEqual(v.tokenSet, true);
  assert.ok(!JSON.stringify(v).includes(ENV));
});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
