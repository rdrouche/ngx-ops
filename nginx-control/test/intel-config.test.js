'use strict';
// Formulaire de configuration Intelligence (#88) : liste blanche, validation, jeton jamais renvoye.
const assert = require('assert');
const S = require('../lib/intel-settings');
const C = require('../lib/intel-config');
let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const URL_OK = 'https://intelligence.ngx-ops.net/api/v1/events';

(async () => {
  await check('configuration valide : YAML relu à l identique par le moteur', () => {
    const r = C.buildConfig({ enable: true, mode: 'identified', api_url: URL_OK, user: 'a@b.fr', token: 'abcdef123456', exclude_ips: '1.2.3.4\n10.0.0.0/8', exclude_rules: ['volumetric'], min_severity: 'medium', share_paths: true, ping_enable: true }, '', {});
    assert.ok(r.ok, r.errors.join(','));
    const s = S.normalizeIntelSettings(r.yaml, {}).settings;
    assert.strictEqual(s.enable, true); assert.strictEqual(s.ready, true); assert.strictEqual(s.minSeverity, 'medium');
    assert.deepStrictEqual(s.excludeIps, ['1.2.3.4', '10.0.0.0/8']); assert.strictEqual(s.sharePaths, true); assert.strictEqual(s.shareUserAgents, false);
  });
  await check('jeton : conservé si absent ou masqué, remplacé si fourni, effacé sur demande', () => {
    const prev = 'token: "keepme12345"\n';
    assert.ok(C.buildConfig({ mode: 'anonymous' }, prev, {}).yaml.includes('keepme12345'));
    assert.ok(C.buildConfig({ mode: 'anonymous', token: '********' }, prev, {}).yaml.includes('keepme12345'));
    assert.ok(C.buildConfig({ mode: 'anonymous', token: 'newtoken9999' }, prev, {}).yaml.includes('newtoken9999'));
    assert.ok(!C.buildConfig({ mode: 'anonymous', clearToken: true }, prev, {}).yaml.includes('token:'));
  });
  await check('refus : http, mode inconnu, caractères d injection YAML, jeton invalide, IP invalide', () => {
    assert.ok(!C.buildConfig({ enable: true, mode: 'anonymous', api_url: 'http://x.tld/a' }, '', {}).ok);
    assert.ok(!C.buildConfig({ mode: 'x' }, '', {}).ok);
    assert.ok(!C.buildConfig({ mode: 'identified', user: 'a@b.fr"\nenable: true' }, '', {}).ok);
    assert.ok(!C.buildConfig({ mode: 'anonymous', token: 'a b"c\nd' }, '', {}).ok);
    assert.ok(!C.buildConfig({ mode: 'anonymous', exclude_ips: 'pas-une-ip' }, '', {}).ok);
    assert.ok(!C.buildConfig({ enable: true, mode: 'identified', api_url: URL_OK }, '', {}).ok, 'identified sans user/jeton');
  });
  await check('formView : aucun secret, lien d inscription dérivé de l URL', () => {
    const text = `enable: true\nmode: identified\napi_url: "${URL_OK}"\nuser: "a@b.fr"\ntoken: "supersecret123"\n`;
    const { settings, errors } = S.normalizeIntelSettings(text, {});
    const v = C.formView({ settings, errors, text, env: {} });
    assert.strictEqual(v.tokenSet, true);
    assert.ok(!JSON.stringify(v).includes('supersecret123'));
    assert.strictEqual(v.registerUrl, 'https://intelligence.ngx-ops.net/register');
    assert.strictEqual(C.registerUrl(''), C.DEFAULT_REGISTER_URL);
  });
  await check('formView : URL venant de l environnement non recopiée dans le fichier', () => {
    const { settings, errors } = S.normalizeIntelSettings('', { apiUrl: URL_OK });
    const v = C.formView({ settings, errors, text: '', env: { apiUrl: URL_OK } });
    assert.strictEqual(v.values.api_url, ''); assert.strictEqual(v.apiUrlDefault, URL_OK);
  });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
