'use strict';
/** lib/logstore-settings.js + lib/shipper-container.js : config logstore.yml et spec du conteneur shipper (v12.80.0). */
const assert = require('assert');
const S = require('../lib/logstore-settings');
const C = require('../lib/shipper-container');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const TOK = 'lgs_' + 'a'.repeat(40);
const ENVD = { defaultLogsPath: '/host/logs', defaultImage: 'reg/analyzer:1', instanceId: '3f2b8c1e-9d4a-4e6b-8a57-1c2d3e4f5a6b' };

console.log('\nnormalizeLogstoreConfig()');
check('vide : desactive, aucune erreur, defauts herites', () => {
  const r = S.normalizeLogstoreConfig('', ENVD);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.config.enable, false);
  assert.strictEqual(r.config.shipperEnable, false);
  assert.strictEqual(r.config.shipperHostLogsPath, '/host/logs');
  assert.strictEqual(r.config.shipperImage, 'reg/analyzer:1');
  assert.strictEqual(r.config.instance, ENVD.instanceId);
  assert.strictEqual(r.config.shipperName, 'ngx-shipper');
  assert.deepStrictEqual(r.readBlockers, ['disabled', 'url', 'token']);
});
check('lecture complete : plus aucun blocage', () => {
  const r = S.normalizeLogstoreConfig(`enable: true\nurl: https://logs.example.com/  # fin\ntoken: ${TOK}\n`, ENVD);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.config.url, 'https://logs.example.com');
  assert.deepStrictEqual(r.readBlockers, []);
});
check('jeton ENV prioritaire sur le yml', () => {
  const env = 'lgs_' + 'b'.repeat(40);
  const r = S.normalizeLogstoreConfig(`enable: true\nurl: https://l.example.com\ntoken: ${TOK}\n`, { ...ENVD, readToken: env });
  assert.strictEqual(r.config.token, env);
});
check('envoi : l URL de lecture sert par defaut, jeton ENV, blocages listes', () => {
  const r = S.normalizeLogstoreConfig('enable: true\nurl: https://l.example.com\ntoken: ' + TOK + '\nshipper_enable: true\n', { ...ENVD, sinkToken: TOK });
  assert.strictEqual(r.config.sinkUrl, 'https://l.example.com');
  assert.deepStrictEqual(r.shipperBlockers, ['host_data_path']);
  const ok = S.normalizeLogstoreConfig('enable: true\nurl: https://l.example.com\ntoken: ' + TOK + '\nshipper_enable: true\nshipper_host_data_path: /srv/shipper/\n', { ...ENVD, sinkToken: TOK });
  assert.deepStrictEqual(ok.shipperBlockers, []);
  assert.strictEqual(ok.config.shipperHostDataPath, '/srv/shipper');
});
check('http:// : refuse vers un hote public, accepte local / service / IP privee', () => {
  for (const u of ['http://logs.example.com', 'http://8.8.8.8:8443']) {
    const r = S.normalizeLogstoreConfig('url: ' + u + '\n', ENVD);
    assert.ok(r.errors.some(e => e.startsWith('url')), u);
    assert.strictEqual(r.config.url, '');
  }
  for (const u of ['http://logstore:8443', 'http://localhost:8443', 'http://127.0.0.1:8443', 'http://10.1.2.3:8443', 'http://192.168.1.5', 'http://172.20.0.4:8443']) {
    const r = S.normalizeLogstoreConfig('url: ' + u + '\n', ENVD);
    assert.deepStrictEqual(r.errors, [], u);
    assert.strictEqual(r.config.url, u);
  }
});
check('allow_insecure leve la limite http:// sur l hote public', () => {
  const r = S.normalizeLogstoreConfig('allow_insecure: true\nurl: http://logs.example.com:8443\n', ENVD);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.config.url, 'http://logs.example.com:8443');
});
check('URL piegees refusees (identifiants, chemin, requete, schema, controle)', () => {
  for (const u of ['https://u:p@logs.example.com', 'https://logs.example.com/v1', 'https://logs.example.com/?x=1', 'ftp://logs.example.com', 'file:///etc/passwd', 'https://logs.example.com#x', 'javascript:alert(1)']) {
    const r = S.normalizeLogstoreConfig('allow_insecure: true\nurl: ' + u + '\n', ENVD);
    assert.strictEqual(r.config.url, '', u);
    assert.ok(r.errors.length, u);
  }
});
check('valeurs invalides : erreurs, defauts conserves, blocages "invalid"', () => {
  const r = S.normalizeLogstoreConfig(
    'enable: oui\ntimeout_seconds: 1\nshipper_name: a b\nshipper_image: x;y\nshipper_host_data_path: relatif\nshipper_host_logs_path: /a/../b\ninstance: "a b"\ntoken: court\n', ENVD);
  assert.ok(r.errors.length >= 8, r.errors.join(' | '));
  assert.strictEqual(r.config.timeoutSeconds, 10);
  assert.strictEqual(r.config.shipperName, 'ngx-shipper');
  assert.strictEqual(r.config.shipperHostDataPath, '');
  assert.ok(r.readBlockers.includes('invalid') && r.shipperBlockers.includes('invalid'));
});
check('un jeton invalide n apparait jamais dans les erreurs', () => {
  const bad = 'secret value with spaces';
  const r = S.normalizeLogstoreConfig('token: ' + bad + '\n', ENVD);
  assert.ok(r.errors.length);
  assert.ok(!r.errors.join('|').includes(bad));
  assert.strictEqual(r.config.token, '');
});
check('publicView : aucun jeton, seulement des indicateurs', () => {
  const r = S.normalizeLogstoreConfig(`enable: true\nurl: https://l.example.com\ntoken: ${TOK}\nshipper_sink_token: ${TOK}\n`, ENVD);
  const v = S.publicView(r.config);
  assert.ok(!JSON.stringify(v).includes(TOK));
  assert.strictEqual(v.tokenSet, true); assert.strictEqual(v.sinkTokenSet, true);
  assert.ok(!('token' in v) && !('sinkToken' in v));
});
check('localShipperUrl : nom du conteneur + port fixe', () => {
  assert.strictEqual(S.localShipperUrl({ shipperName: 'ngx-shipper' }), 'http://ngx-shipper:9181');
});

console.log('\nediteur de configuration : masquage des jetons');
check('token et shipper_sink_token masques puis restaures a l identique', () => {
  const SEC = require('../lib/secrets');
  const t = 'enable: true\nurl: https://x\ntoken: lgs_AAAA\nshipper_sink_token: lgs_BBBB\n';
  const m = SEC.maskSecretsInConfig(t);
  assert.ok(!m.includes('lgs_AAAA') && !m.includes('lgs_BBBB'));
  assert.strictEqual(SEC.unmaskSecrets(m, t), t);
});

console.log('\nbuildShipperSpec()');
const base = () => S.normalizeLogstoreConfig(
  `enable: true\nurl: https://l.example.com\ntoken: ${TOK}\nshipper_enable: true\nshipper_sink_token: ${TOK}\nshipper_host_data_path: /srv/shipper\ninstance: web1\n`, ENVD).config;
check('env complet, binds, entrypoint', () => {
  const sp = C.buildShipperSpec(base(), { localToken: 'L'.repeat(30), network: 'nginx-net', tz: 'Europe/Paris' });
  assert.strictEqual(sp.Image, 'reg/analyzer:1');
  assert.deepStrictEqual(sp.Entrypoint, ['/usr/local/bin/shipper']);
  for (const e of ['LOGSINK_URL=https://l.example.com', 'LOGSINK_TOKEN=' + TOK, 'LOGSINK_INSTANCE=web1', 'LOGSINK_ALLOW_INSECURE=false',
    'LOGSINK_SPOOL_DIR=/data/spool', 'LOGSHIP_DIR=/nginx/logs', 'LOGSHIP_STATE_FILE=/data/offsets.json', 'LOGSHIP_LISTEN=0.0.0.0:9181',
    'LOGSHIP_LOCAL_TOKEN=' + 'L'.repeat(30), 'LOGSHIP_BLOCKLIST=true', 'LOGSHIP_COUNTRY=false', 'TZ=Europe/Paris']) {
    assert.ok(sp.Env.includes(e), e);
  }
  assert.deepStrictEqual(sp.HostConfig.Binds, ['/host/logs:/nginx/logs:ro', '/srv/shipper:/data']);
  assert.strictEqual(sp.HostConfig.NetworkMode, 'nginx-net');
});
check('durcissement : aucun port publie, rootfs RO, capacites retirees, limites', () => {
  const sp = C.buildShipperSpec(base(), { localToken: 'L'.repeat(30) });
  const h = sp.HostConfig;
  assert.strictEqual(h.PortBindings, undefined);
  assert.strictEqual(sp.ExposedPorts, undefined);
  assert.strictEqual(h.ReadonlyRootfs, true);
  assert.deepStrictEqual(h.CapDrop, ['ALL']);
  assert.deepStrictEqual(h.SecurityOpt, ['no-new-privileges:true']);
  assert.ok(h.Memory > 0 && h.PidsLimit > 0);
  assert.strictEqual(h.Privileged, undefined);
  assert.ok(sp.Healthcheck && sp.Healthcheck.Test.includes('healthcheck'));
  assert.strictEqual(sp.Labels['nginx-dashboard.role'], 'shipper');
});
check('jeton local ou jeton d envoi absent : refus', () => {
  assert.throws(() => C.buildShipperSpec(base(), {}), /jeton local/);
  assert.throws(() => C.buildShipperSpec({ ...base(), sinkToken: '' }, { localToken: 'x'.repeat(30) }), /manquant/);
});
check('TZ invalide ignore', () => {
  const sp = C.buildShipperSpec(base(), { localToken: 'L'.repeat(30), tz: 'a b;c' });
  assert.ok(!sp.Env.some(e => e.startsWith('TZ=')));
});
check('analyseur (#110) transmis seulement si URL valide et jeton presents', () => {
  const env = (o) => C.buildShipperSpec(base(), { localToken: 'L'.repeat(30), ...o }).Env;
  const has = (e) => e.some(x => x.startsWith('LOGSHIP_ANALYZER'));
  const ok = env({ analyzerUrl: 'http://ngx-analyzer:9100', analyzerToken: 'tok' });
  assert.ok(ok.includes('LOGSHIP_ANALYZER_URL=http://ngx-analyzer:9100') && ok.includes('LOGSHIP_ANALYZER_TOKEN=tok'));
  assert.ok(!has(env({})) && !has(env({ analyzerUrl: 'http://ngx-analyzer:9100' })));
  assert.ok(!has(env({ analyzerUrl: 'http://a:9100/x;rm', analyzerToken: 'tok' })));
});
check('blocklist / pays desactivables, allow_insecure propage', () => {
  const c = { ...base(), shipperBlocklist: false, shipperCountry: true, sinkAllowInsecure: true };
  const sp = C.buildShipperSpec(c, { localToken: 'L'.repeat(30) });
  assert.ok(sp.Env.includes('LOGSHIP_BLOCKLIST=false') && sp.Env.includes('LOGSHIP_COUNTRY=true') && sp.Env.includes('LOGSINK_ALLOW_INSECURE=true'));
});
check('geoip (#114) monte en lecture seule seulement si pays active et chemin absolu valide', () => {
  const on = { ...base(), shipperCountry: true };
  const binds = (c, o) => C.buildShipperSpec(c, { localToken: 'L'.repeat(30), ...o }).HostConfig.Binds;
  assert.ok(binds(on, { geoipPath: '/data/geoip' }).includes('/data/geoip:/geoip:ro'));
  assert.ok(!binds({ ...on, shipperCountry: false }, { geoipPath: '/data/geoip' }).some(b => b.includes('/geoip')));
  assert.ok(!binds(on, {}).some(b => b.includes('/geoip')));
  assert.ok(!binds(on, { geoipPath: 'rel/geoip' }).some(b => b.includes('/geoip')));
  assert.ok(!binds(on, { geoipPath: '/a:/etc;x' }).some(b => b.includes('/geoip')));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
