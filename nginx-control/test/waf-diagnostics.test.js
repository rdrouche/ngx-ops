'use strict';
/** lib/waf-diagnostics.js : analyse de la config nginx + conseils du WAF emule. */
const assert = require('assert');
const D = require('../lib/waf-diagnostics');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const ids = (a) => a.map(x => x.id);
const OK_STATUS = { logs: { formats: { waf_json: 1 }, dropped: 0 }, crs: { installed: true, version: 'v4.8.0', rulesLoaded: 700 }, engine: { ready: true } };

console.log('\nscanNginxLogging()');
check('log_format, access_log global, vhost sans log, filtre $is_not_static', () => {
  const r = D.scanNginxLogging([
    { name: 'logging.conf', content: 'log_format waf_json escape=json \'{}\';\naccess_log /var/log/nginx/waf.wafemu.log waf_json;\naccess_log /var/log/nginx/access.log combined_vhost if=$is_not_static;\n' },
    { name: 'a.conf', content: 'server {\n server_name a.example.com;\n access_log off;\n}\nserver {\n server_name b.example.com;\n access_log /x.log combined;\n}\n' },
  ]);
  assert.ok(r.wafJsonDefined && r.wafJsonLogged && r.notStaticFilter);
  assert.deepStrictEqual(r.vhosts.filter(v => v.accessLogOff).map(v => v.name), ['a.example.com']);
});
check('commentaires ignores', () => {
  const r = D.scanNginxLogging([{ name: 'x.conf', content: '# log_format waf_json x;\n# access_log /a waf_json;\n' }]);
  assert.strictEqual(r.wafJsonDefined, false); assert.strictEqual(r.wafJsonLogged, false);
});
check('snippet du contrat : fichier separe, format waf_json', () => {
  assert.ok(D.WAF_JSON_SNIPPET.includes('log_format waf_json escape=json'));
  assert.ok(D.WAF_JSON_SNIPPET.includes('access_log /var/log/nginx/waf.wafemu.log waf_json;'));
});

console.log('\nbuildDiagnostics()');
check('WAF injoignable : un seul conseil', () => assert.deepStrictEqual(ids(D.buildDiagnostics({ status: null })), ['unreachable']));
check('etat sain : crs_ok + waf_json_active, aucun warn', () => {
  const a = D.buildDiagnostics({ status: OK_STATUS, nginx: D.scanNginxLogging([]) });
  assert.deepStrictEqual(ids(a), ['crs_ok', 'waf_json_active']);
  assert.ok(a.every(x => x.level !== 'warn'));
  assert.strictEqual(a[0].titleKey, 'wafemu.diag.crs_ok.title');
});
check('CRS absent / erreur / telechargement', () => {
  const s = (crs) => ids(D.buildDiagnostics({ status: { ...OK_STATUS, crs } }));
  assert.ok(s({ installed: false }).includes('crs_missing'));
  assert.ok(s({ installed: false, lastError: 'boom' }).includes('crs_error'));
  assert.ok(s({ downloading: true }).includes('crs_downloading'));
});
check('combined sans vhost, waf_json absent : snippet propose', () => {
  const a = D.buildDiagnostics({ status: { ...OK_STATUS, logs: { formats: { combined: 2 } } }, nginx: D.scanNginxLogging([]) });
  assert.ok(ids(a).includes('log_combined_no_vhost'));
  const m = a.find(x => x.id === 'waf_json_missing');
  assert.ok(m && m.snippet.includes('waf_json') && m.file === D.WAF_JSON_FILE);
});
check('saturation, regles non fiables, vhosts sans log / sans trafic', () => {
  const nginx = D.scanNginxLogging([{ name: 'a.conf', content: 'server { server_name off.example.com; access_log off; }' }]);
  const a = D.buildDiagnostics({
    status: { ...OK_STATUS, logs: { formats: { waf_json: 1 }, dropped: 5, queueDropped: 5 }, unreliableRules: { combined: [1, 2], waf_json: [2] } },
    vhosts: [{ name: 'idle.example.com', seen: false }, { name: 'off.example.com', seen: false }], nginx,
  });
  assert.ok(['saturation', 'rules_unreliable', 'vhost_log_off', 'vhost_no_traffic'].every(i => ids(a).includes(i)));
  assert.strictEqual(a.find(x => x.id === 'rules_unreliable').vars.count, 2);
  assert.ok(!a.find(x => x.id === 'vhost_no_traffic').vars.names.includes('off.example.com'));
});
check('lignes perdues : saturation, illisibles et moteur non pret sont distingues ; doublons ecartes', () => {
  const a = D.buildDiagnostics({ status: { ...OK_STATUS, logs: { formats: { combined: 1, waf_json: 1 }, dropped: 90, queueDropped: 0, unparsed: 90, unparsedSamples: ['bad line'], notReady: 3, duplicatesSkipped: 12 } }, nginx: D.scanNginxLogging([]) });
  assert.ok(!ids(a).includes('saturation'));
  const u = a.find(x => x.id === 'unparsed');
  assert.ok(u && u.vars.count === 90 && u.snippet === 'bad line');
  assert.ok(ids(a).includes('engine_not_ready') && ids(a).includes('dedup_active'));
});
check('remediation : blocklists / source waf / challenge conseilles', () => {
  const settings = { mode: 'remediate', thresholds: { challenge: 5, block: 10 } };
  const b = (lists) => ids(D.buildDiagnostics({ status: OK_STATUS, settings, lists }));
  assert.ok(b({ blocklistEnabled: false }).includes('blocklist_disabled'));
  assert.ok(b({ blocklistEnabled: true, hasWafSource: false, challengeEnabled: true }).includes('no_waf_source'));
  assert.ok(b({ blocklistEnabled: true, hasWafSource: true, challengeEnabled: false }).includes('challenge_disabled'));
  assert.ok(!ids(D.buildDiagnostics({ status: OK_STATUS, settings: { mode: 'observe' }, lists: {} })).includes('blocklist_disabled'));
});

console.log('\ni18n : cles dynamiques wafemu.* presentes en fr et en');
check('chaque conseil, onglet, blocker, code d erreur, raison de suppression a ses cles', () => {
  const fs = require('fs'), path = require('path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'waf-diagnostics.js'), 'utf8');
  const diagIds = [...new Set([...src.matchAll(/lvl\('([a-z_]+)'/g)].map(m => m[1]))];
  assert.ok(diagIds.length >= 19, String(diagIds.length));
  const keys = [];
  for (const id of diagIds) keys.push(`wafemu.diag.${id}.title`, `wafemu.diag.${id}.detail`);
  for (const t of ['overview', 'rules', 'vhosts', 'lists', 'settings', 'simulator', 'advice']) keys.push('wafemu.tab.' + t);
  for (const b of ['disabled', 'accept_limits', 'host_data_path', 'host_rules_path', 'host_logs_path', 'invalid']) keys.push('wafemu.blocker.' + b);
  for (const c of ['accept_limits_required', 'host_data_path_required', 'host_rules_path_required', 'host_logs_path_required', 'invalid_config', 'disabled', 'unreachable']) keys.push('wafemu.err.' + c);
  for (const r of ['global', 'vhost', 'exception', 'system', 'paranoia']) keys.push('wafemu.sup.' + r);
  for (const l of ['block', 'challenge']) keys.push('wafemu.list.' + l, 'wafemu.lists.' + l, 'blocklists.sources.wafList.' + l);
  for (const m of ['observe', 'remediate']) keys.push('wafemu.mode.' + m);
  for (const l of ['info', 'warn', 'ok']) keys.push('wafemu.adv.level.' + l);
  for (const st of ['active', 'disabled_global', 'disabled_system', 'ignored']) keys.push('wafemu.rstate.' + st);
  const fr = require('../public/assets/lang/fr.json'), en = require('../public/assets/lang/en.json');
  const missing = keys.filter(k => !(k in fr) || !(k in en));
  assert.deepStrictEqual(missing, []);
});
check('jeux de cles wafemu.* identiques en fr et en', () => {
  const fr = require('../public/assets/lang/fr.json'), en = require('../public/assets/lang/en.json');
  const k = (o) => Object.keys(o).filter(x => x.startsWith('wafemu.')).sort();
  assert.deepStrictEqual(k(fr), k(en));
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
