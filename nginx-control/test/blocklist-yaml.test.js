'use strict';
const assert = require('assert');
const { parseBlocklistYaml, validateSource, parseAndValidate } = require('../lib/blocklist-yaml');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nparseBlocklistYaml() — syntaxe');
check('cles racine + une source, tout parse correctement', () => {
  const text = [
    'enable: true',
    'interval_cron: "0 3 * * *"',
    'block_action: deny_403',
    'sources:',
    '  - name: datashield',
    '    url: "https://example.org/list.txt"',
    '    enable: true',
  ].join('\n');
  const { config, sources, errors } = parseBlocklistYaml(text);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(config.enable, true);
  assert.strictEqual(config.interval_cron, '0 3 * * *');
  assert.strictEqual(config.block_action, 'deny_403');
  assert.strictEqual(sources.length, 1);
  assert.strictEqual(sources[0].name, 'datashield');
  assert.strictEqual(sources[0].url, 'https://example.org/list.txt');
  assert.strictEqual(sources[0].enable, true);
});

check('plusieurs sources, commentaires et lignes vides ignores', () => {
  const text = [
    '# commentaire d en-tete',
    'enable: true',
    '',
    'sources:',
    '  - name: source-un',
    '    url: "https://a.example/list.txt"',
    '  # commentaire au milieu de la liste',
    '  - name: source-deux',
    '    url: "https://b.example/list.txt"',
    '    enable: false',
  ].join('\n');
  const { sources, errors } = parseBlocklistYaml(text);
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(sources.length, 2);
  assert.strictEqual(sources[1].enable, false);
});

check('ligne non reconnue a l interieur de la liste -> erreur avec numero de ligne', () => {
  const text = [
    'sources:',
    '  - name: ok',
    '    url: "https://a.example/list.txt"',
    'ceci n est pas une cle racine valide sans les deux points',
  ].join('\n');
  const { errors } = parseBlocklistYaml(text);
  assert.strictEqual(errors.length, 1);
  assert.ok(errors[0].startsWith('Ligne 4'));
});

check('fichier vide -> aucune source, aucune erreur', () => {
  const { config, sources, errors } = parseBlocklistYaml('');
  assert.deepStrictEqual(config, {});
  assert.deepStrictEqual(sources, []);
  assert.deepStrictEqual(errors, []);
});

console.log('\nvalidateSource()');
check('source valide -> aucune erreur', () => {
  assert.deepStrictEqual(validateSource({ name: 'ok-1', url: 'https://example.org/x.txt' }, new Set()), []);
});
check('nom manquant -> erreur', () => {
  const errs = validateSource({ url: 'https://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"name"')));
});
check('nom avec caracteres invalides -> erreur', () => {
  const errs = validateSource({ name: 'a b/c', url: 'https://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"name"')));
});
check('nom deja utilise -> erreur', () => {
  const seen = new Set(['dup']);
  const errs = validateSource({ name: 'dup', url: 'https://example.org/x.txt' }, seen);
  assert.ok(errs.some(e => e.includes('deja utilise')));
});
check('url manquante -> erreur', () => {
  const errs = validateSource({ name: 'ok-1' }, new Set());
  assert.ok(errs.some(e => e.includes('"url"')));
});
check('url sans schema http(s) -> erreur (evite ftp://, file://, etc.)', () => {
  const errs = validateSource({ name: 'ok-1', url: 'ftp://example.org/x.txt' }, new Set());
  assert.ok(errs.some(e => e.includes('"url"')));
});

console.log('\nparseAndValidate()');
check('une source invalide n empeche pas les autres d etre retenues', () => {
  const text = [
    'sources:',
    '  - name: bonne-source',
    '    url: "https://a.example/list.txt"',
    '  - name: "invalide car pas de url"',
    '  - name: autre-bonne',
    '    url: "https://b.example/list.txt"',
  ].join('\n');
  const { valid, errors } = parseAndValidate(text);
  assert.strictEqual(valid.length, 2);
  assert.deepStrictEqual(valid.map(s => s.name), ['bonne-source', 'autre-bonne']);
  assert.ok(errors.length >= 1);
});

check('parametres par defaut appliques quand absents', () => {
  const { settings } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(settings.enable, true);
  assert.strictEqual(settings.intervalCron, '0 */6 * * *');
  assert.strictEqual(settings.blockAction, 'deny_403');
  assert.strictEqual(settings.hitLogging.enable, false);
  assert.strictEqual(settings.hitLogging.method, 'dedicated');
});

check('hit_logging_enable/hit_logging_method lus quand presents', () => {
  const { settings } = parseAndValidate('hit_logging_enable: true\nhit_logging_method: approx\nsources: []');
  assert.strictEqual(settings.hitLogging.enable, true);
  assert.strictEqual(settings.hitLogging.method, 'approx');
});

check('hit_logging_method invalide retombe sur dedicated', () => {
  const { settings } = parseAndValidate('hit_logging_method: n_importe_quoi\nsources: []');
  assert.strictEqual(settings.hitLogging.method, 'dedicated');
});

check('block_action invalide retombe sur deny_403 (jamais une valeur non reconnue par le generateur de snippet)', () => {
  const { settings } = parseAndValidate('block_action: rm_rf_slash\nsources: []');
  assert.strictEqual(settings.blockAction, 'deny_403');
});

check('enable: false au niveau racine est respecte', () => {
  const { settings } = parseAndValidate('enable: false\nsources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(settings.enable, false);
});

check('source enable par defaut a true si absent', () => {
  const { valid } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(valid[0].enable, true);
});

console.log('\nsource type: analyzer (retour utilisateur v12.49.4 — liste generee depuis les regles Analyse)');
check('type absent -> "url" (retro-compatible, aucune config existante ne casse)', () => {
  const { valid } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.strictEqual(valid[0].type, 'url');
});
check('type: analyzer -> aucune url requise', () => {
  const errs = validateSource({ name: 'auto', type: 'analyzer' }, new Set());
  assert.deepStrictEqual(errs, []);
});
check('type invalide -> erreur explicite', () => {
  const errs = validateSource({ name: 'x', type: 'ftp' }, new Set());
  assert.ok(errs.some(e => e.includes('"type"')));
});
// v12.50.0 : threshold/window_hours/remediation/min_severity ne se
// configurent plus au niveau de la source — voir
// nginx-analyzer/lib/rules-manager.js#listBlocklistRules(). Une source
// "analyzer" n a donc plus que name/type/enable.
check('type: analyzer -> seulement name/type/enable, aucun champ threshold/window/remediation ici', () => {
  const { valid } = parseAndValidate('sources:\n  - name: auto\n    type: analyzer');
  assert.deepStrictEqual(valid[0], { name: 'auto', type: 'analyzer', enable: true });
});
check('une source analyzer coexiste avec une source url dans la meme config', () => {
  const { valid, errors } = parseAndValidate([
    'sources:',
    '  - name: datashield',
    '    url: "https://a.example/list.txt"',
    '  - name: analyzer-auto',
    '    type: analyzer',
  ].join('\n'));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(valid.length, 2);
  assert.strictEqual(valid[0].type, 'url');
  assert.strictEqual(valid[1].type, 'analyzer');
});

console.log('\nwhitelist (retour utilisateur v12.50.0 — IP/CIDR jamais bloquees, ex: plages privees)');
check('une IP simple et un bloc CIDR sont acceptes', () => {
  const { whitelist, errors } = parseAndValidate('whitelist:\n  - "203.0.113.10"\n  - "10.0.0.0/8"');
  assert.deepStrictEqual(errors, []);
  assert.deepStrictEqual(whitelist, ['203.0.113.10', '10.0.0.0/8']);
});
check('une entree invalide est signalee avec son numero de ligne, sans bloquer les autres', () => {
  const { whitelist, errors } = parseAndValidate('whitelist:\n  - "203.0.113.10"\n  - "pas-une-ip"\n  - "10.0.0.0/8"');
  assert.deepStrictEqual(whitelist, ['203.0.113.10', '10.0.0.0/8']);
  assert.ok(errors.some(e => e.includes('Ligne 3') && e.includes('pas-une-ip')));
});
check('whitelist absente -> liste vide, aucune erreur', () => {
  const { whitelist, errors } = parseAndValidate('sources:\n  - name: x\n    url: "https://a.example/list.txt"');
  assert.deepStrictEqual(whitelist, []);
  assert.deepStrictEqual(errors, []);
});
check('whitelist et sources coexistent, dans n importe quel ordre', () => {
  const { valid, whitelist, errors } = parseAndValidate([
    'whitelist:',
    '  - "10.0.0.0/8"',
    'sources:',
    '  - name: x',
    '    url: "https://a.example/list.txt"',
  ].join('\n'));
  assert.deepStrictEqual(errors, []);
  assert.strictEqual(valid.length, 1);
  assert.deepStrictEqual(whitelist, ['10.0.0.0/8']);
});
check('une adresse IPv6 (contient des ":") n est jamais confondue avec une entree "cle: valeur"', () => {
  const { whitelist, errors } = parseAndValidate('whitelist:\n  - "2001:db8::/32"');
  assert.deepStrictEqual(errors, []);
  assert.deepStrictEqual(whitelist, ['2001:db8::/32']);
});

console.log('\nsource type: waf');
const pv = (lines) => parseAndValidate(['enable: true', 'sources:', ...lines].join('\n'));
check('waf + list: block|challenge valides ; challenge force l action challenge', () => {
  const r = pv(['  - name: w1', '    type: waf', '    list: block', '  - name: w2', '    type: waf', '    list: challenge']);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.valid.length, 2);
  assert.strictEqual(r.valid[0].list, 'block'); assert.strictEqual(r.valid[0].action, null);
  assert.strictEqual(r.valid[1].action, 'challenge');
});
check('waf + action sur la liste block : conservee', () => {
  const r = pv(['  - name: w1', '    type: waf', '    list: block', '    action: drop_444']);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.valid[0].action, 'drop_444');
});
check('waf sans list, list inconnue, url, list sur une source url : erreurs', () => {
  assert.ok(pv(['  - name: w', '    type: waf']).errors.length >= 1);
  assert.ok(pv(['  - name: w', '    type: waf', '    list: nope']).errors.length >= 1);
  assert.ok(pv(['  - name: w', '    type: waf', '    list: block', '    url: "https://x.example/l.txt"']).errors.length >= 1);
  assert.ok(pv(['  - name: u', '    url: "https://x.example/l.txt"', '    list: block']).errors.length >= 1);
});
check('waf + challenge + action contradictoire : erreur de config', () => {
  assert.ok(pv(['  - name: w', '    type: waf', '    list: challenge', '    action: drop_444']).errors.length >= 1);
});

check('v12.70.4 : champs decales d\'un espace (5 espaces) acceptes, source waf valide', () => {
  const r = pv(['  - name: waf-block', '     type: waf', '     list: block', '     enable: true']);
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.valid.length, 1); assert.strictEqual(r.valid[0].type, 'waf'); assert.strictEqual(r.valid[0].list, 'block');
});

check('v12.73.0 : source type challenge valide (sans url/list), action deny_403 ou drop_444', () => {
  const r = pv(['  - name: challenge-bans', '    type: challenge', '    action: drop_444']);
  assert.deepStrictEqual(r.errors, []);
  assert.deepStrictEqual(r.valid[0], { name: 'challenge-bans', type: 'challenge', enable: true, action: 'drop_444' });
});
check('v12.73.0 : source challenge refuse url et action challenge', () => {
  assert.ok(pv(['  - name: c', '    type: challenge', '    url: https://x.tld/l']).errors.length);
  assert.ok(pv(['  - name: c', '    type: challenge', '    action: challenge']).errors.length);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
