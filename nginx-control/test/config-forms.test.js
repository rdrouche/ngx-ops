'use strict';
// Moteur des formulaires de configuration (#102) : validation, mise a jour ligne par ligne, secrets, couverture des fichiers.
const assert = require('assert');
const F = require('../lib/config-forms');
const { SCHEMAS } = require('../lib/config-schemas');

let fail = 0;
function check(name, fn) { try { fn(); console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }
const S = { fields: [
  { key: 'enable', type: 'bool' }, { key: 'port', type: 'int', min: 1, max: 65535 }, { key: 'mode', type: 'enum', options: ['a', 'b'] },
  { key: 'webroot', type: 'path' }, { key: 'url', type: 'url' }, { key: 'cron', type: 'cron' }, { key: 'email', type: 'email' },
  { key: 'token', type: 'secret' }, { key: 'pat', type: 'regex' }, { key: 'name', type: 'string', pattern: /^[a-z]+$/ },
] };

check('validate : types et bornes', () => {
  assert.ok(F.validate({ type: 'int', min: 1, max: 10 }, '11').err);
  assert.strictEqual(F.validate({ type: 'int', min: 1, max: 10 }, '5').v, '5');
  assert.ok(F.validate({ type: 'int' }, '1.5').err);
  assert.ok(F.validate({ type: 'path' }, 'relatif').err);
  assert.ok(F.validate({ type: 'path' }, '/a/../b').err);
  assert.strictEqual(F.validate({ type: 'path' }, '/containers/ngx-ops/nginx/logs').v, '/containers/ngx-ops/nginx/logs');
  assert.ok(F.validate({ type: 'url' }, 'ftp://x').err);
  assert.ok(F.validate({ type: 'url' }, 'https://u:p@x.tld').err);
  assert.ok(F.validate({ type: 'cron' }, '0 */6 * * * *').err);
  assert.ok(F.validate({ type: 'regex' }, '(').err);
  assert.ok(F.validate({ type: 'string' }, 'a"b').err);
  assert.ok(F.validate({ type: 'string' }, 'a\nb').err);
  assert.ok(F.validate({ type: 'enum', options: ['x'] }, 'y').err);
  assert.ok(F.validate({ type: 'string', pattern: /^[a-z]+$/ }, 'A').err);
});
check('applyForm : conserve commentaires, cles inconnues et listes ; remplace en place', () => {
  const prev = '# entete\nenable: false\nunknown: 1\n# note\nport: 80\nsources:\n  - a\n';
  const r = F.applyForm(S, { enable: true, port: 8080 }, prev);
  assert.ok(r.ok);
  assert.strictEqual(r.text, '# entete\nenable: true\nunknown: 1\n# note\nport: 8080\nsources:\n  - a\n');
});
check('applyForm : valeur vide supprime la cle, absent = inchange, nouvelle cle ajoutee', () => {
  const r = F.applyForm(S, { webroot: '', mode: 'b' }, 'webroot: /x\nport: 1\n');
  assert.strictEqual(r.text, 'port: 1\nmode: b\n');
});
check('applyForm : cron toujours entre guillemets, regex sans guillemets, CRLF conserve', () => {
  const r = F.applyForm(S, { cron: '0 */6 * * *', pat: '(^|[._])access\\.log$' }, 'enable: true\r\n');
  assert.strictEqual(r.text, 'enable: true\r\ncron: "0 */6 * * *"\r\npat: (^|[._])access\\.log$\r\n');
  assert.strictEqual(require('../lib/simple-yaml').parseFlatYaml(r.text).cron, '0 */6 * * *');
});
check('applyForm : erreurs par champ, aucun ecriture partielle', () => {
  const r = F.applyForm(S, { port: 0, name: 'A', enable: true }, 'port: 1\n');
  assert.strictEqual(r.ok, false); assert.ok(r.errors.port && r.errors.name); assert.strictEqual(Object.keys(r.errors).length, 2);
});
check('secrets : jamais dans la vue, masque/vide = conserve, clear_ supprime, nouvelle valeur ecrite', () => {
  const prev = 'token: sekret123\nenable: true\n';
  const v = F.formView(S, prev);
  assert.strictEqual(v.secretSet.token, true); assert.ok(!('token' in v.values)); assert.ok(!JSON.stringify(v).includes('sekret123'));
  assert.strictEqual(F.applyForm(S, { token: '********' }, prev).text, prev);
  assert.strictEqual(F.applyForm(S, { token: '' }, prev).text, prev);
  assert.strictEqual(F.applyForm(S, { clear_token: true }, prev).text, 'enable: true\n');
  assert.strictEqual(F.applyForm(S, { token: 'nouveau-secret' }, prev).text, 'token: nouveau-secret\nenable: true\n');
  assert.ok(F.applyForm(S, { token: 'a b' }, prev).errors.token);
});
check('url avec identifiants existants : masques dans la vue et conserves a la sauvegarde', () => {
  const prev = 'url: https://u:tok@forge.tld/repo.git\n';
  const v = F.formView(S, prev);
  assert.strictEqual(v.values.url, 'https://forge.tld/repo.git'); assert.strictEqual(v.credentials.url, true);
  assert.strictEqual(F.applyForm(S, { url: 'https://forge.tld/repo.git' }, prev).text, prev);
  assert.ok(F.applyForm(S, { url: 'https://x:y@forge.tld/r.git' }, prev).errors.url);
});
check('setKey : une cle commentee n est pas modifiee, doublon : premiere occurrence seule', () => {
  assert.strictEqual(F.setKey('# port: 1\n', 'port', '2'), '# port: 1\nport: 2\n');
  assert.strictEqual(F.setKey('port: 1\nport: 3\n', 'port', '2'), 'port: 2\nport: 3\n');
  assert.strictEqual(F.setKey('', 'a', 'b'), 'a: b\n');
});
check('schemas : chaque fichier de config-editor est classe (formulaire, dedie ou en attente)', () => {
  const { FILES } = require('../features/config-editor');
  for (const f of FILES) {
    const s = SCHEMAS[f.key];
    assert.ok(s, `fichier "${f.key}" sans schema ni classement dans lib/config-schemas.js`);
    assert.ok(s.fields || s.dedicated || s.pending, `${f.key} : ni fields, ni dedicated, ni pending`);
  }
  for (const k of Object.keys(SCHEMAS)) assert.ok(FILES.some((f) => f.key === k), `schema "${k}" sans fichier`);
});
check('schemas : champs bien formes, sans doublon, suggestions connues', () => {
  const types = new Set(['bool', 'int', 'number', 'string', 'enum', 'path', 'url', 'email', 'image', 'regex', 'cron', 'secret']);
  const sug = new Set(['logs', 'goaccess', 'geoip', 'certs', 'ssl', 'backups', 'config', 'webroot', 'analyzer', 'waf', 'waf_rules']);
  for (const [k, s] of Object.entries(SCHEMAS)) {
    if (!s.fields) continue;
    const seen = new Set();
    for (const f of s.fields) {
      assert.ok(types.has(f.type), `${k}.${f.key} : type ${f.type}`); assert.ok(/^[a-z][a-z0-9_]*$/.test(f.key), `${k}.${f.key}`);
      assert.ok(!seen.has(f.key), `${k}.${f.key} en double`); seen.add(f.key);
      if (f.suggest) assert.ok(sug.has(f.suggest), `${k}.${f.key} : suggestion ${f.suggest}`);
      if (f.type === 'path') assert.ok(!f.suggest || sug.has(f.suggest));
      if (f.type === 'enum') assert.ok(f.options && f.options.length);
    }
  }
});

console.log('\n' + (fail ? fail + ' FAIL' : 'tous les tests passent'));
process.exit(fail ? 1 : 0);
