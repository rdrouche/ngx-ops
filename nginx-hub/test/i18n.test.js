'use strict';
// Garde-fous i18n : chaque t('…')/tp('…','…') du code client doit avoir sa traduction anglaise ; pas d'innerHTML dans l'UI.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const JS = path.join(__dirname, '..', 'public', 'assets', 'js');
function walk(d) { return fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.js') ? [path.join(d, e.name)] : [])); }

async function loadEn() { return (await import(path.join(JS, 'i18n-en.js'))).EN; }
const unesc = (s) => s.replace(/\\'/g, "'");

test('chaque t()/tp() littéral possède une entrée EN', async () => {
  const EN = await loadEn(); const missing = [];
  for (const f of walk(JS)) {
    if (f.endsWith('i18n.js') || f.endsWith('i18n-en.js')) continue;
    const src = fs.readFileSync(f, 'utf8');
    const re = /(?<![\w.$])(t|tp)\(\s*'((?:[^'\\\n]|\\.)*)'(?:\s*,\s*'((?:[^'\\\n]|\\.)*)')?/g;
    let m;
    while ((m = re.exec(src))) {
      const keys = m[1] === 'tp' ? [m[2], m[3]] : [m[2]];
      for (const k of keys) if (k && !(unesc(k) in EN)) missing.push(`${path.relative(JS, f)}: ${unesc(k)}`);
    }
  }
  assert.deepStrictEqual(missing, []);
});

test('les paramètres {x} sont identiques en FR et EN', async () => {
  const EN = await loadEn(); const bad = [];
  const ph = (s) => (s.match(/\{\w+\}/g) || []).sort().join();
  for (const [k, v] of Object.entries(EN)) if (ph(k) !== ph(v)) bad.push(k);
  assert.deepStrictEqual(bad, []);
});

test('aucune entrée EN vide ou orpheline de contenu', async () => {
  const EN = await loadEn();
  for (const [k, v] of Object.entries(EN)) assert.ok(typeof v === 'string' && v.trim().length > 0, k);
});

test('l’UI n’utilise jamais innerHTML / outerHTML / insertAdjacentHTML / document.write', () => {
  const bad = [];
  for (const f of walk(JS)) {
    const src = fs.readFileSync(f, 'utf8').replace(/\/\/[^\n]*/g, '');
    if (/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write\(/.test(src)) bad.push(path.relative(JS, f));
  }
  assert.deepStrictEqual(bad, []);
});

test('aucune clé en double dans le dictionnaire EN (la dernière écraserait la première en silence)', () => {
  const src = fs.readFileSync(path.join(JS, 'i18n-en.js'), 'utf8');
  const seen = new Set(); const dup = [];
  for (const m of src.matchAll(/^ {2}"((?:[^"\\]|\\.)*)":/gm)) { if (seen.has(m[1])) dup.push(m[1]); seen.add(m[1]); }
  assert.deepStrictEqual(dup, []);
});
