'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseYaml } = require('../lib/yaml');
const { loadConfig } = require('../lib/config');

test('yaml : mappings inline imbriqués et listes inline', () => {
  const y = parseYaml('a: { b: 1, c: [x, y], d: { e: true } }\nf: {}\nlist: [1, "a, b"]\n');
  assert.deepStrictEqual(y, { a: { b: 1, c: ['x', 'y'], d: { e: true } }, f: {}, list: [1, 'a, b'] });
  assert.throws(() => parseYaml('a: { sans deux points }'), /mapping inline/);
});

test('config : modules.indicators accepte la forme inline, `true` et "true" ; toute autre forme = désactivé', () => {
  const cfgOf = (txt) => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hubcfg-')), 'hub.yml'); fs.writeFileSync(f, txt); return loadConfig({ file: f, env: {} }); };
  assert.strictEqual(cfgOf('modules:\n  indicators: { enabled: true }\n').modules.indicators.enabled, true);
  assert.strictEqual(cfgOf('modules:\n  indicators:\n    enabled: true\n').modules.indicators.enabled, true);
  assert.strictEqual(cfgOf('modules:\n  indicators: true\n').modules.indicators.enabled, true);
  assert.strictEqual(cfgOf('modules:\n  indicators:\n    enabled: "true"\n').modules.indicators.enabled, true);
  assert.strictEqual(cfgOf('modules:\n  indicators: { enabled: false }\n').modules.indicators.enabled, false);
  assert.strictEqual(cfgOf('modules:\n  indicators: nope\n').modules.indicators.enabled, false);
  const c = cfgOf('modules:\n  intervals_s: { ops: 90 }\n');
  assert.strictEqual(c.modules.intervals_s.ops, 90);
  assert.strictEqual(c.modules.intervals_s.alerts, 60, 'les autres intervalles gardent leur défaut');
});
