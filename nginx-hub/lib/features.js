'use strict';
/**
 * Chargeur de features : chaque dossier features/<nom>/index.js exporte
 *   { name, depends?: string[], register(ctx) }
 * Ajouter une fonctionnalité = ajouter un dossier ; aucun autre fichier à modifier.
 * Une feature peut être désactivée via config.features.<nom>: false.
 */
const fs = require('node:fs');
const path = require('node:path');

function discover(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(dir, d.name, 'index.js')))
    .map((d) => require(path.join(dir, d.name, 'index.js')));
}

function order(features) {
  const byName = new Map(features.map((f) => [f.name, f]));
  const out = []; const state = new Map();
  const visit = (f, chain = []) => {
    if (state.get(f.name) === 2) return;
    if (state.get(f.name) === 1) throw new Error('dépendance circulaire : ' + [...chain, f.name].join(' → '));
    state.set(f.name, 1);
    for (const d of f.depends || []) {
      const dep = byName.get(d);
      if (!dep) throw new Error(`feature « ${f.name} » dépend de « ${d} » (absente ou désactivée)`);
      visit(dep, [...chain, f.name]);
    }
    state.set(f.name, 2); out.push(f);
  };
  [...features].sort((a, b) => a.name.localeCompare(b.name)).forEach((f) => visit(f));
  return out;
}

async function loadFeatures(ctx, dir) {
  const enabled = discover(dir).filter((f) => ctx.config.features[f.name] !== false);
  const loaded = [];
  for (const f of order(enabled)) {
    await f.register(ctx);
    loaded.push({ name: f.name, version: f.version || '1' });
    ctx.log.debug('feature chargée', { feature: f.name });
  }
  return loaded;
}

module.exports = { loadFeatures, discover, order };
