'use strict';
/**
 * Taches planifiees sur les conteneurs geres (#111) : redemarrer / mettre a jour / verifier les mises a jour.
 * S'appuie sur le moteur uniforme lib/container-lifecycle.js (memes actions que les boutons des pages, #104/#105).
 * Cibles : un conteneur (id) ou « groupe » = tous les conteneurs actifs partageant une meme image (ex. l'agent Go :
 * analyzer + WAF + shipper) ; valeur `group:<image>`. Les conteneurs dynamiques (GoAccess) ont leur tache propre.
 * Jamais de creation implicite : un conteneur absent est ignore (une tache planifiee ne doit pas en faire apparaitre un).
 */
const lifecycle = require('./container-lifecycle');

const SCHED_GROUP = 'group:';
const SCHED_MAX_VALUE = 100;

const schedCtDescs = () => lifecycle.ids().map((id) => lifecycle.get(id)).filter(Boolean);
const schedCtSafe = (fn, dflt) => { try { return fn(); } catch { return dflt; } };

/** Options du formulaire : chaque conteneur + un groupe par image partagee par au moins 2 conteneurs actifs. */
function schedCtOptions() {
  const ds = schedCtDescs();
  const out = ds.map((d) => ({ value: d.id, label: d.label || d.id }));
  const byImage = new Map();
  for (const d of ds) {
    const img = schedCtSafe(() => (d.enabled() ? d.image() : ''), '');
    if (img) byImage.set(img, [...(byImage.get(img) || []), d]);
  }
  for (const [img, list] of byImage) {
    if (list.length >= 2 && (SCHED_GROUP + img).length <= SCHED_MAX_VALUE) {
      out.unshift({ value: SCHED_GROUP + img, label: `${list.map((d) => d.label || d.id).join(' + ')} (image partagée)` });
    }
  }
  return out;
}

/** Valeurs choisies -> descripteurs uniques (ordre stable) + valeurs inconnues. */
function schedCtResolve(values) {
  const list = Array.isArray(values) ? values : [];
  const seen = new Set(); const descs = []; const unknown = [];
  const push = (d) => { if (!seen.has(d.id)) { seen.add(d.id); descs.push(d); } };
  for (const v of list) {
    if (typeof v !== 'string') continue;
    if (v.startsWith(SCHED_GROUP)) {
      const img = v.slice(SCHED_GROUP.length);
      const members = schedCtDescs().filter((d) => schedCtSafe(() => d.enabled() && d.image() === img, false));
      if (!members.length) unknown.push(v); else members.forEach(push);
    } else {
      const d = lifecycle.get(v);
      if (d) push(d); else unknown.push(v);
    }
  }
  return { descs, unknown };
}

/**
 * Applique `action` (restart | update) a chaque cible, l'une apres l'autre. `deps` : moteur injectable (tests).
 * @returns {{status:'ok'|'error'|'skipped', message:string, done:string[], skipped:string[], errors:string[]}}
 */
async function schedCtRun(action, values, deps = {}) {
  const eng = deps.engine || lifecycle;
  const { descs, unknown } = deps.resolved || schedCtResolve(values);
  const done = []; const skipped = []; const errors = unknown.map((u) => `${u} : cible inconnue`);
  if (!descs.length && !unknown.length) return { status: 'error', message: 'Aucun conteneur sélectionné', done, skipped, errors };
  for (const d of descs) {
    const label = d.label || d.id;
    try {
      const st = await eng.status(d);
      if (!st.enabled || !st.exists) { skipped.push(label); continue; }
      const r = await eng.act(d.id, action);
      if (r && r.ok === false) errors.push(`${label} : ${r.error || 'échec'}`);
      else done.push(label);
    } catch (e) { errors.push(`${label} : ${(e && (e.code || e.message)) || 'erreur'}`); }
  }
  const verb = action === 'update' ? 'mis à jour' : 'redémarré(s)';
  const parts = [];
  if (done.length) parts.push(`${done.join(', ')} : ${verb}`);
  if (skipped.length) parts.push(`ignoré(s) (absent ou désactivé) : ${skipped.join(', ')}`);
  if (errors.length) parts.push(`erreurs : ${errors.join(' ; ')}`);
  const status = errors.length ? 'error' : done.length ? 'ok' : 'skipped';
  return { status, message: parts.join(' — ') || 'Rien à faire', done, skipped, errors };
}

/** Verifie (pull) toutes les images des conteneurs actifs et existants, sans rien appliquer. */
async function schedCtCheckAll(deps = {}) {
  const eng = deps.engine || lifecycle;
  const descs = deps.descs || schedCtDescs();
  const available = []; const errors = []; let checked = 0;
  for (const d of descs) {
    const label = d.label || d.id;
    try {
      const st = await eng.status(d);
      if (!st.enabled || !st.exists) continue;
      const r = await eng.act(d.id, 'check');
      checked += 1;
      if (r && r.ok === false) errors.push(`${label} : ${r.error || 'échec'}`);
      else if (r && (r.updateAvailable || r.imageUpdated)) available.push(label);
    } catch (e) { errors.push(`${label} : ${(e && (e.code || e.message)) || 'erreur'}`); }
  }
  return { checked, available, errors };
}

module.exports = { schedCtOptions, schedCtResolve, schedCtRun, schedCtCheckAll, SCHED_GROUP };
