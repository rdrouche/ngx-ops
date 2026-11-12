'use strict';
/**
 * Cycle de vie uniforme des conteneurs geres par le dashboard (#104, #105).
 * Chaque integration (analyseur, WAF, shipper, ...) declare un descripteur ; les actions sont les memes partout :
 *   start (demarre l'existant, ou cree), restart, recreate (supprime puis recree depuis la config),
 *   check (pull + compare, sans rien changer), update (pull puis recree si l'image du conteneur est en retard),
 *   stop (garde le conteneur), down (arrete et supprime).
 * Correction #105 : « en retard » = l'image du CONTENEUR differe de l'image locale actuelle du tag (pas « le pull a
 * change quelque chose »), sinon un 2e / 3e conteneur partageant la meme image n'etait jamais recree apres le 1er pull.
 * Descripteur : { id, label, page?, enabled(), containerName(), image(), create(), mapError?(e) }.
 * `create()` est la fonction existante de l'integration (detruit + recree + demarre depuis la configuration).
 */
const dockerReal = require('./docker');

const ACTIONS = ['start', 'restart', 'recreate', 'update', 'check', 'stop', 'down'];
const NEEDS_ENABLED = new Set(['start', 'restart', 'recreate', 'update', 'check']);
const ID_RE = /^[a-z][a-z0-9-]{0,30}$/;
const PROVIDER_ID_RE = /^([a-z][a-z0-9-]{0,30}):([A-Za-z0-9][A-Za-z0-9._-]{0,99})$/;

const httpError = (status, code, message) => Object.assign(new Error(message || code), { status, code });

function createEngine(dk = dockerReal) {
  const registry = new Map();
  const busy = new Set();
  const enc = encodeURIComponent;

  function registerDescriptor(d) {
    if (!d || !ID_RE.test(d.id || '')) throw new Error('descripteur : id invalide');
    for (const f of ['enabled', 'containerName', 'image', 'create']) if (typeof d[f] !== 'function') throw new Error(`descripteur ${d.id} : ${f}() manquant`);
    registry.set(d.id, d);
    return d;
  }
  // Fournisseurs dynamiques (ex. GoAccess : un conteneur par source de logs) : id « prefixe:cle ».
  //   { resolve(key) -> descripteur|null (sync, sans id), list() -> [cle] des conteneurs existants (async) }
  const providers = new Map();
  function registerProvider(prefix, p) {
    if (!ID_RE.test(prefix || '') || !p || typeof p.resolve !== 'function' || typeof p.list !== 'function') throw new Error('fournisseur invalide');
    providers.set(prefix, p);
  }
  function fromProvider(prefix, key) {
    const p = providers.get(prefix);
    const d = p && p.resolve(key);
    if (!d) return null;
    const full = { ...d, id: `${prefix}:${key}` };
    for (const f of ['enabled', 'containerName', 'image', 'create']) if (typeof full[f] !== 'function') return null;
    return full;
  }
  function get(id) {
    if (typeof id !== 'string') return null;
    if (registry.has(id)) return registry.get(id);
    const m = PROVIDER_ID_RE.exec(id);
    return m ? fromProvider(m[1], m[2]) : null;
  }
  /** Tous les descripteurs : statiques + ceux des fournisseurs (conteneurs existants seulement). */
  async function all() {
    const out = [...registry.values()];
    for (const [prefix, p] of providers) {
      let keys = [];
      try { keys = await p.list(); } catch { keys = []; }
      for (const k of keys) { const d = fromProvider(prefix, k); if (d) out.push(d); }
    }
    return out;
  }
  const ids = () => [...registry.keys()];

  async function inspect(name) {
    const r = await dk.dockerCall('GET', `/containers/${enc(name)}/json`);
    if (r.status === 0) return { exists: false, running: false, name, dockerUnavailable: true, error: r.error };
    if (r.status === 404) return { exists: false, running: false, name };
    if (r.status !== 200) return { exists: false, running: false, name, error: `HTTP ${r.status}` };
    const b = r.body || {};
    return {
      exists: true, running: !!(b.State && b.State.Running === true), status: (b.State && b.State.Status) || 'unknown', name,
      image: (b.Config && b.Config.Image) || '', imageId: b.Image || '', created: b.Created || '', started: (b.State && b.State.StartedAt) || '',
    };
  }

  async function status(d) {
    const enabled = !!d.enabled();
    const imageRef = d.image() || '';
    const st = await inspect(d.containerName());
    const availableImageId = imageRef ? await dk.getImageId(imageRef) : null;
    const outdated = !!(st.exists && st.imageId && availableImageId && st.imageId !== availableImageId);
    return { id: d.id, label: d.label || d.id, page: d.page || null, enabled, imageRef, availableImageId, outdated, ...st };
  }

  async function post(name, verb, query = '') {
    const r = await dk.dockerCall('POST', `/containers/${enc(name)}/${verb}${query}`);
    if (![204, 304].includes(r.status)) throw new Error(`${verb} failed: ${r.status === 0 ? r.error : r.status}`);
  }
  async function removeContainer(name) { await dk.dockerCall('DELETE', `/containers/${enc(name)}?force=true`).catch(() => {}); }

  /** Recree si en retard : un conteneur en marche est recree ; un conteneur arrete est supprime (le prochain demarrage repart d'une image a jour). */
  async function applyUpdate(d, st) {
    if (!st.exists || !st.outdated) return { recreated: false, removedStale: false };
    if (st.running) { await d.create(); return { recreated: true, removedStale: false }; }
    await removeContainer(st.name);
    return { recreated: false, removedStale: true };
  }

  async function runPull(d) {
    const pull = await dk.pullAndCheckUpdate(d.image());
    if (!pull.ok) return { ok: false, error: pull.error || 'pull failed' };
    return { ok: true, imageUpdated: !!pull.updated };
  }

  async function act(id, action) {
    const d = get(id);
    if (!d) throw httpError(404, 'unknown_container');
    if (!ACTIONS.includes(action)) throw httpError(400, 'unknown_action');
    if (busy.has(id)) throw httpError(409, 'busy');
    if (NEEDS_ENABLED.has(action) && !d.enabled()) throw httpError(409, 'disabled');
    busy.add(id);
    try {
      const name = d.containerName();
      if (action === 'recreate') { await d.create(); return { ok: true, action }; }
      const st = await inspect(name);
      if (st.dockerUnavailable) throw httpError(503, 'docker_unavailable', st.error || 'docker unavailable');
      switch (action) {
        case 'start':
          if (st.exists && st.running) return { ok: true, action, noop: true };
          if (st.exists) await post(name, 'start'); else await d.create();
          return { ok: true, action };
        case 'restart':
          if (st.exists) await post(name, 'restart', '?t=10'); else await d.create();
          return { ok: true, action };
        case 'stop':
          if (st.exists) await post(name, 'stop', '?t=10');
          return { ok: true, action, noop: !st.exists };
        case 'down':
          if (st.exists) { await post(name, 'stop', '?t=10').catch(() => {}); await removeContainer(name); }
          return { ok: true, action, noop: !st.exists };
        case 'check': case 'update': {
          const p = await runPull(d);
          if (!p.ok) return { ok: false, action, error: p.error };
          const cur = await status(d);
          if (action === 'check') return { ok: true, action, pulled: true, imageUpdated: p.imageUpdated, updateAvailable: cur.outdated, containerExists: cur.exists, running: cur.running };
          const u = await applyUpdate(d, cur);
          return { ok: true, action, pulled: true, imageUpdated: p.imageUpdated || u.recreated || u.removedStale, wasOutdated: cur.outdated, ...u };
        }
        default: throw httpError(400, 'unknown_action');
      }
    } finally { busy.delete(id); }
  }

  /** Vue d'ensemble : statut de chaque conteneur + autres conteneurs partageant la meme image. */
  async function overview() {
    const list = await Promise.all((await all()).map((d) => status(d).catch((e) => ({ id: d.id, label: d.label || d.id, error: e.message }))));
    for (const s of list) s.peers = list.filter((o) => o.id !== s.id && o.imageRef && o.imageRef === s.imageRef && o.enabled).map((o) => o.id);
    return list;
  }

  /** Un seul pull par image, puis recreation de chaque consommateur actif en retard (apply=false : simple compte rendu). */
  async function updateAll({ image, apply = false } = {}) {
    const consumers = (await all()).filter((d) => d.enabled() && d.image() && (!image || d.image() === image));
    const byImage = new Map();
    for (const d of consumers) { const k = d.image(); byImage.set(k, [...(byImage.get(k) || []), d]); }
    const groups = [];
    for (const [img, ds] of byImage) {
      const pull = await dk.pullAndCheckUpdate(img);
      if (!pull.ok) { groups.push({ image: img, ok: false, error: pull.error || 'pull failed', results: [] }); continue; }
      const results = [];
      for (const d of ds) {
        try {
          if (busy.has(d.id)) { results.push({ id: d.id, label: d.label || d.id, ok: false, error: 'busy' }); continue; }
          const cur = await status(d);
          const r = { id: d.id, label: d.label || d.id, ok: true, exists: cur.exists, running: cur.running, outdated: cur.outdated, recreated: false };
          if (apply && cur.outdated) { busy.add(d.id); try { Object.assign(r, await applyUpdate(d, cur)); } finally { busy.delete(d.id); } }
          results.push(r);
        } catch (e) { results.push({ id: d.id, label: d.label || d.id, ok: false, error: e.message }); }
      }
      groups.push({ image: img, ok: true, imageUpdated: !!pull.updated, results });
    }
    return { ok: groups.every((g) => g.ok), groups };
  }

  return { register: registerDescriptor, registerProvider, get, ids, inspect, status, act, overview, updateAll, ACTIONS };
}

const engine = createEngine();

/** Corps de reponse des anciennes routes `image/update` (meme forme qu'avant), mais avec la nouvelle logique (#105). */
async function legacyImageUpdate(id) {
  try {
    const r = await engine.act(id, 'update');
    if (!r.ok) return { ok: false, error: r.error };
    return { ok: true, pulled: true, updated: !!r.imageUpdated, recreated: !!r.recreated };
  } catch (e) {
    if (e.code === 'docker_unavailable' || e.code === 'busy') return { ok: false, error: e.message };
    if (e.code === 'disabled') throw e;
    return { ok: true, pulled: true, updated: true, recreated: false, recreateError: e.message };
  }
}

module.exports = { createEngine, httpError, legacyImageUpdate };
// Methodes du moteur (register, get, act...) : exposees mais NON enumerables. Des noms aussi generiques que `get` ou
// `register` ne doivent pas entrer dans l'inventaire des exports du socle (test/imports.test.js les croirait
// « appeles sans import » dans tout module qui definit sa propre methode du meme nom).
for (const [k, v] of Object.entries(engine)) Object.defineProperty(module.exports, k, { value: v, enumerable: false });
