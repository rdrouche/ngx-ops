'use strict';
/**
 * Chemins HOTE detectes (ticket #103) : le dashboard lit ses propres montages (`docker inspect` sur
 * lui-meme) pour retrouver, quel que soit le compose (ancien /containers/nginx-rproxy, nouveau
 * /containers/ngx-ops...), le chemin hote correspondant a chaque dossier qu'il voit. Sert a pre-remplir
 * les formulaires de configuration et a afficher conteneur + hote. Lecture seule, rien n'est stocke.
 * Les fonctions `normalize` / `hostFor` / `suggestions` sont pures (testees sans Docker).
 */
const os = require('os');
const path = require('path');
const cfg = require('./config');
const docker = require('./docker');

const TTL_MS = 30000;
let cache = null;

/** Reduit la reponse `docker inspect` : montages (bind : chemin hote ; volume : nom, pas de chemin stable) + projet compose. */
function normalize(body) {
  const b = body && typeof body === 'object' ? body : {};
  const labels = (b.Config && b.Config.Labels) || {};
  const mounts = (Array.isArray(b.Mounts) ? b.Mounts : [])
    .filter((m) => m && typeof m.Destination === 'string' && m.Destination)
    .map((m) => ({
      container: m.Destination,
      host: m.Type === 'bind' && typeof m.Source === 'string' ? m.Source : null,
      type: String(m.Type || ''),
      name: m.Type === 'volume' ? String(m.Name || '') : null,
      rw: m.RW !== false,
    }))
    .sort((a, c) => a.container.localeCompare(c.container));
  const dir = labels['com.docker.compose.project.working_dir'];
  const name = labels['com.docker.compose.project'];
  return { mounts, project: dir || name ? { name: name || '', dir: dir || '' } : null };
}

/** Chemin hote d'un chemin conteneur (montage bind le plus specifique), ou null. */
function hostFor(mounts, containerPath) {
  const p = path.posix.normalize(String(containerPath || ''));
  let best = null;
  for (const m of mounts) {
    if (!m.host) continue;
    const dest = path.posix.normalize(m.container);
    if (p === dest || p.startsWith(dest.endsWith('/') ? dest : dest + '/')) {
      if (!best || dest.length > best.dest.length) best = { dest, m };
    }
  }
  if (!best) return null;
  const rest = p.slice(best.dest.length);
  return path.posix.join(best.m.host, rest) || best.m.host;
}

const sibling = (host, name) => (host ? path.posix.join(path.posix.dirname(host), name) : null);

/** Suggestions de chemins hote par usage (`derived` : deduit d'un dossier voisin, a verifier). */
function suggestions(mounts, env = cfg) {
  const direct = (cands) => {
    for (const c of cands.filter(Boolean)) {
      const h = hostFor(mounts, c);
      if (h) return { host: h, container: c, derived: false };
    }
    return null;
  };
  const out = {
    logs: direct([env.DIR_LOGS]),
    goaccess: direct([env.DIR_GOACCESS]),
    geoip: direct([env.DIR_GEOIP, '/geoip']),
    certs: direct([env.DIR_CERTS, '/certificats/certbot']),
    ssl: direct([env.DIR_SSL, '/certificats/ssl']),
    backups: direct([env.DIR_BACKUPS]),
    config: direct([env.CONFIG_DIR]),
  };
  const logs = out.logs && out.logs.host;
  const derive = (key, name) => { if (!out[key] && logs) out[key] = { host: sibling(logs, name), container: null, derived: true }; };
  derive('webroot', 'webroot');
  derive('analyzer', 'analyzer');
  derive('waf', 'waf');
  derive('waf_rules', 'waf-rules');
  if (!out.geoip) derive('geoip', 'geoip_data');
  for (const k of Object.keys(out)) if (!out[k]) delete out[k];
  return out;
}

async function inspectSelf() {
  for (const id of [process.env.HOSTNAME, os.hostname()].filter(Boolean)) {
    try {
      const r = await docker.dockerCall('GET', `/containers/${encodeURIComponent(id)}/json`);
      if (r && r.status === 200 && r.body) return r.body;
    } catch { /* candidat suivant */ }
  }
  return null;
}

/** { available, project, mounts, suggestions } — detection impossible (socket absent) : available=false, rien d'invente. */
async function detect({ fresh = false } = {}) {
  if (!fresh && cache && Date.now() - cache.at < TTL_MS) return cache.value;
  const body = await inspectSelf();
  let value;
  if (!body) value = { available: false, project: null, mounts: [], suggestions: {} };
  else {
    const n = normalize(body);
    value = { available: true, project: n.project, mounts: n.mounts, suggestions: suggestions(n.mounts) };
  }
  cache = { at: Date.now(), value };
  return value;
}

module.exports = { normalize, hostFor, suggestions, detect };
