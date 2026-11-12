'use strict';
/**
 * Extraction TOLÉRANTE des virtual hosts depuis les modules `inventory` (et `traffic`) d'un dashboard.
 * Le contrat ne fige que le nom des parties : `inventory.vhosts` (« fichiers de site, blocs server, noms, backends/upstreams, état »)
 * a la forme de l'API interne du dashboard. On parcourt donc la structure à la recherche de noms d'hôtes plausibles.
 * Sortie normalisée : [{ name, upstream, backend_kind, targets, state, file, listen, tls, cert_days, requests, errors, bytes }].
 */

const HOST = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^localhost$/i;
const NAME_KEYS = ['server_name', 'server_names', 'servername', 'servernames', 'names', 'name', 'domains', 'domain', 'hostname', 'host', 'vhost', 'hosts'];
const CHILD_KEYS = ['servers', 'blocks', 'server_blocks', 'sites', 'vhosts', 'items', 'files', 'list', 'entries', 'data', 'rows', 'locations'];
const FILEEXT = /\.(conf|disable|disabled|bak|sample|inc|old|orig|save|tmp)$/i;
const BACKEND_KEY = /(proxy|upstream|backend|pass|target|destination)/i;
const MAX_NODES = 20000;
const MAX_OUT = 5000;

const snake = (k) => String(k).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const clip = (s, n = 200) => String(s).slice(0, n);

function hostsFrom(v) {
  const out = [];
  const add = (s) => { if (typeof s === 'string') for (const p of s.split(/[\s,;]+/)) if (p && p !== '_' && !FILEEXT.test(p) && HOST.test(p)) out.push(p.toLowerCase()); };
  if (Array.isArray(v)) v.forEach((x) => add(x)); else add(v);
  return out;
}

const pick = (o, keys) => { for (const k of Object.keys(o)) { if (keys.includes(snake(k)) && o[k] !== null && o[k] !== undefined && typeof o[k] !== 'object') return o[k]; } return undefined; };
function listish(o, keys) {
  for (const k of Object.keys(o)) {
    if (!keys.includes(snake(k))) continue;
    const v = o[k];
    if (Array.isArray(v)) { const r = v.map((x) => (isObj(x) ? pick(x, ['url', 'address', 'server', 'target', 'host', 'name']) : x)).filter((x) => typeof x === 'string' || typeof x === 'number').slice(0, 5).join(', '); return r || undefined; }
    if (typeof v === 'string' || typeof v === 'number') return String(v);
  }
  return undefined;
}

/** Cherche récursivement (profondeur 4) les valeurs texte de clés évoquant un backend : proxy_pass, upstream, backend… */
function findBackends(o, depth = 0, out = new Set()) {
  if (depth > 4 || out.size >= 5) return out;
  if (Array.isArray(o)) { for (const x of o.slice(0, 30)) findBackends(x, depth + 1, out); return out; }
  if (!isObj(o)) return out;
  for (const [k, v] of Object.entries(o)) {
    if (BACKEND_KEY.test(k) && typeof v === 'string' && v && v.length < 200) out.add(v);
    else if (BACKEND_KEY.test(k) && Array.isArray(v)) for (const x of v.slice(0, 5)) { if (typeof x === 'string') out.add(x); else if (isObj(x)) { const u = pick(x, ['url', 'address', 'server', 'host', 'name']); if (typeof u === 'string') out.add(u); } }
    else if (typeof v === 'object' && v !== null) findBackends(v, depth + 1, out);
  }
  return out;
}

function extractOne(o, inherited, files) {
  // entrée « fichier de configuration » (x.conf + état activé/désactivé) : ce n'est pas un vhost, on retient seulement l'état du fichier
  const fname = pick(o, ['name', 'file', 'filename', 'path']);
  if (typeof fname === 'string' && FILEEXT.test(fname) && !Object.keys(o).some((k) => ['server_name', 'server_names', 'servername', 'domains', 'domain'].includes(snake(k)))) {
    const st = pick(o, ['enabled', 'state', 'status', 'active']);
    if (st !== undefined) files.set(fname.split('/').pop(), st);
    return null;
  }
  const names = [];
  for (const k of Object.keys(o)) if (NAME_KEYS.includes(snake(k))) names.push(...hostsFrom(o[k]));
  if (!names.length) return null;
  const state = pick(o, ['state', 'status', 'enabled', 'active', 'health']);
  // forme réelle du dashboard : locations[{ path, kind, raw: 'http://x_upstream' | '$backend', targets:[…] }]
  const locRaw = Array.isArray(o.locations) ? [...new Set(o.locations.map((l) => (isObj(l) ? [pick(l, ['raw', 'proxy_pass']), listish(l, ['targets'])] : [])).flat().filter((x) => typeof x === 'string' && x))] : [];
  const upstream = (locRaw.length ? locRaw.slice(0, 5).join(', ') : undefined) || listish(o, ['upstream', 'upstreams', 'backend', 'backends', 'proxy_pass', 'target', 'targets', 'locations_backends']) || (() => {
    const f = [...findBackends(o)];
    if (f.length) return f.join(', ');
    // proxy_pass dans des locations imbriquées
    const loc = Array.isArray(o.locations) ? o.locations : null;
    if (!loc) return undefined;
    const set = new Set(loc.map((l) => (isObj(l) ? pick(l, ['proxy_pass', 'upstream', 'backend']) : null)).filter((x) => typeof x === 'string'));
    return set.size ? [...set].slice(0, 5).join(', ') : undefined;
  })();
  // #68 : type de backend (`kind` : docker | upstream | variable | unresolved…) et cibles résolues ; schéma additif, absent = rendu inchangé
  const kinds = new Set(); const tg = new Set();
  if (Array.isArray(o.locations)) {
    for (const l of o.locations) {
      if (!isObj(l)) continue;
      if (typeof l.kind === 'string' && /^[a-z_-]{1,20}$/i.test(l.kind)) kinds.add(l.kind.toLowerCase());
      if (Array.isArray(l.targets)) for (const x of l.targets.slice(0, 10)) {
        if (typeof x === 'string' && x) tg.add(clip(x, 80));
        else if (isObj(x) && typeof x.host === 'string' && x.host) tg.add(clip(x.port !== undefined && x.port !== null ? `${x.host}:${x.port}` : x.host, 80));
      }
    }
  }
  const file = pick(o, ['file', 'filename', 'path', 'source_file', 'conf']) ?? inherited.file;
  const listen = listish(o, ['listen', 'ports', 'port']);
  const tlsRaw = pick(o, ['ssl', 'tls', 'https', 'has_ssl']);
  return [...new Set(names)].map((name) => ({
    name,
    upstream: upstream !== undefined ? clip(upstream) : undefined,
    backend_kind: kinds.size ? [...kinds].slice(0, 4).join(', ') : undefined,
    targets: tg.size ? [...tg].slice(0, 5) : undefined,
    state: state === undefined ? undefined : typeof state === 'boolean' ? (state ? 'enabled' : 'disabled') : clip(state, 40),
    file: file !== undefined ? clip(file) : undefined,
    listen: listen !== undefined ? clip(listen, 60) : undefined,
    tls: typeof tlsRaw === 'boolean' ? tlsRaw : undefined,
  }));
}

function walk(node, inherited, out, budget, depth) {
  if (budget.n-- <= 0 || depth > 8 || out.length >= MAX_OUT) return;
  if (Array.isArray(node)) { for (const x of node) walk(x, inherited, out, budget, depth + 1); return; }
  if (!isObj(node)) return;
  const here = extractOne(node, inherited, budget.files);
  const file = pick(node, ['file', 'filename', 'path', 'source_file']) ?? inherited.file;
  if (here) { out.push(...here); if (!Object.keys(node).some((k) => CHILD_KEYS.includes(snake(k)) && k !== 'locations')) return; }
  // clés d'une map { "<vhost>": {...} } : le nom d'hôte est la clé
  for (const [k, v] of Object.entries(node)) {
    if (HOST.test(k) && isObj(v) && !here) {
      const r = extractOne({ name: k, ...v }, { file }, budget.files) || [{ name: k.toLowerCase() }];
      out.push(...r);
    } else if (typeof v === 'object' && v !== null && (CHILD_KEYS.includes(snake(k)) || !here)) {
      walk(v, { file }, out, budget, depth + 1);
    }
  }
}

function certDays(certs) {
  /** @type {{names: string[], days: number}[]} */
  const list = [];
  const src = Array.isArray(certs) ? certs : (certs && Array.isArray(certs.certificates) ? certs.certificates : []);
  for (const c of src) {
    if (!isObj(c)) continue;
    const names = [];
    for (const k of Object.keys(c)) if (['domains', 'domain', 'names', 'name', 'sans', 'san', 'subject', 'cn', 'common_name'].includes(snake(k))) names.push(...hostsFrom(c[k]));
    let days = pick(c, ['days_left', 'daysleft', 'days_remaining', 'days']);
    if (typeof days !== 'number') {
      const na = pick(c, ['not_after', 'notafter', 'expires', 'expiry', 'valid_to']);
      const ms = typeof na === 'number' ? (na < 1e11 ? na * 1000 : na) : Date.parse(na);
      days = Number.isFinite(ms) ? Math.floor((ms - Date.now()) / 86400e3) : undefined;
    }
    if (names.length && typeof days === 'number') list.push({ names, days });
  }
  return list;
}
const covers = (pattern, host) => pattern === host || (pattern.startsWith('*.') && host.endsWith(pattern.slice(1)) && host.split('.').length === pattern.split('.').length);

/**
 * @param {object|null} inventory data du module inventory
 * @param {object|null} traffic   data du module traffic
 * @param {Array} [summaryTop]    top_vhosts du résumé (repli quand ni inventory ni traffic ne donnent de noms)
 */
function extractVhosts(inventory, traffic, summaryTop) {
  const map = new Map();
  const upsert = (v) => { const cur = map.get(v.name) || { name: v.name }; for (const [k, x] of Object.entries(v)) if (x !== undefined && cur[k] === undefined) cur[k] = x; map.set(v.name, cur); };

  const out = [];
  const budget = { n: MAX_NODES, files: new Map() };
  if (inventory && inventory.vhosts !== undefined) walk(inventory.vhosts, {}, out, budget, 0);
  for (const v of out) if (v.state === undefined && v.file) { const st = budget.files.get(String(v.file).split('/').pop()); if (st !== undefined) v.state = typeof st === 'boolean' ? (st ? 'enabled' : 'disabled') : clip(st, 40); }
  out.forEach(upsert);

  const certs = inventory ? certDays(inventory.certificates) : [];
  const trows = [];
  if (traffic && traffic.vhosts !== undefined) {
    const tv = traffic.vhosts;
    const rows = Array.isArray(tv) ? tv : (isObj(tv) && Array.isArray(tv.vhosts) ? tv.vhosts : isObj(tv) ? Object.entries(tv).map(([k, v]) => (isObj(v) ? { name: k, ...v } : { name: k, requests: v })) : []);
    for (const r of rows) if (isObj(r)) trows.push(r);
  }
  for (const r of (Array.isArray(summaryTop) ? summaryTop : [])) if (isObj(r)) trows.push(r);
  for (const r of trows) {
    const name = hostsFrom(pick(r, ['name', 'vhost', 'host', 'domain', 'server_name']))[0];
    if (!name) continue;
    const num = (keys) => { const v = pick(r, keys); return typeof v === 'number' ? v : undefined; };
    const cur = map.get(name);
    const rec = { name, requests: num(['requests', 'count', 'total', 'hits']), errors: num(['errors', 'error', 'errs']), bytes: num(['bytes', 'bytes_sent', 'size']) };
    if (cur) { for (const [k, x] of Object.entries(rec)) if (x !== undefined && cur[k] === undefined) cur[k] = x; } else map.set(name, Object.fromEntries(Object.entries(rec).filter(([, x]) => x !== undefined)));
  }
  const res = [...map.values()].slice(0, MAX_OUT);
  for (const v of res) {
    const c = certs.filter((x) => x.names.some((p) => covers(p, v.name)));
    if (c.length) v.cert_days = Math.min(...c.map((x) => x.days));
  }
  return res.sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { extractVhosts, HOST };
