// Rendu « intelligent » de données JSON de forme inconnue (contrat 12.78.0 : seules l'enveloppe et les noms de parties sont figés).
// Principe : deviner la nature d'une valeur d'après le NOM de sa clé et sa forme (date, octets, durée, pourcentage, état…),
// puis choisir le meilleur rendu (tableau triable/filtrable, graphique, barres, grille clé/valeur). Aucun HTML injecté : DOM uniquement.
import { h, mount } from './dom.js';
import { t, tr, locale } from './i18n.js';
import { fmt, bytes, dateTime, ago, sevLabel, toast } from './util.js';
import { lineChart, chartBox } from './charts.js';

const MAX_DEPTH = 6;
const snake = (k) => String(k).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

// ── Libellés de colonnes courants (français = clé de traduction) ──
const KEYLABELS = {
  name: 'Nom', vhost: 'Vhost', host: 'Hôte', hostname: 'Hôte', domain: 'Domaine', domains: 'Domaines', server_name: 'Nom du serveur', server_names: 'Noms du serveur',
  status: 'État', state: 'État', enabled: 'Activé', online: 'En ligne', running: 'En marche', active: 'Actif', version: 'Version', type: 'Type', kind: 'Type', severity: 'Sévérité',
  source: 'Source', ts: 'Date', time: 'Heure', hour: 'Heure', date: 'Date', since: 'Depuis', until: 'Jusqu’à', last_seen: 'Dernière activité', last_ok: 'Dernier succès',
  country: 'Pays', count: 'Nombre', total: 'Total', hits: 'Hits', blocked: 'Bloquées', requests: 'Requêtes', errors: 'Erreurs', bytes: 'Volume', humans: 'Humains', robots: 'Robots',
  latency_ms: 'Latence', uptime: 'Disponibilité', uptime_s: 'Durée de fonctionnement', duration: 'Durée', url: 'URL', target: 'Cible', targets: 'Cibles', message: 'Message',
  summary: 'Résumé', description: 'Description', id: 'Identifiant', user: 'Utilisateur', username: 'Utilisateur', action: 'Action', file: 'Fichier', path: 'Chemin',
  upstream: 'Backend', upstreams: 'Backends', backend: 'Backend', backends: 'Backends', listen: 'Écoute', ssl: 'TLS', tls: 'TLS', issuer: 'Émetteur', not_after: 'Expire le', not_before: 'Valide depuis',
  days_left: 'Jours restants', days: 'Jours', rule: 'Règle', rules: 'Règles', scenario: 'Scénario', origin: 'Origine', attempts: 'Tentatives', score: 'Score', ips: 'IP', ip: 'IP',
  protocol: 'Protocole', tunnel_connected: 'Tunnel connecté', vhost_count: 'Vhosts', every: 'Fréquence', schedule: 'Planification', last_run: 'Dernière exécution', next_run: 'Prochaine exécution',
  _key: 'Clé', redirected: 'Redirigées', pages: 'Pages servies', solved: 'Résolus', failed: 'Échoués', rate_limited: 'Limitées (débit)', pass_bot: 'Bots autorisés', offenders: 'Contrevenants', bans: 'Bannissements', first_seen: 'Première activité', attempts_total: 'Tentatives', expired: 'Expirés', warning: 'Avertissement', started: 'Début', reason: 'Raison', last_check: 'Dernier contrôle', cert_days: 'Certificat (jours)', uptime_pct: 'Disponibilité', checked: 'Contrôlé', resolved: 'Résolu', result: 'Résultat', note: 'Remarque', interval: 'Intervalle', next: 'Prochain', ok: 'OK', error: 'Erreur', code: 'Code', method: 'Méthode', size: 'Taille', percent: 'Pourcentage', pct: 'Pourcentage',
};
/** Enregistre des libellés supplémentaires (clé technique snake_case → texte français = clé de traduction). */
export function registerLabels(map) { for (const [k, v] of Object.entries(map)) KEYLABELS[snake(k)] ||= v; }
export function humanKey(k) {
  const s = snake(k);
  if (KEYLABELS[s]) return tr(KEYLABELS[s]);
  const base = s.replace(/_(at|s|ms|pct|percent|bytes|count)$/, '');
  if (base !== s && KEYLABELS[base]) return tr(KEYLABELS[base]);
  const w = base.replace(/[_\-.]+/g, ' ').trim();
  return w.charAt(0).toUpperCase() + w.slice(1);
}

// ── Détection de la nature d'une valeur ──
const RE = {
  time: /(^|_)(ts|time|timestamp|date|datetime|at|hour|day|minute|bucket|slot|since|until|seen|started|ended|created|updated|modified|mtime|expires?|expiry|expiration|not_before|not_after|generated|last_[a-z_]+|next_[a-z_]+|first_[a-z_]+)$/,
  bytes: /(^|_)(bytes?|octets?|size|volume|rx|tx|mem|memory|disk|transferred|traffic)$|_bytes$/,
  ms: /_ms$|^ms$|(^|_)(latency|rtt|response_time)$/,
  dur: /(^|_)(uptime|duration|elapsed|age|ttl)(_s|_sec|_seconds)?$|_seconds$|_secs?$|(^|_)(interval|timeout)_s$/,
  pct: /(pct|percent|percentage)$/,
  ratio: /(ratio|rate|share)$/,
  days: /(^|_)days(_left|_remaining)?$/,
  country: /^(country|country_code|cc)$/,
  ip: /(^|_)(ip|addr|address|remote_addr|client_ip|src_ip)$/,
};
const STATEFR = { up: 'En ligne', down: 'Hors ligne', enabled: 'Activé', disabled: 'Désactivé', resolved: 'Résolu', ok: 'OK', online: 'En ligne', offline: 'Hors ligne', running: 'En marche', active: 'Actif', failed: 'Échec', failure: 'Échec', pending: 'En attente', warning: 'Avertissement', degraded: 'Dégradé', error: 'Erreur', healthy: 'Sain', expired: 'Expiré', stopped: 'Arrêté', success: 'Succès', timeout: 'Délai dépassé', open: 'Ouvert', closed: 'Fermé', unknown: 'Inconnu', connected: 'Connecté', disconnected: 'Déconnecté' };
const OKW = new Set(['ok', 'up', 'online', 'running', 'active', 'enabled', 'success', 'healthy', 'passed', 'resolved', 'closed', 'valid', 'connected', 'ready']);
const WARNW = new Set(['warning', 'warn', 'degraded', 'pending', 'unknown', 'partial', 'slow', 'medium', 'expiring', 'stale', 'starting']);
const ERRW = new Set(['error', 'down', 'offline', 'failed', 'failure', 'critical', 'expired', 'stopped', 'fatal', 'unreachable', 'timeout', 'high', 'open', 'invalid', 'disconnected']);
const SEVW = new Set(['critical', 'high', 'medium', 'low', 'warning', 'info']);

export function toMs(v) {
  if (typeof v === 'number' && Number.isFinite(v)) { if (v >= 1e12 && v < 1e14) return v; if (v >= 1e9 && v < 1e11) return v * 1000; return null; }
  if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?/.test(v)) { const n = Date.parse(v); return Number.isFinite(n) ? n : null; }
  if (typeof v === 'string' && /^\d{10,13}$/.test(v)) return toMs(Number(v));
  return null;
}

export function fmtDuration(s) {
  s = Math.max(0, Math.round(Number(s)));
  const d = Math.floor(s / 86400); const hh = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60);
  if (d) return t('{d} j {h} h', { d, h: hh });
  if (hh) return t('{h} h {m} min', { h: hh, m });
  if (m) return t('{m} min', { m });
  return t('{n} s', { n: s });
}
const fmtMs = (v) => (v < 1000 ? `${Math.round(v)} ms` : `${(v / 1000).toFixed(1).replace('.', locale() === 'fr-FR' ? ',' : '.')} s`);
const fmtNum = (v) => (Number.isInteger(v) ? fmt(v) : new Intl.NumberFormat(locale(), { maximumFractionDigits: 2 }).format(v));
const flag = (cc) => (/^[A-Za-z]{2}$/.test(cc) ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '');

export function dateNode(ms) {
  return h('span', { class: 'nowrap', title: `${new Date(ms).toISOString()} — ${ago(ms)}` }, dateTime(ms));
}
const stateCls = (w) => (OKW.has(w) ? 'ok' : ERRW.has(w) ? 'err' : WARNW.has(w) ? 'warn' : '');

/** @returns {{node: Node|string, sort: number|string|null, text: string}} */
export function smartValue(key, v) {
  const k = snake(key || '');
  if (v === null || v === undefined || v === '') return { node: h('span', { class: 'muted' }, '—'), sort: null, text: '' };
  if (typeof v === 'boolean') return { node: h('span', { class: `badge ${v ? 'ok' : ''}` }, v ? t('Oui') : t('Non')), sort: v ? 1 : 0, text: v ? 'oui' : 'non' };
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return { node: '—', sort: null, text: '' };
    if (RE.days.test(k)) return { node: h('span', { class: `badge ${v < 0 ? 'err' : v <= 14 ? 'warn' : 'ok'}` }, v < 0 ? t('Expiré') : t('{n} j', { n: v })), sort: v, text: String(v) };
    if (RE.bytes.test(k) && !RE.time.test(k)) return { node: h('span', { class: 'num' }, bytes(v)), sort: v, text: bytes(v) };
    if (RE.ms.test(k)) return { node: h('span', { class: 'num' }, fmtMs(v)), sort: v, text: fmtMs(v) };
    if (RE.pct.test(k)) return { node: h('span', { class: 'num' }, `${fmtNum(v)} %`), sort: v, text: `${v} %` };
    if (RE.ratio.test(k) && v >= 0 && v <= 1) return { node: h('span', { class: 'num' }, `${fmtNum(Math.round(v * 1000) / 10)} %`), sort: v, text: `${v * 100} %` };
    if (RE.dur.test(k)) return { node: h('span', { class: 'num' }, fmtDuration(v)), sort: v, text: fmtDuration(v) };
    const ms = toMs(v);
    if (ms !== null && (RE.time.test(k) || (v >= 1.4e12 && !RE.bytes.test(k)) || (v >= 1.5e9 && v < 4e9 && Number.isInteger(v) && !RE.bytes.test(k) && !/(count|total|requests|hits|num|score|port|id)$/.test(k)))) return { node: dateNode(ms), sort: ms, text: dateTime(ms) };
    return { node: h('span', { class: 'num' }, fmtNum(v)), sort: v, text: fmtNum(v) };
  }
  if (typeof v === 'string') {
    const ms = toMs(v);
    if (ms !== null && (RE.time.test(k) || /^\d{4}-\d{2}-\d{2}T/.test(v))) return { node: dateNode(ms), sort: ms, text: dateTime(ms) };
    if (RE.country.test(k) && /^[A-Za-z]{2}$/.test(v)) return { node: h('span', null, `${flag(v)} ${v.toUpperCase()}`), sort: v, text: v };
    const w = v.toLowerCase();
    if (/(^|_)(status|state|health|result|level|severity|outcome)$/.test(k) || OKW.has(w) || ERRW.has(w) || WARNW.has(w)) {
      if (SEVW.has(w) && /sever|level/.test(k)) return { node: h('span', { class: `badge ${stateCls(w)}` }, sevLabel(w)), sort: v, text: v };
      if (OKW.has(w) || ERRW.has(w) || WARNW.has(w)) return { node: h('span', { class: `badge ${stateCls(w)}`, title: v }, STATEFR[w] ? t(STATEFR[w]) : v), sort: v, text: v };
    }
    if (RE.ip.test(k)) return { node: h('span', { class: 'mono' }, v), sort: v, text: v };
    if (v.includes('\n')) { const first = v.split('\n').find((x) => x.trim()) || ''; return { node: h('details', { class: 'inl-det' }, h('summary', null, first.length > 60 ? `${first.slice(0, 57)}…` : first || '…'), h('pre', { class: 'raw mono' }, v)), sort: v, text: v }; }
    if (v.length > 140) return { node: h('span', { title: v }, `${v.slice(0, 137)}…`), sort: v, text: v };
    return { node: v, sort: v, text: v };
  }
  if (Array.isArray(v) && !v.length) return { node: h('span', { class: 'muted' }, '—'), sort: 0, text: '' };
  if (Array.isArray(v) && v.length >= 3 && v.every((x) => typeof x === 'boolean')) {
    return { node: h('span', { class: 'spark', title: t('{n} contrôles : {k} OK', { n: v.length, k: v.filter(Boolean).length }) }, v.slice(-40).map((x) => h('i', { class: x ? 'ok' : 'err' }))), sort: v.filter(Boolean).length / v.length, text: `${v.filter(Boolean).length}/${v.length}` };
  }
  if (Array.isArray(v)) {
    const text = v.every(isScalar) ? v.map((x) => smartValue(key, x).text || String(x)).join(', ') : t('{n} élément(s)', { n: v.length });
    if (v.every(isScalar) && v.length) {
      const shown = v.slice(0, 4).map((x) => h('span', { class: 'chip' }, String(smartValue(key, x).text || x)));
      return { node: h('span', { class: 'chips' }, shown, v.length > 4 ? h('span', { class: 'muted' }, `+${v.length - 4}`) : null), sort: v.length, text };
    }
    return { node: h('span', { class: 'muted' }, text), sort: v.length, text };
  }
  return { node: h('span', { class: 'muted' }, t('{n} champ(s)', { n: Object.keys(v).length })), sort: null, text: '' };
}

const isScalar = (v) => v === null || ['string', 'number', 'boolean'].includes(typeof v);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

// ── Tableaux ──
const NAMEY = /^(name|vhost|vhost_name|host|hostname|domain|domains|server_name|server_names|target|rule|scenario|type|kind|source|user)$/;
const IDENT = /^(id|title|label|description|path|url|status|state|enabled|ok|up)$/;
const TECH = /(^|\.)(block_index|location_index|target_index|index|key)$/;

function flattenRow(row) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (isScalar(v) || (Array.isArray(v) && v.every(isScalar))) out[k] = v;
    else if (isObj(v)) {
      const ent = Object.entries(v).filter(([, x]) => isScalar(x) || (Array.isArray(x) && x.every(isScalar))).slice(0, 8);
      for (const [kk, x] of ent) out[`${k}.${kk}`] = x;
    }
  }
  return out;
}

/** Toutes les colonnes non vides (ordre d'apparition) + sélection par défaut (noms d'abord, techniques masqués, 12 max). */
function columnsOf(flat, opt = {}) {
  const seen = new Map();
  for (const r of flat.slice(0, 100)) for (const [k, v] of Object.entries(r)) { const c = seen.get(k) || { k, n: 0 }; if (v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length)) c.n++; seen.set(k, c); }
  const all = [...seen.values()].filter((c) => c.n > 0).map((c) => c.k).slice(0, 60);
  const last = (k) => snake(k).split('.').pop();
  const rk = (k) => (NAMEY.test(last(k)) ? 0 : IDENT.test(last(k)) ? 1 : 2);
  const def = all.filter((k) => !TECH.test(snake(k)) && !(opt.hide && opt.hide.test(k)))
    .map((k, i) => ({ k, i })).sort((a, b) => rk(a.k) - rk(b.k) || a.i - b.i).map((c) => c.k).slice(0, opt.maxCols || 12);
  return { all, def };
}

function toCsv(cols, rows) {
  const esc = (x) => { const s = x === null || x === undefined ? '' : Array.isArray(x) ? x.join(' ') : String(x); return /[",;\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  return [cols.map((c) => esc(humanKey(c.split('.').pop()))).join(';'), ...rows.map((r) => cols.map((c) => esc(r.flat[c])).join(';'))].join('\n');
}
const lsGet = (k) => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* stockage indisponible */ } };

/**
 * Tableau triable, filtrable, paginé ; sélecteur de colonnes (mémorisé), détail repliable par ligne, export CSV.
 * @param {object[]} rows
 * @param {{pageSize?:number, name?:string, hide?:RegExp, maxCols?:number}} opt
 */
export function smartTable(rows, opt = {}) {
  const data = rows.map((r) => { const { _raw, ...rest } = r; return { raw: _raw || rest, flat: flattenRow(rest) }; });
  const { all, def } = columnsOf(data.map((d) => d.flat), opt);
  if (!all.length) return h('p', { class: 'muted pad' }, t('Structure non tabulaire.'));
  const store = `hub_cols_${opt.name || 'table'}`;
  const saved = (lsGet(store) || []).filter((c) => all.includes(c));
  let cols = saved.length ? all.filter((c) => saved.includes(c)) : def;
  const st = { q: '', sort: null, dir: 1, shown: opt.pageSize || 25, pick: false };
  const wrap = h('div', { class: 'stbl' });
  const open = new Set();
  const isNum = (c) => data.some((d) => typeof d.flat[c] === 'number') && !RE.time.test(snake(c)) && !data.some((d) => typeof d.flat[c] === 'string' && d.flat[c]);
  const cellOf = (d, c) => smartValue(c.split('.').pop(), d.flat[c]);
  const label = (c) => humanKey(c.split('.').pop());

  function view() {
    const numeric = new Set(cols.filter(isNum));
    let list = data;
    const q = st.q.trim().toLowerCase();
    if (q) list = list.filter((d) => JSON.stringify(d.raw).toLowerCase().includes(q));
    if (st.sort) {
      const c = st.sort;
      list = [...list].sort((a, b) => {
        const x = cellOf(a, c).sort; const y = cellOf(b, c).sort;
        if (x === null && y === null) return 0; if (x === null) return 1; if (y === null) return -1;
        return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), locale(), { numeric: true })) * st.dir;
      });
    }
    const toggle = (id) => { open.has(id) ? open.delete(id) : open.add(id); view(); };
    const body = [];
    list.slice(0, st.shown).forEach((d) => {
      const id = data.indexOf(d);
      body.push(h('tr', { class: 'click', tabindex: '0', 'aria-expanded': String(open.has(id)), onClick: () => toggle(id), onKeydown: (e) => { if (e.key === 'Enter') toggle(id); } },
        cols.map((c) => h('td', { class: numeric.has(c) ? 'r num' : '' }, cellOf(d, c).node))));
      if (open.has(id)) body.push(h('tr', { class: 'detail' }, h('td', { colspan: cols.length || 1 }, renderSmart(d.raw, { depth: 3, noTableToggle: true }))));
    });
    const picker = all.length > 3 ? h('details', { class: 'colpick', open: st.pick, onToggle: (e) => { st.pick = e.target.open; } },
      h('summary', { class: 'btn sm' }, t('Colonnes ({n}/{m})', { n: cols.length, m: all.length })),
      h('div', { class: 'colbox' }, all.map((c) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: cols.includes(c), onChange: (e) => { cols = all.filter((x) => (x === c ? e.target.checked : cols.includes(x))); lsSet(store, cols); view(); } }), label(c))),
        h('button', { class: 'btn sm', type: 'button', onClick: () => { cols = def; lsSet(store, []); view(); } }, t('Par défaut')))) : null;
    mount(wrap,
      h('div', { class: 'toolbar tight' },
        data.length > 8 ? h('input', { class: 'field', type: 'search', placeholder: 'Filtrer…', 'aria-label': 'Filtrer', value: st.q, onInput: (e) => { st.q = e.target.value; st.shown = opt.pageSize || 25; view(); const i = wrap.querySelector('input[type=search]'); if (i) { i.focus(); i.setSelectionRange(st.q.length, st.q.length); } } }) : null,
        h('span', { class: 'muted grow' }, list.length === data.length ? t('{n} ligne(s)', { n: fmt(data.length) }) : t('{n} ligne(s) sur {m}', { n: fmt(list.length), m: fmt(data.length) })),
        picker,
        h('button', { class: 'btn sm', type: 'button', onClick: () => {
          const blob = new Blob([`\uFEFF${toCsv(cols, list)}`], { type: 'text/csv;charset=utf-8' });
          const a = h('a', { href: URL.createObjectURL(blob), download: `${opt.name || 'export'}.csv` }); document.body.append(a); a.click(); a.remove(); toast(t('Export CSV prêt'));
        } }, 'CSV')),
      list.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
        h('thead', null, h('tr', null, cols.map((c) => h('th', { scope: 'col', title: c, class: `${numeric.has(c) ? 'r' : ''} sortable`, 'aria-sort': st.sort === c ? (st.dir > 0 ? 'ascending' : 'descending') : 'none' },
          h('button', { type: 'button', class: 'thbtn', title: 'Trier', onClick: () => { if (st.sort === c) st.dir = -st.dir; else { st.sort = c; st.dir = numeric.has(c) ? -1 : 1; } view(); } }, label(c), st.sort === c ? (st.dir > 0 ? ' ▲' : ' ▼') : ''))))),
        h('tbody', null, body))) : h('div', { class: 'empty' }, t('Aucun résultat.')),
      list.length > st.shown ? h('div', { class: 'actions pad' }, h('button', { class: 'btn sm', type: 'button', onClick: () => { st.shown += 50; view(); } }, t('Afficher plus ({n} restantes)', { n: fmt(list.length - st.shown) }))) : null);
  }
  view();
  return wrap;
}

// ── Séries temporelles ──
const PREFER = ['requests', 'total', 'count', 'hits', 'redirected', 'pages', 'started', 'solved', 'failed', 'blocked', 'errors'];
const rank = (k) => { const i = PREFER.indexOf(k); return i < 0 ? 99 : i; };
const NOT_METRIC = /(^|_)(id|index|port|code|status|line|pid)$/;
const regular = (ts) => {
  if (ts.length < 3) return false;
  const d = new Map();
  for (let i = 1; i < ts.length; i++) { const x = Math.round((ts[i] - ts[i - 1]) / 1000); d.set(x, (d.get(x) || 0) + 1); }
  return Math.max(...d.values()) / (ts.length - 1) >= 0.6;
};
const TIMEKEY = /^(t|ts|time|timestamp|timestamps|hour|hours|date|datetime|bucket|day|minute|at|labels|x)$/;

/** Normalise les formes courantes d'une série : tableau de points, { series|points|data|rows: [...] }, tableaux parallèles, map horodatage → valeurs. */
export function seriesRowsFrom(v) {
  if (Array.isArray(v)) return v.length >= 3 && v.every(isObj) ? v : null;
  if (!isObj(v)) return null;
  for (const k of ['series', 'points', 'data', 'rows', 'items', 'buckets', 'hours']) if (Array.isArray(v[k]) && v[k].length >= 3 && v[k].every(isObj)) return v[k];
  const arrs = Object.entries(v).filter(([, x]) => Array.isArray(x) && x.length >= 3 && x.every(isScalar));
  const tk = arrs.find(([k, x]) => TIMEKEY.test(snake(k)) && toMs(x[0]) !== null);
  if (tk && arrs.length >= 2) return tk[1].map((tv, i) => ({ [tk[0]]: tv, ...Object.fromEntries(arrs.filter(([k]) => k !== tk[0]).map(([k, x]) => [k, x[i]])) }));
  const ent = Object.entries(v);
  if (ent.length >= 3 && ent.every(([k, x]) => toMs(/^\d+$/.test(k) ? Number(k) : k) !== null && isObj(x))) return ent.map(([k, x]) => ({ ts: /^\d+$/.test(k) ? Number(k) : k, ...x }));
  return null;
}

/** Un graphique par famille d'unités (compteurs / octets / durées) : jamais deux échelles sur le même axe. Séries irrégulières (événements) : pas de graphique. */
export function seriesChart(rows, title) {
  if (!Array.isArray(rows) || rows.length < 3 || !isObj(rows[0])) return null;
  const tk = Object.keys(rows[0]).find((k) => TIMEKEY.test(snake(k)) && toMs(rows[0][k]) !== null);
  if (!tk) return null;
  if (!regular(rows.map((r) => toMs(r[tk])).filter((x) => x !== null).sort((a, b) => a - b))) return null;
  const nums = Object.keys(rows[0]).filter((k) => k !== tk && typeof rows[0][k] === 'number' && !RE.time.test(snake(k)) && !NOT_METRIC.test(snake(k)));
  const groups = { count: [], bytes: [], ms: [] };
  for (const k of nums) groups[RE.bytes.test(snake(k)) ? 'bytes' : RE.ms.test(snake(k)) ? 'ms' : 'count'].push(k);
  const cls = ['l1', 'l2', 'l3'];
  const boxes = [];
  for (const [g, keys] of Object.entries(groups)) {
    if (!keys.length) continue;
    const use = keys.sort((a, b) => rank(a) - rank(b)).slice(0, 3);
    const pts = rows.map((r) => ({ t: toMs(r[tk]), ...Object.fromEntries(use.map((k) => [k, typeof r[k] === 'number' ? r[k] : null])) })).filter((p) => p.t !== null).sort((a, b) => a.t - b.t);
    if (pts.length < 3) continue;
    const fmtY = g === 'bytes' ? (v) => bytes(v) : g === 'ms' ? fmtMs : undefined;
    boxes.push(chartBox(title && boxes.length === 0 ? title : use.map(humanKey).join(' · '), lineChart(pts, use.map((k, i) => ({ key: k, cls: cls[i], area: i === 0 })), fmtY ? { format: fmtY } : {}), use.map((k, i) => [['c1', 'c2', 'c3'][i], humanKey(k)])));
  }
  if (!boxes.length) return null;
  return boxes.length === 1 ? boxes[0] : h('div', { class: 'stack' }, boxes);
}

// ── Barres (map clé → nombre) ──
export function barList(obj, key) {
  const ent = Object.entries(obj).filter(([, v]) => typeof v === 'number').sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...ent.map(([, v]) => v));
  const shown = ent.slice(0, 15);
  return h('div', { class: 'bars' }, shown.map(([k, v]) => {
    const i = h('i'); i.style.width = `${Math.max(1, Math.round((v / max) * 100))}%`;
    return h('div', { class: 'bar-row' }, h('span', { class: 'bl' }, RE.country.test(snake(key)) ? smartValue('country', k).node : /^[A-Za-z_][A-Za-z0-9_]*$/.test(k) ? humanKey(k) : k), h('span', { class: 'bt' }, i), h('b', { class: 'num' }, smartValue(key, v).node));
  }), ent.length > shown.length ? h('p', { class: 'muted' }, t('+ {n} autres', { n: ent.length - shown.length })) : null);
}

// ── Grille clé / valeur ──
export function kvGrid(obj) {
  const ent = Object.entries(obj).filter(([, v]) => isScalar(v) || (Array.isArray(v) && v.every(isScalar)));
  if (!ent.length) return null;
  return h('dl', { class: 'kvgrid' }, ent.map(([k, v]) => h('div', { class: 'kvi' }, h('dt', null, humanKey(k)), h('dd', null, smartValue(k, v).node))));
}

// ── Séries par clé : { "<vhost>": [points] } ──
function seriesByKey(obj, key) {
  const keys = Object.keys(obj);
  const box = h('div'); let cur = keys[0];
  const sel = h('select', { class: 'select', 'aria-label': 'Choisir', onChange: (e) => { cur = e.target.value; draw(); } }, keys.map((k) => h('option', { value: k }, k)));
  function draw() { mount(box, seriesChart(obj[cur], cur) || h('p', { class: 'muted pad' }, t('Données insuffisantes'))); }
  draw();
  return h('div', { class: 'stack' }, h('div', { class: 'toolbar tight' }, sel, h('span', { class: 'muted' }, t('{n} série(s)', { n: keys.length }))), box);
}

/** Rendu récursif : choisit la meilleure représentation d'une valeur. */
export function renderSmart(v, ctx = {}) {
  const depth = ctx.depth || 0; const key = ctx.key || '';
  if (isScalar(v)) return h('span', null, smartValue(key, v).node);
  if (depth > MAX_DEPTH) return h('p', { class: 'muted' }, t('Détail tronqué.'));
  if (Array.isArray(v)) {
    if (!v.length) return h('p', { class: 'muted' }, t('Aucune donnée.'));
    if (v.every(isScalar)) return h('div', { class: 'chips' }, v.slice(0, 80).map((x) => h('span', { class: 'chip' }, String(smartValue(key, x).text || x))), v.length > 80 ? h('span', { class: 'muted' }, `+${v.length - 80}`) : null);
    const objs = v.filter(isObj);
    if (objs.length) {
      const chart = ctx.noTableToggle ? null : seriesChart(objs);
      return h('div', { class: 'stack' }, chart, chart ? h('details', { class: 'sub' }, h('summary', null, t('Tableau des données')), smartTable(objs, { name: key })) : smartTable(objs, { name: key }));
    }
    return h('div', { class: 'stack' }, v.map((x) => renderSmart(x, { depth: depth + 1, key })));
  }
  const ent = Object.entries(v);
  if (!ent.length) return h('p', { class: 'muted' }, t('Aucune donnée.'));
  // série (tableaux parallèles, { series: [...] }, map horodatage → valeurs)
  const sr = ctx.noTableToggle ? null : seriesRowsFrom(v);
  if (sr && seriesChart(sr)) {
    const kv0 = kvGrid(Object.fromEntries(ent.filter(([, x]) => isScalar(x))));
    const extra = ent.filter(([, x]) => isObj(x) && Object.keys(x).length).map(([k, x]) => h('details', { class: 'sub', open: true }, h('summary', null, humanKey(k)), renderSmart(x, { depth: depth + 1, key: k })));
    return h('div', { class: 'stack' }, kv0, extra, seriesChart(sr), h('details', { class: 'sub' }, h('summary', null, t('Tableau des données')), smartTable(sr, { name: key })));
  }
  // map clé → nombre : barres
  if (ent.length >= 4 && ent.every(([, x]) => typeof x === 'number')) return barList(v, key);
  // map clé → séries temporelles
  if (ent.length >= 1 && ent.every(([, x]) => Array.isArray(x) && x.length > 1 && x.every(isObj)) && seriesChart(ent[0][1])) return seriesByKey(v, key);
  // map clé → enregistrement : tableau avec la clé en première colonne
  if (ent.length >= 2 && ent.every(([, x]) => isObj(x) && Object.values(x).some(isScalar)) && !ent.every(([, x]) => Object.values(x).every((y) => !isScalar(y)))) {
    return smartTable(ent.map(([k, x]) => ({ _key: k, ...x })), { name: key });
  }
  const kv = kvGrid(v);
  const rest = ent.filter(([, x]) => !(isScalar(x) || (Array.isArray(x) && x.every(isScalar))));
  return h('div', { class: 'stack' }, kv, rest.map(([k, x], i) => h('details', { class: 'sub', open: depth < 2 && (rest.length <= 3 || i < 2) }, h('summary', null, humanKey(k), isCount(x)), renderSmart(x, { depth: depth + 1, key: k }))));
}
const isCount = (x) => (Array.isArray(x) ? h('span', { class: 'badge' }, String(x.length)) : null);

/** Recherche (BFS, profondeur ≤ 3) du premier nombre dont la clé figure dans `names`. */
export function findNum(obj, names, maxDepth = 3) {
  const q = [[obj, 0]];
  while (q.length) {
    const [o, d] = q.shift();
    if (!isObj(o)) continue;
    for (const n of names) if (typeof o[n] === 'number') return o[n];
    if (d < maxDepth) for (const x of Object.values(o)) if (isObj(x)) q.push([x, d + 1]);
  }
  return null;
}
