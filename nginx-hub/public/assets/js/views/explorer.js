// Explorateur du log store (#107) : recherche de logs bruts multi-instances + fiche IP. DONNÉES PERSONNELLES : admin seulement,
// rien n'est stocké par le Hub (relais), l'audit ne reçoit que des noms de filtres et des compteurs. Rendu DOM sûr (jamais de HTML).
import { h, mount } from '../dom.js';
import { get } from '../api.js';
import { fmt, bytes, dateTime, toast } from '../util.js';
import { t } from '../i18n.js';
import { card, tile, hbars, empty } from '../viz/widgets.js';

const PERIODS = [[1, '1 h'], [6, '6 h'], [24, '24 h'], [72, '3 j'], [168, '7 j'], [336, '14 j'], [744, '31 j']];
const SOURCES = ['access', 'waf', 'challenge', 'blocklist', 'crowdsec', 'analysis'];
const ACTIONS = ['allowed', 'logged', 'challenged', 'blocked'];
const FIELDS = ['instance', 'site', 'source', 'action', 'status', 'ip', 'path', 'ua', 'rule']; // filtres de la recherche (hors période)
const TOP_DIMS = [['rule', 'Règles'], ['path', 'Chemins'], ['ua', 'User-agents'], ['ip', 'IP'], ['country', 'Pays'], ['site', 'Sites'], ['bot_class', 'Bots']];
const TOP_FILTER = { rule: 'rule', path: 'path', ua: 'ua', ip: 'ip', site: 'site' }; // dimensions qui se pivotent en filtre de recherche
const ACTION_TONE = { allowed: 'ok', logged: 'warn', challenged: 'warn', blocked: 'err' };
const PLAIN_IP = /^[0-9a-fA-F:.]{2,45}$/;
const MAX_ROWS = 2000; // plafond d'affichage cumulé (pagination « plus de résultats »)

/** Teinte d'un code de statut : 2xx vert, 3xx bleu, 4xx ambre, 5xx rouge (mêmes teintes que l'histogramme des Journaux). */
export function statusTone(s) { return s >= 500 ? 'err' : s >= 400 ? 'warn' : s >= 300 ? 'info' : s >= 200 ? 'ok' : ''; }

/** Cellule CSV : neutralise l'injection de formule (=, +, -, @) et protège guillemets et sauts de ligne. */
export function csvCell(v) {
  let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
export function toCsv(rows) {
  const cols = ['ts', 'instance', 'site', 'source', 'action', 'ip', 'method', 'path', 'status', 'bytes', 'rt_ms', 'country', 'bot_class', 'rule', 'ua', 'extra'];
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(c === 'ts' ? new Date(r.ts).toISOString() : r[c])).join(','))].join('\n');
}

/** Filtres initiaux depuis le fragment : #/explorer?ip=…&site=… (liens partageables : filtres seulement, jamais de données). */
function fromHash() {
  const q = new URLSearchParams((window.location.hash.split('?')[1]) || '');
  const f = { hours: 24 };
  const hrs = Number.parseInt(q.get('hours'), 10); if (hrs >= 1 && hrs <= 744) f.hours = hrs;
  for (const k of FIELDS) if (q.get(k)) f[k] = q.get(k).slice(0, 200);
  return f;
}
function toHash(f) {
  const q = new URLSearchParams(); q.set('hours', String(f.hours));
  for (const k of FIELDS) if (f[k]) q.set(k, f[k]);
  return `#/explorer?${q}`;
}
function apiQuery(f, cursor) {
  const q = new URLSearchParams(); q.set('hours', String(f.hours));
  for (const k of FIELDS) if (f[k]) q.set(k, f[k]);
  if (cursor) q.set('cursor', cursor);
  return q.toString();
}

export function explorerView(root) {
  const st = { camp: { items: [], loading: false, error: null, show: false }, top: { dim: 'rule', items: [], loading: false, error: null, open: false }, f: fromHash(), rows: [], cursor: null, loading: false, instances: [], ipCard: null, open: new Set() };
  const bar = h('div'); const panel = h('div'); const campPanel = h('div'); const topPanel = h('div'); const table = h('div'); const note = h('div', { class: 'muted count-line' });
  let disposed = false;

  const input = (name, label, ph, w = 150) => h('label', { class: 'check' }, label, ' ', h('input', { class: 'select', name, value: st.f[name] || '', placeholder: ph || '', style: `width:${w}px`, maxlength: '200', 'aria-label': label,
    onChange: (e) => { st.f[name] = e.target.value.trim(); }, onKeydown: (e) => { if (e.key === 'Enter') { st.f[name] = e.target.value.trim(); search(); } } }));
  const sel = (name, label, opts) => h('label', { class: 'check' }, label, ' ', h('select', { class: 'select', 'aria-label': label, onChange: (e) => { st.f[name] = e.target.value; } },
    h('option', { value: '' }, t('Tous')), opts.map(([v, l]) => h('option', { value: v, selected: st.f[name] === v }, l))));

  function drawBar() {
    mount(bar, h('div', { class: 'stack' },
      h('div', { class: 'toolbar' },
        h('label', { class: 'check' }, t('Période'), ' ', h('select', { class: 'select', 'aria-label': t('Période'), onChange: (e) => { st.f.hours = Number(e.target.value); } }, PERIODS.map(([hrs, l]) => h('option', { value: hrs, selected: hrs === st.f.hours }, l)))),
        sel('instance', t('Instance'), st.instances.map((i) => [i.id, i.name || i.id])),
        input('site', t('Site'), 'exemple.fr'), sel('source', t('Source'), SOURCES.map((s) => [s, s])), sel('action', t('Action'), ACTIONS.map((a) => [a, a]))),
      h('div', { class: 'toolbar' },
        input('status', t('Statut'), '404 / 4xx', 90), input('ip', t('IP'), '203.0.113.9', 170), input('path', t('Chemin contient'), '/wp-login', 170), input('ua', t('User-agent contient'), 'curl', 150), input('rule', t('Règle'), 'wp-login', 130),
        h('button', { class: 'btn primary sm', type: 'button', onClick: () => search() }, t('Rechercher')),
        h('button', { class: 'btn sm', type: 'button', onClick: reset }, t('Réinitialiser')),
        h('button', { class: 'btn sm', type: 'button', disabled: !st.rows.length, onClick: exportCsv }, t('Exporter (CSV)')),
        h('button', { class: 'btn sm', type: 'button', onClick: shareLink }, t('Copier le lien')))));
  }

  /** Vue attaques : classement d'une dimension sur la période et les filtres courants ; un clic sur une valeur la pose en filtre. */
  async function loadTop() {
    const tp = st.top; tp.loading = true; tp.error = null; drawTop();
    const q = new URLSearchParams({ dimension: tp.dim, hours: String(st.f.hours), limit: '15' });
    for (const k of ['instance', 'site', 'source', 'action', 'rule', 'status']) if (st.f[k]) q.set(k, st.f[k]);
    try {
      const d = await get(`/logstore/explorer/top?${q}`);
      if (disposed) return;
      tp.items = d.items;
    } catch (e) { tp.items = []; tp.error = e.code === 'unauthenticated' ? null : e.message; }
    tp.loading = false; drawTop();
  }
  function drawTop() {
    const tp = st.top;
    const tabs = h('div', { class: 'toolbar' }, TOP_DIMS.map(([d, l]) => h('button', { class: `btn sm${tp.dim === d ? ' primary' : ''}`, type: 'button', 'aria-pressed': String(tp.dim === d), onClick: () => { tp.dim = d; loadTop(); } }, t(l))),
      h('button', { class: 'btn sm', type: 'button', onClick: () => loadTop() }, t('Actualiser')));
    const filterName = TOP_FILTER[tp.dim];
    const body = tp.loading ? h('div', { class: 'muted' }, t('Chargement…')) : tp.error ? h('div', { class: 'muted' }, tp.error)
      : !tp.items.length ? empty(t('Aucune donnée pour ces filtres.'))
        : h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', { scope: 'col' }, t('Valeur')), h('th', { scope: 'col', class: 'num' }, t('Événements')))),
          h('tbody', null, tp.items.map((x) => h('tr', null, h('td', { class: 'mono' }, filterName ? pivot(filterName, x.key) : x.key), h('td', { class: 'num' }, fmt(x.count)))))));
    mount(topPanel, card(t('Top attaques et sources'), h('div', { class: 'stack' }, tabs, body), { note: t('Même période et mêmes filtres que la recherche ; cliquer une valeur la pose en filtre.') }));
  }

  /** Campagnes : même signature (règle + chemin) depuis plusieurs IP, 7 jours max ; un clic pose règle et chemin en filtres. */
  async function loadCamp() {
    const c = st.camp; c.loading = true; c.error = null; drawCamp();
    const q = new URLSearchParams({ hours: String(Math.min(st.f.hours, 168)) });
    for (const k of ['instance', 'site', 'source', 'action']) if (st.f[k]) q.set(k, st.f[k]);
    try { const d = await get(`/logstore/explorer/campaigns?${q}`); if (disposed) return; c.items = d.items; } catch (e) { c.items = []; c.error = e.code === 'unauthenticated' ? null : e.message; }
    c.loading = false; drawCamp();
  }
  function drawCamp() {
    const c = st.camp;
    const toggle = h('button', { class: 'btn sm', type: 'button', 'aria-expanded': String(c.show), onClick: () => { c.show = !c.show; c.show ? loadCamp() : drawCamp(); } }, c.show ? t('Masquer') : t('Afficher les campagnes'));
    const body = !c.show ? null : c.loading ? h('div', { class: 'muted' }, t('Chargement…')) : c.error ? h('div', { class: 'muted' }, c.error)
      : !c.items.length ? empty(t('Aucune campagne détectée (signature vue depuis au moins 3 IP).'))
        : h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, [t('Règle'), t('Chemin'), t('IP'), t('Événements'), t('Bloqués'), t('Sites'), t('Instances'), t('Dernier passage')].map((x) => h('th', { scope: 'col' }, x)))),
          h('tbody', null, c.items.map((x) => h('tr', null, h('td', null, pivot('rule', x.rule)), h('td', { class: 'mono' }, x.path ? pivot('path', x.path, x.path.slice(0, 60)) : '—'),
            h('td', { class: 'num' }, fmt(x.ips)), h('td', { class: 'num' }, fmt(x.events)), h('td', { class: 'num' }, fmt(x.blocked)), h('td', { class: 'num' }, fmt(x.sites)), h('td', { class: 'num' }, fmt(x.instances)), h('td', { class: 'mono num' }, x.last_seen ? dateTime(x.last_seen) : '—'))))));
    mount(campPanel, card(t('Campagnes (attaques distribuées)'), h('div', { class: 'stack' }, toggle, body), { note: t('Une signature (règle + chemin) vue depuis plusieurs IP : sondage distribué. 7 jours maximum.') }));
  }

  /** Pivot : un clic sur une valeur ajoute le filtre et relance la recherche. */
  function pivot(name, value, label) {
    if (value === null || value === undefined || value === '') return h('span', { class: 'muted' }, '—');
    return h('button', { class: 'linkbtn', type: 'button', title: t('Filtrer sur cette valeur'), onClick: () => { st.f[name] = String(value); drawBar(); search(); } }, label === undefined ? String(value) : label);
  }

  function drawTable() {
    if (!st.rows.length) { mount(table, st.loading ? h('div', { class: 'muted' }, t('Chargement…')) : card(t('Événements'), empty(t('Aucun événement pour ces filtres.')))); return; }
    const head = [t('Date'), t('Instance'), t('Site'), t('Source'), t('IP'), t('Requête'), t('Statut'), t('Règle'), t('Pays')];
    const rowEls = st.rows.flatMap((e, i) => {
      const main = h('tr', { class: 'click', tabindex: '0', 'aria-expanded': String(st.open.has(i)),
        onClick: (ev) => { if (ev.target.closest('button')) return; st.open.has(i) ? st.open.delete(i) : st.open.add(i); drawTable(); },
        onKeydown: (ev) => { if (ev.key === 'Enter' && !ev.target.closest('button')) { st.open.has(i) ? st.open.delete(i) : st.open.add(i); drawTable(); } } },
        h('td', { class: 'mono num' }, dateTime(e.ts)), h('td', null, pivot('instance', e.instance)), h('td', null, pivot('site', e.site)),
        h('td', null, pivot('source', e.source), ' ', e.action ? h('span', { class: `badge ${ACTION_TONE[e.action] || ''}` }, e.action) : null),
        h('td', { class: 'mono' }, e.ip ? pivot('ip', e.ip) : (e.ip_key ? pivot('ip', e.ip_key, `${e.ip_key.slice(0, 8)}…`) : h('span', { class: 'muted' }, '—'))),
        h('td', { class: 'mono', title: `${e.method || ''} ${e.path || ''}` }, `${e.method || ''} ${(e.path || '').slice(0, 60)}`),
        h('td', null, e.status ? h('span', { class: `badge ${statusTone(e.status)}` }, String(e.status)) : '—'),
        h('td', null, e.rule || '—'), h('td', null, e.country || '—'));
      if (!st.open.has(i)) return [main];
      const kv = [['User-Agent', e.ua], ['Referer', e.referer_host], ['Bot', e.bot_class], [t('Octets'), e.bytes === null ? null : bytes(e.bytes)], ['rt (ms)', e.rt_ms], [t('Chemin'), e.path], ...Object.entries(e.extra || {}).map(([k, v]) => [`extra.${k}`, Array.isArray(v) ? v.join(', ') : v])]
        .filter(([, v]) => v !== null && v !== undefined && v !== '');
      return [main, h('tr', { class: 'detail' }, h('td', { colspan: String(head.length) }, h('dl', { class: 'kv' }, kv.map(([k, v]) => [h('dt', null, k), h('dd', { class: 'mono' }, String(v))]))))];
    });
    mount(table, card(t('Événements'), h('div', { class: 'tbl-wrap' }, h('table', null,
      h('thead', null, h('tr', null, head.map((x) => h('th', { scope: 'col' }, x)))), h('tbody', null, rowEls))),
    { note: t('{n} ligne(s) affichée(s)', { n: st.rows.length }) }),
    st.cursor && st.rows.length < MAX_ROWS ? h('div', { style: 'margin-top:8px' }, h('button', { class: 'btn sm', type: 'button', disabled: st.loading, onClick: () => search(true) }, t('Plus de résultats'))) : null);
  }

  /** Fiche IP : seulement pour une IP unique (un /24 ou une clé de pseudonyme n'a pas de chemin dédié côté log store). */
  async function loadIpCard() {
    const ip = st.f.ip;
    if (!ip || !PLAIN_IP.test(ip) || ip.includes('/')) { st.ipCard = null; mount(panel); return; }
    try {
      const d = await get(`/logstore/explorer/ip?ip=${encodeURIComponent(ip)}&hours=${st.f.hours}&limit=500`);
      if (disposed) return;
      st.ipCard = d; drawIpCard();
    } catch (e) { mount(panel); if (e.code !== 'unauthenticated') toast(e.message); }
  }
  function drawIpCard() {
    const d = st.ipCard; if (!d) { mount(panel); return; }
    const s = d.summary;
    const bars = (items, pivotName, cls) => hbars(items.map((x) => ({ label: x.key, value: x.count, cls })), { limit: 8 });
    mount(panel, card(t('Fiche IP : {ip}', { ip: st.f.ip }), h('div', { class: 'stack' },
      h('div', { class: 'kpis' }, tile(t('Événements'), fmt(s.total), t('{h} h', { h: st.f.hours })), tile(t('Premier passage'), s.first_seen ? dateTime(s.first_seen) : '—', ''), tile(t('Dernier passage'), s.last_seen ? dateTime(s.last_seen) : '—', ''),
        tile(t('Sites'), fmt(d.by_site.length), ''), tile(t('Instances'), fmt(d.by_instance.length), '')),
      h('div', { class: 'vz-grid vz-root' },
        card(t('Par source et action'), hbars(s.by_source_action.map((x) => ({ label: `${x.source || '?'} · ${x.action || '?'}`, value: x.count, cls: ACTION_TONE[x.action] === 'err' ? 'err' : ACTION_TONE[x.action] === 'warn' ? 'warn' : 'c1' })), { limit: 8 })),
        card(t('Par site'), bars(d.by_site, 'site', 'c2')), card(t('Par instance'), bars(d.by_instance, 'instance', 'c4')), d.by_rule.length ? card(t('Règles déclenchées'), bars(d.by_rule, 'rule', 'warn')) : null),
      h('div', { class: 'muted' }, t('La chronologie complète de cette IP (toutes sources, sites et instances) est dans le tableau ci-dessous.'))),
    { note: d.ip_mode && d.ip_mode !== 'clear' ? t('Mode IP du log store : {m}', { m: d.ip_mode }) : undefined }));
  }

  async function search(more = false) {
    if (st.loading) return;
    st.loading = true;
    if (!more) { st.rows = []; st.cursor = null; st.open = new Set(); note.textContent = ''; }
    drawTable();
    try {
      const d = await get(`/logstore/explorer/events?${apiQuery(st.f, more ? st.cursor : null)}`);
      if (disposed) return;
      st.rows = more ? st.rows.concat(d.events) : d.events; st.cursor = d.next_cursor;
      history.replaceState(null, '', toHash(st.f)); // lien partageable : filtres seulement
      if (!more) { await loadIpCard(); loadTop(); if (st.camp.show) loadCamp(); }
    } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
    st.loading = false; drawBar(); drawTable();
  }
  function reset() { st.f = { hours: 24 }; st.ipCard = null; mount(panel); drawBar(); search(); }
  function exportCsv() {
    const blob = new Blob([toCsv(st.rows)], { type: 'text/csv;charset=utf-8' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `logs-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  async function shareLink() {
    const u = `${window.location.origin}${window.location.pathname}${toHash(st.f)}`;
    try { await navigator.clipboard.writeText(u); toast(t('Lien copié (filtres seulement, aucune donnée).')); } catch { toast(u); }
  }

  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, t('Explorateur')), h('p', null, t('Recherche dans les logs bruts de toutes les instances (log store). Données personnelles : administrateurs seulement, rien n’est stocké par le Hub.')))),
    h('div', { class: 'stack' }, bar, topPanel, campPanel, panel, note, table));
  drawBar(); drawTable(); drawCamp();
  get('/logstore/overview?hours=1').then((d) => { if (!disposed && d && d.instances) { st.instances = d.instances; drawBar(); } }).catch(() => {});
  search();
  return () => { disposed = true; };
}
