// Onglets de modules d'une instance (inventaire, trafic, sécurité, opérations, supervision, rapports, indicateurs).
// Les objets de `data` ont la forme des API internes du dashboard : le rendu est piloté par smart.js (dates, octets, durées…
// détectés d'après le nom des champs) ; ce fichier ne définit que l'ordre, les libellés, les KPI et le cas particulier de la supervision.
import { h, mount, icon } from '../dom.js';
import { get, post } from '../api.js';
import { fmt, ago, toast, errorText, bytes, copy } from '../util.js';
import { t, tr } from '../i18n.js';
import { dashboardFor } from '../viz/index.js';
import { card as vzCard, hbars, donut } from '../viz/widgets.js';
import { renderSmart, smartTable, humanKey, findNum, toMs, registerLabels, seriesRowsFrom } from '../smart.js';

export const MODULES = [
  ['inventory', 'Inventaire'], ['traffic', 'Trafic'], ['security', 'Sécurité'], ['ops', 'Opérations'], ['monitoring', 'Supervision'], ['reports', 'Rapports'],
];

const PART_LABELS = {
  vhosts: 'Virtual hosts', certificates: 'Certificats', nginx: 'nginx', agents: 'Agents', containers_managed: 'Conteneurs gérés',
  series_hourly: 'Série horaire globale', series_hourly_by_vhost: 'Séries horaires par vhost', countries: 'Pays par volume', clients: 'Clients', clients_by_vhost: 'Clients par vhost', clients_by_country: 'Clients par pays',
  blocklists_status: 'Listes de blocage', blocklists_hits: 'Hits des listes', challenge_status: 'Challenge — état', challenge_stats: 'Challenge — statistiques', challenge_blocks: 'Challenge — blocages',
  waf_status: 'WAF — état', waf_top_rules: 'WAF — règles', waf_series: 'WAF — série', waf_top_ips: 'WAF — IP', crowdsec_status: 'CrowdSec — état', crowdsec_decisions: 'CrowdSec — décisions', alerts: 'Alertes par type',
  events: 'Événements', scheduler_tasks: 'Tâches planifiées', scheduler_runs: 'Exécutions', digests: 'Digests',
  rules: 'Règles d’analyse', exceptions: 'Exceptions', baseline: 'Baseline (vhosts)', baseline_country: 'Baseline (pays)', baseline_data: 'Baseline (volume)',
  targets: 'Cibles supervisées', incidents: 'Incidents',
};
// Ordre d'affichage : parties documentées d'abord (dans cet ordre), puis les parties inconnues.
const ORDER = {
  inventory: ['vhosts', 'certificates', 'nginx', 'agents', 'containers_managed'],
  traffic: ['series_hourly', 'countries', 'vhosts', 'clients', 'series_hourly_by_vhost', 'clients_by_vhost', 'clients_by_country'],
  security: ['alerts', 'waf_status', 'waf_top_rules', 'waf_series', 'waf_top_ips', 'crowdsec_status', 'crowdsec_decisions', 'blocklists_status', 'blocklists_hits', 'challenge_status', 'challenge_stats', 'challenge_blocks'],
  ops: ['events', 'scheduler_tasks', 'scheduler_runs', 'digests'],
  reports: ['rules', 'exceptions', 'baseline', 'baseline_country', 'baseline_data'],
};
registerLabels(PART_LABELS);
const partLabel = (k) => (PART_LABELS[k] ? t(PART_LABELS[k]) : humanKey(k));
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

/** Premier tableau trouvé : x lui-même, ou x[clé] pour l'une des clés. */
function arr(x, ...keys) {
  if (Array.isArray(x)) return x;
  if (isObj(x)) for (const k of keys) if (Array.isArray(x[k])) return x[k];
  return null;
}
const sum = (rows, names) => { let s = null; for (const n of names) { if (rows.some((r) => typeof r[n] === 'number')) { s = rows.reduce((a, r) => a + (typeof r[n] === 'number' ? r[n] : 0), 0); break; } } return s; };

function kpi(label, value, note, cls) {
  return h('div', { class: 'kpi' }, h('span', { class: 'l' }, label), h('span', { class: `v sm ${cls || ''}` }, value), h('span', { class: 'n' }, note || ''));
}

function kpisFor(name, data, derived) {
  const k = [];
  const d = data || {};
  if (name === 'inventory') {
    if (derived && derived.vhosts) k.push(kpi(t('Virtual hosts'), fmt(derived.vhosts.length), t('{n} avec backend', { n: derived.vhosts.filter((v) => v.upstream).length })));
    const s = d.certificates && d.certificates.summary;
    if (s) k.push(kpi(t('Certificats'), fmt(s.total), t('{e} expirés · {w} à renouveler', { e: s.expired ?? 0, w: s.warning ?? 0 }), s.expired ? 'err-txt' : ''));
    if (isObj(d.nginx)) k.push(kpi('nginx', d.nginx.running === false ? t('Arrêté') : d.nginx.running ? t('En marche') : '—', [d.nginx.version, d.nginx.connections != null ? t('{n} connexions', { n: fmt(d.nginx.connections) }) : ''].filter(Boolean).join(' · ')));
    const ag = arr(d.agents, 'agents');
    if (ag) k.push(kpi(t('Agents'), `${ag.filter((a) => a.online === true || a.status === 'online').length} / ${ag.length}`, t('en ligne')));
  } else if (name === 'traffic') {
    const rows = seriesRowsFrom(d.series_hourly) || arr(d.series_hourly, 'points', 'series', 'data');
    // série horaire vide (agrégat pas encore prêt) : repli sur les totaux par vhost, puis clients.total
    const vh = arr(d.vhosts, 'vhosts', 'items');
    const src = rows && rows.length ? rows : vh;
    if (src && src.length) {
      const rows2 = src; const rows_ = rows2;
      let req = sum(rows_, ['requests', 'total', 'count', 'hits']); const err = sum(rows_, ['errors', 'error', 'errs']); const by = sum(rows_, ['bytes', 'bytes_sent', 'size']);
      if (req === null) req = findNum(d.clients, ['total']);
      if (req !== null) k.push(kpi(t('Requêtes'), fmt(req), rows && rows.length ? t('sur la fenêtre') : t('somme des vhosts')));
      if (err !== null) k.push(kpi(t('Erreurs'), fmt(err), req ? `${((err / req) * 100).toFixed(1)} %` : '', req && err / req > 0.05 ? 'err-txt' : ''));
      if (by !== null) k.push(kpi(t('Volume'), bytes(by), rows && rows.length ? t('sur la fenêtre') : t('somme des vhosts')));
    }
    const c = isObj(d.countries) ? Object.keys(d.countries).length : arr(d.countries, 'countries', 'items') ? arr(d.countries, 'countries', 'items').length : null;
    if (c) k.push(kpi(t('Pays'), fmt(c), t('distincts')));
  } else if (name === 'security') {
    const total = findNum(d.alerts, ['total']); const un = findNum(d.alerts, ['unacked']);
    if (total !== null) k.push(kpi(t('Alertes'), fmt(total), t('{n} non acquittées', { n: un ?? 0 }), un ? 'err-txt' : ''));
    const dec = arr(d.crowdsec_decisions, 'decisions', 'items');
    if (dec) k.push(kpi(t('Décisions CrowdSec'), fmt(dec.length), ''));
    const rules = arr(d.waf_top_rules, 'rules', 'items');
    if (rules) k.push(kpi(t('Règles WAF déclenchées'), fmt(rules.length), ''));
    const ips = findNum(d.blocklists_status, ['ips', 'total_ips', 'total', 'count']);
    if (ips !== null) k.push(kpi(t('Listes de blocage'), fmt(ips), t('IP')));
  } else if (name === 'ops') {
    const ev = findNum(d.events, ['total']) ?? (arr(d.events, 'events') || []).length;
    k.push(kpi(t('Événements'), fmt(ev), ''));
    const tasks = arr(d.scheduler_tasks, 'tasks', 'items');
    if (tasks) k.push(kpi(t('Tâches planifiées'), fmt(tasks.length), ''));
    const dg = arr(d.digests, 'digests', 'items');
    if (dg) k.push(kpi(t('Digests'), fmt(dg.length), ''));
  } else if (name === 'reports') {
    const rules = arr(d.rules, 'rules', 'items');
    if (rules) k.push(kpi(t('Règles d’analyse'), `${rules.filter((r) => r.enable !== false && r.enabled !== false).length} / ${rules.length}`, t('actives')));
    const ex = arr(d.exceptions, 'exceptions', 'items');
    if (ex) k.push(kpi(t('Exceptions'), fmt(ex.length), ''));
  }
  return k.length ? h('div', { class: 'kpis' }, k) : null;
}

// ── Supervision : cibles + incidents ──
const UPW = new Set(['ok', 'up', 'online', 'healthy', 'running', 'success']);
function isUp(row) {
  if (isObj(row.last) && typeof row.last.ok === 'boolean') return row.last.ok;
  for (const k of ['up', 'ok', 'healthy', 'online', 'status', 'state', 'health']) {
    const v = row[k];
    if (typeof v === 'boolean') return v;
    if (typeof v === 'string') return UPW.has(v.toLowerCase());
  }
  return null;
}
const gv = (o, ...keys) => { for (const k of keys) if (o && o[k] !== undefined && o[k] !== null) return o[k]; return undefined; };
/** Une cible de supervision → ligne lisible (cible, chemin, état, code, latence, dernier contrôle, disponibilité, historique). Ligne brute conservée pour le détail. */
function monRow(r0) {
  if (!isObj(r0)) return { target: String(r0) };
  const snk = (o) => (isObj(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase(), v])) : {});
  const sm = snk(r0.summary); const r = { ...snk(r0), summary: sm };
  const last = snk(isObj(r.last) ? r.last : sm.last);
  if (r.last === undefined && isObj(sm.last)) r.last = last;
  if (r.up === undefined && typeof sm.up === 'boolean') r.up = sm.up;
  const name = (Array.isArray(r.server_names) ? r.server_names[0] : r.server_names) ?? gv(r, 'name', 'target', 'host', 'vhost_name');
  const up = isUp(r);
  const out = {
    target: name, path: gv(r, 'path', 'url', 'location'), status: up === true ? 'up' : up === false ? 'down' : undefined,
    code: gv(last, 'status', 'code', 'http_status', 'status_code'), latency_ms: gv(last, 'ms', 'latency_ms', 'latency'), last_check: gv(last, 'ts', 'time', 'at', 'date', 'checked_at'),
    uptime_pct: gv(sm, 'uptime_pct', 'uptime', 'availability_pct', 'availability', 'pct'), checks: gv(sm, 'checks_in_window', 'checks', 'total'),
    down_since: gv(sm, 'down_since'), error: gv(last, 'error', 'err'), history: gv(r, 'sparkline', 'history'), interval_s: gv(r, 'interval_sec', 'interval_s', 'interval'),
    scheme: r.scheme, host: r.host, port: r.port, file: gv(r, 'file'),
  };
  for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k];
  out._raw = r0;
  return out;
}

function monitoringView(data) {
  if (data.enabled === false) return h('div', { class: 'panel' }, h('div', { class: 'empty' }, t('Supervision non activée sur ce dashboard (aucune cible) — ce n’est pas une erreur.')));
  const tg = data.targets;
  let targets = arr(tg, 'targets', 'items', 'list');
  if (!targets && isObj(tg)) targets = Object.entries(tg).filter(([, v]) => isObj(v)).map(([key, v]) => ({ target: key, ...v }));
  targets = (targets || []).map(monRow);
  const inc = [];
  if (isObj(data.incidents)) for (const [key, v] of Object.entries(data.incidents)) for (const i of arr(v, 'incidents', 'items') || []) inc.push(isObj(i) ? { target: key, ...i } : { target: key, incident: i });
  const timeKey = (r) => Object.keys(r).find((k) => /(^|_)(ts|time|since|started|at|date)$/.test(k) && toMs(r[k]) !== null);
  inc.sort((a, b) => (toMs(b[timeKey(b)]) || 0) - (toMs(a[timeKey(a)]) || 0));
  const up = targets.filter((r) => isUp(r) === true).length; const down = targets.filter((r) => isUp(r) === false).length;
  const known = new Set(['enabled', 'targets', 'incidents', 'reachable']);
  const others = Object.entries(data).filter(([k]) => !known.has(k));
  return h('div', { class: 'stack' },
    h('div', { class: 'kpis' }, kpi(t('Cibles supervisées'), fmt(targets.length), ''), kpi(t('En ligne'), fmt(up), '', ''), kpi(t('En échec'), fmt(down), '', down ? 'err-txt' : ''), kpi(t('Incidents'), fmt(inc.length), t('20 derniers par cible'))),
    targets.length ? h('div', { class: 'vz-grid vz-root' },
      vzCard(t('Disponibilité'), donut([{ label: t('En ligne'), value: up, cls: 'ok' }, { label: t('En échec'), value: down, cls: 'err' }, { label: t('Inconnu'), value: targets.length - up - down, cls: 'off' }], { center: `${up}/${targets.length}`, sub: t('cibles') })),
      targets.some((r) => typeof r.latency_ms === 'number') ? vzCard(t('Latence'), hbars(targets.filter((r) => typeof r.latency_ms === 'number').sort((a, b) => b.latency_ms - a.latency_ms).slice(0, 10).map((r) => ({ label: `${r.target ?? '?'}${r.path && r.path !== '/' ? ` ${r.path}` : ''}`, value: r.latency_ms, cls: isUp(r) === false ? 'err' : r.latency_ms > 1000 ? 'warn' : 'c1' })), { format: (v) => `${Math.round(v)} ms` })) : null,
      targets.some((r) => typeof r.uptime_pct === 'number') ? vzCard(t('Taux de disponibilité'), hbars(targets.filter((r) => typeof r.uptime_pct === 'number').sort((a, b) => a.uptime_pct - b.uptime_pct).slice(0, 10).map((r) => ({ label: `${r.target ?? '?'}${r.path && r.path !== '/' ? ` ${r.path}` : ''}`, value: r.uptime_pct, cls: r.uptime_pct < 99 ? 'warn' : 'ok' })), { format: (v) => `${(Math.round(v * 100) / 100)} %`, max: 100 })) : null) : null,
    h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, t('Cibles supervisées'))),
      targets.length ? smartTable(targets, { name: 'monitoring-cibles', maxCols: 14 }) : h('div', { class: 'empty' }, t('Aucune cible renvoyée par le dashboard. Ouvrez « Données brutes » pour voir ce qu’il envoie.'))),
    inc.length ? h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, t('Incidents'), ' ', h('span', { class: 'badge' }, String(inc.length)))), smartTable(inc, { name: 'monitoring-incidents' })) : null,
    others.map(([k, v]) => h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, partLabel(k))), h('div', { class: 'panel-b' }, renderSmart(v, { key: k })))));
}

// ── Vue d'un module ──
export function moduleView(root, { id, name, session }) {
  const body = h('div', { class: 'stack' });
  let rawOpen = false;
  async function load() {
    try {
      const m = await get(`/instances/${id}/modules/${name}`);
      const errs = Object.entries(m.parts_errors || {});
      const stale = m.status !== 'ok';
      const data = m.data;
      const parts = data && name !== 'monitoring' && name !== 'indicators' ? orderParts(name, data) : [];
      const nav = parts.length > 3 ? h('div', { class: 'chips partnav', role: 'navigation', 'aria-label': t('Parties') }, parts.map(([k]) => h('button', { class: 'chip btnchip', type: 'button', onClick: () => document.getElementById(`part-${name}-${k}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }, partLabel(k)))) : null;
      const dash = data ? dashboardFor(name, data) : null;
      const detailNodes = () => [nav,
        data && name === 'monitoring' ? monitoringView(data) : null,
        data && name === 'inventory' && m.derived && m.derived.vhosts && m.derived.vhosts.length ? h('section', { class: 'panel', id: `part-${name}-derived` }, h('div', { class: 'panel-h' }, h('h2', null, t('Virtual hosts'), ' ', h('span', { class: 'badge' }, String(m.derived.vhosts.length)))), smartTable(m.derived.vhosts, { name: 'vhosts', pageSize: 50 }), h('details', { class: 'sub pad' }, h('summary', null, t('Données d’origine (blocs server, fichiers)')), renderSmart(data.vhosts, { key: 'vhosts' }))) : null,
        parts.filter(([k]) => !(name === 'inventory' && k === 'vhosts' && m.derived && m.derived.vhosts && m.derived.vhosts.length)).map(([k, v]) => h('section', { class: 'panel', id: `part-${name}-${k}` },
          h('div', { class: 'panel-h' }, h('h2', null, partLabel(k), count(v))),
          h('div', { class: 'panel-b' }, name === 'inventory' && k === 'vhosts' && m.derived && m.derived.vhosts && m.derived.vhosts.length ? h('details', { class: 'sub' }, h('summary', null, t('Données d’origine (blocs server, fichiers)')), renderSmart(v, { key: k })) : renderSmart(v, { key: k }))))];
      mount(body,
        h('div', { class: 'kv' },
          h('span', null, t('Collecté'), ' : ', h('b', null, ago(m.fetched_at))),
          m.status === 'ips_disabled' ? h('span', { class: 'err-txt' }, t('Le dashboard n’expose pas les IP (expose_ips).')) : null,
          session.perms.includes('indicators:view') && m.expose_ips ? h('span', { class: 'badge warn' }, t('IP visibles (données personnelles)')) : null,
          session.perms.includes('instances:refresh') ? h('button', { class: 'btn sm', type: 'button', onClick: async () => { try { await post(`/instances/${id}/modules/refresh`); await load(); toast(t('Actualisé')); } catch (e) { toast(e.message); } } }, icon('refresh', 14), t('Actualiser')) : null,
          data ? h('button', { class: 'btn sm', type: 'button', 'aria-pressed': String(rawOpen), onClick: () => { rawOpen = !rawOpen; load(); } }, t('Données brutes')) : null),
        stale ? h('div', { class: 'banner err', role: 'status' }, h('div', { class: 't' }, h('b', null, m.status === 'absent' ? t('Module désactivé sur le dashboard') : t('Dernière collecte en échec : {e}', { e: errorText(m.error) || m.status })),
          h('span', null, data ? t('Dernières données valides affichées ci-dessous (obsolètes).') : ''))) : null,
        errs.length ? h('div', { class: 'banner' }, h('div', { class: 't' }, h('b', null, t('Parties indisponibles (≠ zéro)')), h('span', null, errs.map(([k, v]) => `${partLabel(k)} : ${v}`).join(' · ')))) : null,
        rawOpen && data ? rawPanel(data) : null,
        dash || (data && name !== 'monitoring' ? kpisFor(name, data, m.derived) : null),
        dash ? h('details', { class: 'panel vz-all' }, h('summary', null, t('Toutes les données (détail)')), h('div', { class: 'stack pad' }, detailNodes())) : detailNodes(),
        !data && !stale ? h('div', { class: 'panel' }, h('div', { class: 'empty' }, t('Aucune donnée.'))) : null);
    } catch (e) {
      if (e.status === 404) mount(body, h('div', { class: 'panel' }, h('div', { class: 'empty' }, t('Pas encore collecté — patientez quelques minutes.'))));
      else if (e.code !== 'unauthenticated') mount(body, h('div', { class: 'panel' }, h('div', { class: 'empty' }, e.message)));
    }
  }
  mount(root, body);
  load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 60_000);
  return () => clearInterval(timer);
}

function orderParts(name, data) {
  const order = ORDER[name] || [];
  const keys = Object.keys(data);
  return [...order.filter((k) => k in data), ...keys.filter((k) => !order.includes(k))].map((k) => [k, data[k]]);
}
function count(v) {
  const n = Array.isArray(v) ? v.length : isObj(v) ? (arr(v, 'items', 'list', 'rows') || []).length || null : null;
  return n ? h('span', { class: 'badge' }, String(n)) : null;
}
function rawPanel(data) {
  let txt = JSON.stringify(data, null, 2);
  const cut = txt.length > 200_000;
  if (cut) txt = `${txt.slice(0, 200_000)}\n… ${t('tronqué')}`;
  return h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, t('Données brutes (JSON)')), h('button', { class: 'btn sm', type: 'button', onClick: () => copy(txt) }, t('Copier'))), h('pre', { class: 'raw mono' }, txt));
}
