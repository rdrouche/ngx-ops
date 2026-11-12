import { t } from '../i18n.js';
import { h, mount, icon } from '../dom.js';
import { get, post } from '../api.js';
import { sevLabel, fmt, compact, ago, dateTime, uptime, badge, STATUS, COMPONENT, COMPONENT_NAMES, ratioBar, hostOf, errorText, toast, bytes } from '../util.js';
import { backupsPanel } from './backups.js';
import { lineChart, chartBox } from '../charts.js';
import { instanceDialog } from './instance-form.js';
import { tabBar, tabPage } from './tabs.js';
import { hbars, donut } from '../viz/widgets.js';

const RANGES = [['24h', '24 h'], ['7d', '7 jours'], ['30d', '30 jours']];

function secPanel(s) {
  const sec = s.security || {};
  const rows = [];
  if (sec.crowdsec) rows.push(['CrowdSec — décisions actives', typeof sec.crowdsec.active === 'boolean' ? (sec.crowdsec.active ? 'Actif' : 'Inactif') : fmt(sec.crowdsec.active)]);
  if (sec.waf) rows.push(['WAF — requêtes bloquées (24 h)', fmt(sec.waf.blocked_24h)]);
  if (sec.blocklists) { rows.push(['Listes de blocage — IP', fmt(sec.blocklists.ips)]); rows.push(['Listes de blocage — hits (24 h)', fmt(sec.blocklists.hits_24h)]); }
  if (s.mfa && s.mfa.accounts !== null) rows.push(['Comptes avec MFA', fmt(s.mfa.accounts)]);
  return h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Sécurité')),
    h('div', { class: 'panel-b mini' }, rows.length ? rows.map(([l, v]) => h('div', null, h('span', { class: 'd' }, l), h('b', { class: 'num' }, v))) : h('p', { class: 'muted' }, 'Aucune donnée de sécurité remontée.')));
}

function kpi(label, value, note, small) {
  return h('div', { class: 'kpi' }, h('span', { class: 'l' }, label), h('span', { class: `v ${small ? 'sm' : ''}` }, value), h('span', { class: 'n' }, note || ''));
}

export function instanceView(root, { session, id, tab = 'overview' }) {
  const isAdmin = session.perms.includes('instances:write');
  const canRefresh = session.perms.includes('instances:refresh');
  const body = h('div', { class: 'stack' }); const chartsEl = h('div');
  const backups = session.perms.includes('backups:view') ? backupsPanel({ id, session }) : { el: null, load: () => {} };
  let range = '24h'; let timer = null; let inst = null; let mods = null; let tabsDispose = null;

  async function loadHistory() {
    try {
      const { points } = await get(`/instances/${id}/history?range=${range}`);
      const pct = (p) => (p.up === null ? null : p.up * 100);
      const pts = points.map((p) => ({ ...p, up: pct(p) }));
      mount(chartsEl, h('section', { class: 'panel' },
        h('div', { class: 'panel-h' }, h('h2', null, 'Historique'), h('div', { class: 'seg', role: 'group', 'aria-label': 'Période' }, RANGES.map(([k, l]) => h('button', { type: 'button', 'aria-pressed': String(range === k), onClick: () => { range = k; loadHistory(); } }, l)))),
        h('div', { class: 'panel-b charts' },
          chartBox('Disponibilité (%)', lineChart(pts, [{ key: 'up', cls: 'l2', area: false }], { fixedMax: 100, format: (v) => `${Math.round(v)}` })),
          chartBox('Latence (ms)', lineChart(pts, [{ key: 'latency_ms', cls: 'l1', area: true }], { format: (v) => `${Math.round(v)}` })),
          chartBox('Requêtes 24 h glissantes', lineChart(pts, [{ key: 'humans', cls: 'l1' }, { key: 'robots', cls: 'l2' }]), [['c1', 'Humains'], ['c2', 'Robots']]),
          chartBox('Requêtes et erreurs (24 h glissantes)', lineChart(pts, [{ key: 'requests', cls: 'l1', area: true }, { key: 'errors', cls: 'l3' }]), [['c1', 'Requêtes'], ['c3', 'Erreurs']]),
          chartBox('Alertes actives', lineChart(pts, [{ key: 'alerts', cls: 'l3', area: false }], { format: (v) => `${Math.round(v)}` })))));
    } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
  }

  function pageHead(i) {
    return h('div', { class: 'page-h' },
      h('div', null, h('a', { href: '#/' }, '← Toutes les instances'), h('h1', null, i.name, ' ', badge(STATUS, i.status)), h('p', null, hostOf(i.url), ' · dernier contact ', ago(i.last_contact_at), i.latency_ms != null ? ` · ${i.latency_ms} ms` : '')),
      h('div', { class: 'actions' },
        h('a', { class: 'btn primary', href: i.deeplink, target: '_blank', rel: 'noopener noreferrer' }, 'Ouvrir le dashboard ', icon('ext', 15)),
        canRefresh ? h('button', { class: 'btn', type: 'button', onClick: async (e) => { e.currentTarget.disabled = true; try { inst = await post(`/instances/${id}/refresh`); render(); toast('Actualisé'); } catch (ex) { toast(ex.message); } } }, icon('refresh', 15), 'Actualiser') : null,
        isAdmin ? h('button', { class: 'btn', type: 'button', onClick: () => instanceDialog({ instance: i, onSaved: load, onDeleted: () => { window.location.hash = '#/'; } }) }, 'Modifier') : null));
  }

  function render() {
    const i = inst; const s = i.detail; const b = i.summary;
    const tbl = (rows) => h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Virtual host'), h('th', { scope: 'col', class: 'r' }, 'Requêtes'), h('th', { scope: 'col', class: 'r' }, 'Erreurs'), h('th', { scope: 'col', class: 'r' }, 'Volume'))),
      h('tbody', null, rows.map((r) => h('tr', null, h('td', null, h('b', null, r.name)), h('td', { class: 'r num' }, fmt(r.requests)), h('td', { class: `r num ${r.errors && r.requests && r.errors / r.requests > 0.05 ? 'err-txt' : ''}` }, fmt(r.errors)), h('td', { class: 'r num' }, bytes(r.bytes)))))));

    mount(body,
      pageHead(i),
      tabBar(id, 'overview', mods, session),
      i.last_error && i.status !== 'online' ? h('div', { class: 'banner err', role: 'status' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, errorText(i.last_error)), h('span', null, t('{n} échec(s) consécutif(s) · dernière réponse valide : {d}', { n: i.consecutive_failures, d: i.last_ok_at ? dateTime(i.last_ok_at) : t('aucune') })))) : null,
      !i.enabled ? h('div', { class: 'banner' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, 'Collecte désactivée'), h('span', null, 'Aucune requête n’est envoyée à cette instance.'))) : null,
      b && s ? h('div', { class: 'stack' },
        h('div', { class: 'kpis' },
          kpi('Version NGX Ops', b.version || '—', b.hostname || '', true), kpi('nginx', b.nginx_status === 'running' ? 'En marche' : b.nginx_status === 'stopped' ? 'Arrêté' : 'Inconnu', `${b.nginx_version || ''} ${s.nginx.uptime_s ? '· ' + uptime(s.nginx.uptime_s) : ''}`.trim(), true),
          kpi('Virtual hosts', fmt(b.vhosts), s.nginx.config_ok === false ? 'Configuration invalide' : t('{n} connexions', { n: fmt(b.connections) })), kpi('Requêtes (24 h)', b.traffic_available ? compact(b.requests || b.humans + b.robots) : '—', b.traffic_available ? t('{e} erreurs · {b}', { e: compact(b.errors), b: bytes(b.bytes) }) : 'Analyse indisponible'),
          kpi('Humains / robots (24 h)', b.traffic_available ? compact(b.humans) : '—', b.traffic_available ? t('{r} robots · {b} bloquées', { r: compact(b.robots), b: compact(b.blocked) }) : '', false),
          kpi('Alertes actives', fmt(b.alerts_active), b.alerts_critical ? t('{n} critique(s)', { n: b.alerts_critical }) : 'Aucune critique'))) : null,
      b && s ? h('div', { class: 'cols' },
        h('div', { class: 'main' },
          h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Top virtual hosts (24 h)')), s.top_vhosts.length ? h('div', { class: 'panel-b' }, hbars(s.top_vhosts.map((r) => ({ label: r.name, value: r.requests || 0, sub: `${r.errors ? `${fmt(r.errors)} ${t('err.')} · ` : ''}${bytes(r.bytes)}`, cls: r.requests && r.errors / r.requests > 0.05 ? 'warn' : 'c1' })), { format: compact }))
            : h('div', { class: 'empty' }, 'Aucune donnée.'),
            b.traffic_available ? h('div', { class: 'panel-b' }, donut([{ label: t('Humains'), value: b.humans || 0, cls: 'c2' }, { label: t('Bots'), value: b.robots || 0, cls: 'c5' }], { center: compact((b.humans || 0) + (b.robots || 0)), sub: t('requêtes') })) : null),
          chartsEl, backups.el),
        h('div', { class: 'side' },
          h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Composants')), h('div', { class: 'panel-b' },
            Object.keys(s.components).length ? Object.entries(s.components).map(([k, c]) => h('div', { class: 'comp' }, h('div', null, h('div', null, h('b', null, COMPONENT_NAMES[k] || k)), c.detail ? h('div', { class: 'd' }, c.detail) : null), badge(COMPONENT, c.state))) : h('p', { class: 'muted' }, 'Aucun composant remonté.'))),
          secPanel(s),
          s.certs_expiring.length ? h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Certificats à renouveler')), h('div', { class: 'panel-b mini' },
            s.certs_expiring.map((c) => h('div', null, h('b', null, c.name), h('span', { class: `badge ${c.days_left !== null && c.days_left < 0 ? 'err' : c.days_left !== null && c.days_left <= 14 ? 'warn' : ''}` }, c.days_left === null ? '?' : c.days_left < 0 ? 'Expiré' : t('{n} j', { n: c.days_left })))))) : null,
          s.top_countries.length ? h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Pays (24 h)')), h('div', { class: 'panel-b' }, hbars(s.top_countries.map((c) => ({ label: c.country === '??' ? t('Inconnu') : c.country, value: c.requests })), { format: compact }))) : null,
          h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Alertes actives')), h('div', { class: 'panel-b' },
            s.alerts.items.length ? h('div', { class: 'alist' }, s.alerts.items.map((a) => h('div', null, h('div', null, h('span', { class: `badge ${a.severity === 'critical' ? 'err' : a.severity === 'warning' ? 'warn' : ''}` }, sevLabel(a.severity)), ' ', h('b', null, a.title)), h('span', { class: 'muted' }, a.since ? ago(Date.parse(a.since)) : '')))) : h('p', { class: 'muted' }, 'Aucune alerte.'))))) : null,
      s?.schema_newer ? h('p', { class: 'muted' }, 'Ce dashboard utilise un schéma de résumé plus récent : seuls les champs connus du Hub sont affichés.') : null,
      b && s ? null : h('div', { class: 'stack' }, chartsEl, backups.el));
  }

  async function load() {
    try { inst = await get(`/instances/${id}`); try { mods = await get(`/instances/${id}/modules`); } catch { mods = null; } render(); loadHistory(); backups.load(); }
    catch (e) { if (e.status === 404) mount(body, h('div', { class: 'panel' }, h('div', { class: 'empty' }, 'Instance introuvable. ', h('a', { href: '#/' }, 'Retour')))); else if (e.code !== 'unauthenticated') toast(e.message); }
  }
  async function tick() { try { inst = await get(`/instances/${id}`); render(); } catch { /* prochain cycle */ } }

  if (tab !== 'overview') {
    // onglet de module : en-tête de l'instance + barre + contenu du module
    const head = h('div');
    get(`/instances/${id}`).then((i) => { inst = i; mount(head, pageHead(i)); }).catch((e) => { if (e.code !== 'unauthenticated') toast(e.message); });
    tabsDispose = tabPage(root, { id, tab, session, header: head });
    return () => tabsDispose();
  }
  mount(root, body);
  load();
  timer = setInterval(() => { if (!document.hidden) tick(); }, 30_000);
  return () => clearInterval(timer);
}
