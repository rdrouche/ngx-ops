import { t, tp } from '../i18n.js';
import { h, mount, icon } from '../dom.js';
import { get, post } from '../api.js';
import { sevLabel, fmt, compact, ago, badge, STATUS, ratioBar, hostOf, errorText, toast, bytes } from '../util.js';
import { instanceDialog } from './instance-form.js';
import { hbars } from '../viz/widgets.js';

const prefs = { q: '', status: 'all', sort: 'status', layout: 'cards' };
try { Object.assign(prefs, JSON.parse(sessionStorage.getItem('hub_prefs') || '{}')); } catch { /* préférences par défaut */ }
const savePrefs = () => { try { sessionStorage.setItem('hub_prefs', JSON.stringify(prefs)); } catch { /* ignoré */ } };

const RANK = { offline: 0, degraded: 1, unknown: 2, online: 3, disabled: 4 };
const SORTS = {
  status: (a, b) => RANK[a.status] - RANK[b.status] || (b.summary?.alerts_active || 0) - (a.summary?.alerts_active || 0) || a.name.localeCompare(b.name),
  name: (a, b) => a.name.localeCompare(b.name),
  alerts: (a, b) => (b.summary?.alerts_active || 0) - (a.summary?.alerts_active || 0) || a.name.localeCompare(b.name),
  traffic: (a, b) => ((b.summary?.humans || 0) + (b.summary?.robots || 0)) - ((a.summary?.humans || 0) + (a.summary?.robots || 0)),
};

function matches(i) {
  if (prefs.status !== 'all' && i.status !== prefs.status) return false;
  const q = prefs.q.trim().toLowerCase();
  return !q || [i.name, i.url, i.slug, ...(i.tags || []), i.summary?.version || ''].join(' ').toLowerCase().includes(q);
}

const go = (i) => { window.location.hash = `#/i/${i.id}`; };

function card(i) {
  const s = i.summary;
  return h('a', { class: `card s-${i.status}`, href: `#/i/${i.id}` },
    h('div', { class: 'card-h' }, h('div', null, h('div', { class: 'name' }, i.name), h('div', { class: 'host' }, hostOf(i.url))), badge(STATUS, i.status)),
    s ? h('div', { class: 'stats' },
      h('div', { class: 'stat' }, h('span', { class: 'l' }, 'Vhosts'), h('span', { class: 'v' }, fmt(s.vhosts))),
      h('div', { class: 'stat' }, h('span', { class: 'l' }, 'Alertes'), h('span', { class: `v ${s.alerts_critical ? 'err-txt' : ''}` }, fmt(s.alerts_active))),
      h('div', { class: 'stat' }, h('span', { class: 'l' }, 'Version'), h('span', { class: 'v' }, s.version || '—'))) : h('p', { class: 'muted' }, i.enabled ? 'En attente de la première collecte…' : 'Collecte désactivée'),
    s ? h('div', null, h('div', { class: 'card-f' }, h('span', null, t('Humains {n}', { n: compact(s.humans) })), h('span', null, t('Robots {n}', { n: compact(s.robots) }))), ratioBar(s.humans, s.robots)) : null,
    i.last_error && i.status !== 'online' ? h('div', { class: 'err-txt' }, errorText(i.last_error)) : null,
    h('div', { class: 'card-f' }, h('span', null, ago(i.last_contact_at)), h('span', null, i.latency_ms != null ? `${i.latency_ms} ms` : ''), h('span', null, (i.tags || []).map((t) => h('span', { class: 'chip' }, t)))));
}

function table(items) {
  return h('div', { class: 'panel' }, h('div', { class: 'tbl-wrap' }, h('table', null,
    h('thead', null, h('tr', null, ...['Instance', 'État', 'Version', 'Vhosts', 'Humains', 'Robots', 'Alertes', 'Latence', 'Dernier contact'].map((t, k) => h('th', { scope: 'col', class: k >= 3 && k <= 7 ? 'r' : '' }, t)))),
    h('tbody', null, items.map((i) => {
      const s = i.summary;
      return h('tr', { class: 'click', tabindex: '0', onClick: () => go(i), onKeydown: (e) => { if (e.key === 'Enter') go(i); } },
        h('td', null, h('b', null, i.name), h('div', { class: 'muted' }, hostOf(i.url))), h('td', null, badge(STATUS, i.status)), h('td', null, s?.version || '—'),
        h('td', { class: 'r num' }, fmt(s?.vhosts)), h('td', { class: 'r num' }, compact(s?.humans)), h('td', { class: 'r num' }, compact(s?.robots)),
        h('td', { class: `r num ${s?.alerts_critical ? 'err-txt' : ''}` }, fmt(s?.alerts_active)), h('td', { class: 'r num' }, i.latency_ms != null ? `${i.latency_ms} ms` : '—'), h('td', null, ago(i.last_contact_at)));
    })))));
}

function kpi(label, value, note, cls = '') {
  return h('div', { class: 'kpi' }, h('span', { class: 'l' }, label), h('span', { class: 'v' }, value), h('span', { class: `n ${cls}` }, note));
}

export function overviewView(root, { session }) {
  const isAdmin = session.perms.includes('instances:write');
  const top = h('div', { class: 'stack' }); const bottom = h('div', { class: 'stack' }); const list = h('div');
  let timer = null; let data = null; let ov = null;

  const renderList = () => {
    if (!data) return;
    const items = data.items.filter(matches).sort(SORTS[prefs.sort]);
    mount(list, !data.items.length
      ? h('div', { class: 'panel' }, h('div', { class: 'empty' }, 'Aucune instance. ', isAdmin ? 'Ajoutez votre premier dashboard NGX Ops.' : 'Demandez à un administrateur d’en ajouter.'))
      : !items.length ? h('div', { class: 'panel' }, h('div', { class: 'empty' }, 'Aucune instance ne correspond au filtre.'))
        : prefs.layout === 'table' ? table(items) : h('div', { class: 'cards' }, items.map(card)));
  };

  const sevBadge = (sev) => h('span', { class: `badge ${sev === 'critical' ? 'err' : sev === 'warning' ? 'warn' : ''}` }, sevLabel(sev));
  const certBadge = (d) => h('span', { class: `badge ${d !== null && d < 0 ? 'err' : d !== null && d <= 14 ? 'warn' : ''}` }, d === null ? '?' : d < 0 ? 'Expiré' : `${d} j`);

  const renderTop = () => {
    if (!ov) return;
    const c = ov.counts; const tot = ov.totals; const bk = ov.backups;
    const down = c.offline;
    mount(top,
      down ? h('div', { class: 'banner err', role: 'status' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, tp('{n} instance hors ligne', '{n} instances hors ligne', down)), h('span', null, 'Aucune réponse valide après plusieurs tentatives consécutives.')),
        h('button', { class: 'btn sm', type: 'button', onClick: () => { prefs.status = 'offline'; savePrefs(); renderAll(); } }, 'Voir')) : null,
      h('div', { class: 'kpis' },
        kpi('Instances en ligne', `${c.online} / ${c.total - c.disabled}`, c.degraded ? tp('{n} dégradée', '{n} dégradées', c.degraded) : 'Toutes opérationnelles', c.degraded || down ? 'warn' : 'ok'),
        kpi('Alertes actives', fmt(tot.alerts_active), tot.alerts_critical ? tp('{n} critique', '{n} critiques', tot.alerts_critical) : 'Aucune critique', tot.alerts_critical ? 'err' : 'ok'),
        kpi('Requêtes (24 h)', compact(tot.requests || (tot.humans + tot.robots)), t('{e} erreurs · {b}', { e: compact(tot.errors), b: bytes(tot.bytes) }), tot.requests && tot.errors / tot.requests > 0.05 ? 'warn' : ''),
        kpi('Requêtes humaines (24 h)', compact(tot.humans), t('{r} robots · {b} bloquées', { r: compact(tot.robots), b: compact(tot.blocked) })),
        kpi('Virtual hosts', fmt(tot.vhosts), t('{n} connexions nginx', { n: fmt(tot.connections) })),
        bk && bk.expected ? kpi('Sauvegardes à jour', `${bk.ok} / ${bk.expected}`, bk.late.length ? t('{n} en retard', { n: bk.late.length }) : t('Toutes récentes'), bk.late.length ? 'err' : 'ok') : null),
      bk && bk.late.length ? h('div', { class: 'banner err', role: 'status' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, tp('{n} instance sans sauvegarde depuis plus de {h} h', '{n} instances sans sauvegarde depuis plus de {h} h', bk.late.length, { h: bk.alert_after_hours })), h('span', null, bk.late.map((x) => x.name).join(', '))),
        h('a', { class: 'btn sm', href: '#/backups' }, 'Voir')) : null);

    // Sous la liste des instances : Alertes récentes | Pays côte à côte, puis certificats.
    mount(bottom,
      (ov.alerts.length || ov.top_countries.length) ? h('div', { class: 'cols2 even' },
        h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Alertes récentes (toutes instances)')),
          ov.alerts.length ? h('div', { class: 'tbl-wrap' }, h('table', null, h('tbody', null, ov.alerts.slice(0, 6).map((a) => h('tr', { class: 'click', onClick: () => { window.location.hash = `#/i/${a.instance_id}`; } },
            h('td', null, sevBadge(a.severity)), h('td', null, h('b', null, a.title)), h('td', { class: 'muted' }, a.instance), h('td', { class: 'muted nowrap' }, a.since ? ago(Date.parse(a.since)) : '')))))) : h('div', { class: 'empty' }, 'Aucune alerte.')),
        h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Pays (requêtes 24 h, toutes instances)')),
          ov.top_countries.length ? h('div', { class: 'panel-b' }, hbars(ov.top_countries.slice(0, 8).map((x) => ({ label: x.country === '??' ? t('Inconnu') : x.country, value: x.requests })), { format: compact })) : h('div', { class: 'empty' }, 'Aucune donnée.'))) : null,
      ov.certs_expiring.length ? h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Certificats à renouveler')),
        h('div', { class: 'panel-b mini' }, ov.certs_expiring.slice(0, 6).map((x) => h('div', null, h('span', null, h('b', null, x.name), ' ', h('span', { class: 'd' }, x.instance)), certBadge(x.days_left))))) : null);
  };

  const renderAll = () => { renderTop(); renderList(); renderToolbar(); };

  async function load() {
    try { [data, ov] = await Promise.all([get('/instances'), get('/overview')]); renderAll(); } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
  }

  const search = h('input', { class: 'field', type: 'search', placeholder: 'Filtrer par nom, URL, étiquette, version…', 'aria-label': 'Filtrer les instances', value: prefs.q, onInput: (e) => { prefs.q = e.target.value; savePrefs(); renderList(); } });
  const sel = (opts, key, label) => h('select', { class: 'select', 'aria-label': label, onChange: (e) => { prefs[key] = e.target.value; savePrefs(); renderAll(); } },
    opts.map(([v, l]) => h('option', { value: v, selected: prefs[key] === v }, l)));
  const toolbarEl = h('div', { class: 'toolbar' });
  function renderToolbar() {
    mount(toolbarEl, h('div', { class: 'grow' }, search),
      sel([['all', 'Tous les états'], ['online', 'En ligne'], ['degraded', 'Dégradé'], ['offline', 'Hors ligne'], ['unknown', 'Inconnu'], ['disabled', 'Désactivé']], 'status', 'Filtrer par état'),
      sel([['status', 'Tri : état'], ['name', 'Tri : nom'], ['alerts', 'Tri : alertes'], ['traffic', 'Tri : trafic']], 'sort', 'Trier'),
      h('div', { class: 'seg', role: 'group', 'aria-label': 'Affichage' },
        h('button', { type: 'button', 'aria-pressed': String(prefs.layout === 'cards'), onClick: () => { prefs.layout = 'cards'; savePrefs(); renderAll(); } }, 'Cartes'),
        h('button', { type: 'button', 'aria-pressed': String(prefs.layout === 'table'), onClick: () => { prefs.layout = 'table'; savePrefs(); renderAll(); } }, 'Liste')));
  }

  mount(root,
    h('div', { class: 'page-h' }, h('div', null, h('h1', null, 'Vue d’ensemble'), h('p', null, 'État de tous les dashboards NGX Ops en un coup d’œil.')),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', type: 'button', onClick: async () => { await load(); toast('Actualisé'); } }, icon('refresh', 15), 'Actualiser'),
        isAdmin ? h('button', { class: 'btn primary', type: 'button', onClick: () => instanceDialog({ onSaved: load }) }, 'Ajouter une instance') : null)),
    top, toolbarEl, list, bottom);
  renderToolbar();
  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 30_000);
  return () => clearInterval(timer);
}
