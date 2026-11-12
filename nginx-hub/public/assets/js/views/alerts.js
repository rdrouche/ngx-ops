// Alertes détaillées (contrat 12.78.0) : liste filtrable, par instance ou globale. Les IP n'apparaissent que pour les admins
// (permission indicators:view) et seulement si le dashboard les expose.
import { h, mount } from '../dom.js';
import { get } from '../api.js';
import { dateTime, fmt, toast, sevLabel } from '../util.js';
import { t } from '../i18n.js';

const PAGE = 50;
const sevCls = (s) => (s === 'critical' || s === 'high' ? 'err' : s === 'medium' || s === 'warning' ? 'warn' : '');

/** @returns {{el: HTMLElement, load: Function}} */
export function alertsList({ instanceId = null, instances = [], session }) {
  const el = h('div', { class: 'stack' });
  const f = { instance: instanceId || '', severity: '', acked: '', offset: 0 };
  let data = null;
  const canIps = session.perms.includes('indicators:view');

  const sel = (key, opts, label) => h('select', { class: 'select', 'aria-label': label, onChange: (e) => { f[key] = e.target.value; f.offset = 0; load(); } },
    opts.map(([v, l]) => h('option', { value: v, selected: String(f[key]) === String(v) }, l)));

  function render() {
    const sevs = [...new Set(data.facets.map((x) => x.severity).filter(Boolean))].sort();
    mount(el,
      h('div', { class: 'toolbar' },
        instanceId ? null : sel('instance', [['', t('Toutes les instances')], ...instances.map((i) => [i.id, i.name])], t('Instance')),
        sel('severity', [['', t('Toutes sévérités')], ...sevs.map((s) => [s, sevLabel(s)])], t('Sévérité')),
        sel('acked', [['', t('Toutes')], ['0', t('Non acquittées')], ['1', t('Acquittées')]], t('État')),
        h('span', { class: 'muted grow' }, t('{n} alerte(s)', { n: fmt(data.total) }))),
      h('section', { class: 'panel' }, data.items.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
        h('thead', null, h('tr', null, [t('Date'), t('Sévérité'), t('Type'), t('Résumé'), t('Vhost'), t('Pays'), t('IP'), instanceId ? '' : t('Instance'), t('État')].map((x) => h('th', { scope: 'col' }, x)))),
        h('tbody', null, data.items.map((a) => {
          const ev = a.evidence && Object.keys(a.evidence).length ? a.evidence : null;
          return h('tr', null,
            h('td', { class: 'num nowrap' }, dateTime(a.ts)),
            h('td', null, h('span', { class: `badge ${sevCls(a.severity)}` }, sevLabel(a.severity))),
            h('td', null, h('span', { class: 'chip mono' }, a.type || '—')),
            h('td', null, a.summary || '—', ev ? h('details', { class: 'ev' }, h('summary', null, t('Éléments de preuve')), h('pre', { class: 'mono' }, JSON.stringify(ev, null, 2))) : null),
            h('td', null, a.vhost || '—'), h('td', null, a.country || '—'),
            h('td', { class: 'mono' }, canIps && a.ips && a.ips.length ? a.ips.join(', ') : (a.ip_count ? t('{n} IP', { n: a.ip_count }) : '—')),
            instanceId ? null : h('td', null, h('a', { href: `#/i/${a.instance_id}` }, a.instance)),
            h('td', null, a.acked ? h('span', { class: 'badge ok' }, t('Acquittée')) : h('span', { class: 'badge warn' }, t('Ouverte'))));
        })))) : h('div', { class: 'empty' }, t('Aucune alerte détaillée collectée.'))),
      data.total > PAGE ? h('div', { class: 'actions' },
        h('button', { class: 'btn sm', type: 'button', disabled: f.offset === 0, onClick: () => { f.offset = Math.max(0, f.offset - PAGE); load(); } }, t('Précédent')),
        h('span', { class: 'muted' }, `${f.offset + 1}–${Math.min(f.offset + PAGE, data.total)} / ${fmt(data.total)}`),
        h('button', { class: 'btn sm', type: 'button', disabled: f.offset + PAGE >= data.total, onClick: () => { f.offset += PAGE; load(); } }, t('Suivant'))) : null);
  }

  async function load() {
    const q = new URLSearchParams({ limit: PAGE, offset: f.offset });
    if (f.instance) q.set('instance', f.instance);
    if (f.severity) q.set('severity', f.severity);
    if (f.acked !== '') q.set('acked', f.acked);
    try { data = await get(`/alerts?${q}`); render(); } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
  }
  return { el, load };
}

export function alertsView(root, { session }) {
  const host = h('div');
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, t('Alertes')), h('p', null, t('Alertes d’analyse détaillées remontées par les dashboards (conservées {n} jours).', { n: 30 })))), host);
  let timer = null;
  (async () => {
    let instances = [];
    try { instances = (await get('/instances')).items; } catch { /* filtre instance indisponible */ }
    const list = alertsList({ instances, session });
    mount(host, list.el); list.load();
    timer = setInterval(() => { if (!document.hidden) list.load(); }, 60_000);
  })();
  return () => clearInterval(timer);
}
