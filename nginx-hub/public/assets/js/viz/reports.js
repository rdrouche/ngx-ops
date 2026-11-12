// Onglet Rapports : règles d'analyse, apprentissage de la baseline, exceptions (ticket #67).
import { h } from '../dom.js';
import { fmt } from '../util.js';
import { t } from '../i18n.js';
import { reportsModel } from './model-ops.js';
import { card, tile, donut, meter, empty } from './widgets.js';

const SEV = { critical: 'err', high: 'err', medium: 'warn', low: 'c1', info: 'c4' };
const BASE = () => ({ vhost: t('Par vhost'), country: t('Par pays'), data: t('Volume de données') });
const remed = (r) => (r.remediation ? t('remédiation : {m}', { m: r.remediationType || 'block' }) : t('alerte seule'));

export function reportsView(data) {
  const m = reportsModel(data);
  const k = m.kpis;

  const tiles = h('div', { class: 'kpis' },
    tile(t('Règles intégrées'), `${k.builtinsOn} / ${k.builtins}`, t('actives')),
    tile(t('Règles personnalisées'), `${k.customOn} / ${k.custom}`, t('actives')),
    tile(t('Avec remédiation'), fmt(k.remediating), t('blocage ou challenge automatique')),
    tile(t('Exceptions'), fmt(k.exceptions), ''));

  const ruleChips = (rows) => h('div', { class: 'rules' }, rows.map((r) => h('div', { class: `rule ${r.enabled ? '' : 'off'}` }, h('i', { class: `dot ${r.enabled ? 'ok' : 'off'}`, 'aria-hidden': 'true' }), h('b', null, r.name || r.key), h('small', null, [r.enabled ? t('active') : t('désactivée'), r.enabled ? remed(r) : ''].filter(Boolean).join(' · ')))));
  const builtin = card(t('Règles intégrées'), m.builtins.length ? h('div', { class: 'vz-split' }, donut([{ label: t('Actives'), value: k.builtinsOn, cls: 'ok' }, { label: t('Désactivées'), value: k.builtins - k.builtinsOn, cls: 'off' }], { center: `${k.builtinsOn}/${k.builtins}` }), ruleChips(m.builtins)) : empty(), { badge: m.builtins.length });

  const custom = card(t('Règles personnalisées'), m.custom.length
    ? h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, t('Règle')), h('th', null, t('Sévérité')), h('th', { class: 'r' }, t('Seuil')), h('th', null, t('Portée')), h('th', null, t('Action')))),
      h('tbody', null, m.custom.map((r) => h('tr', { class: r.enabled ? '' : 'muted' }, h('td', null, h('b', null, r.name), h('div', { class: 'muted' }, `#${r.id}`)),
        h('td', null, r.severity ? h('span', { class: `badge ${SEV[r.severity] === 'err' ? 'err' : SEV[r.severity] === 'warn' ? 'warn' : ''}` }, r.severity) : '—'),
        h('td', { class: 'r num nowrap' }, r.minMatches !== null ? `${r.minMatches} / ${r.windowMinutes ?? '?'} min` : '—'), h('td', null, r.scope || '—'),
        h('td', null, r.enabled ? remed(r) : t('désactivée')))))))
    : empty(t('Aucune règle personnalisée.')), { badge: m.custom.length });

  const base = card(t('Apprentissage de la baseline'), m.baselines.length
    ? h('div', { class: 'vz-stack' }, m.baselines.map(([key, b]) => h('div', null,
      h('div', { class: 'vz-cap' }, h('b', null, BASE()[key]), h('span', { class: 'muted' }, b.learning ? t('apprentissage : jour {d} sur {r}', { d: b.daysElapsed, r: b.daysRequired }) : t('opérationnelle'))),
      meter(b.daysRequired ? (b.daysElapsed / b.daysRequired) * 100 : 100, b.learning ? 'c3' : 'ok'),
      h('div', { class: 'vz-cap' }, h('span', { class: 'muted' }, [b.coverage !== null ? t('couverture {n} %', { n: Math.round(b.coverage * (b.coverage <= 1 ? 100 : 1)) }) : '', b.keys !== null ? t('{n} clés suivies', { n: fmt(b.keys) }) : '', b.vhosts !== null ? t('{n} vhosts', { n: fmt(b.vhosts) }) : ''].filter(Boolean).join(' · '))))))
    : empty());

  const exc = card(t('Exceptions'), m.exceptions.length
    ? h('div', { class: 'chips' }, m.exceptions.slice(0, 40).map((e) => h('span', { class: 'chip' }, String(e.vhost ?? e.host ?? e.pattern ?? e.path ?? e.id ?? '?'), e.ruleId ? ` · #${e.ruleId}` : '')))
    : empty(t('Aucune exception.')), { badge: m.exceptions.length });

  return h('div', { class: 'stack vz-root' }, tiles, h('div', { class: 'vz-grid' }, builtin, base, custom, exc));
}
