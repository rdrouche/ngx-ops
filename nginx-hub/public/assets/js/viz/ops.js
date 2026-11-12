// Onglet Opérations : tâches planifiées, prochaines exécutions, historique, digests (ticket #67).
import { h } from '../dom.js';
import { fmt, ago, dateTime } from '../util.js';
import { t } from '../i18n.js';
import { opsModel } from './model-ops.js';
import { card, tile, hbars, donut, columns, empty } from './widgets.js';

const ST = { ok: 'ok', err: 'err', new: 'c3', off: 'off' };
const dur = (ms) => (ms === null ? '—' : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
const inFuture = (ms) => { const s = Math.round((ms - Date.now()) / 1000); return s < 60 ? t('dans {n} s', { n: Math.max(0, s) }) : s < 3600 ? t('dans {n} min', { n: Math.round(s / 60) }) : s < 86400 ? t('dans {n} h', { n: Math.round(s / 3600) }) : t('dans {n} j', { n: Math.round(s / 86400) }); };

export function opsView(data) {
  const m = opsModel(data);
  const k = m.kpis;
  const labels = { ok: t('Réussies'), err: t('En échec'), new: t('Jamais exécutées'), off: t('Désactivées') };

  const tiles = h('div', { class: 'kpis' },
    tile(t('Tâches planifiées'), fmt(k.tasks), t('{n} actives', { n: k.enabled })),
    tile(t('En échec'), fmt(k.failing), k.failing ? t('à vérifier') : t('aucune'), k.failing ? 'err' : 'ok'),
    tile(t('Exécutions'), fmt(k.runsTotal), k.running ? t('{n} en cours', { n: k.running }) : ''),
    tile(t('Digests'), fmt(k.digests), m.digests[0] ? t('dernier {d}', { d: ago(m.digests[0].at) }) : ''));

  const states = card(t('État des tâches'), k.tasks ? donut(m.states.map((s) => ({ label: labels[s.key], value: s.value, cls: ST[s.key] })), { center: String(k.tasks), sub: t('tâches') }) : empty());

  const next = card(t('Prochaines exécutions'), m.upcoming.length
    ? h('div', { class: 'tl' }, m.upcoming.slice(0, 8).map((x) => h('div', { class: 'tl-row' }, h('i', { class: 'tl-dot c1' }), h('div', null, h('b', null, x.name), h('small', null, x.schedule)), h('span', { class: 'num muted' }, inFuture(x.nextRun)))))
    : empty(t('Aucune exécution planifiée.')));

  const list = card(t('Tâches'), m.tasks.length
    ? h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, t('Tâche')), h('th', null, t('État')), h('th', null, t('Planification')), h('th', { class: 'r' }, t('Durée')), h('th', null, t('Dernière exécution')))),
      h('tbody', null, m.tasks.map((x) => h('tr', null, h('td', null, h('b', null, x.name), x.type ? h('div', { class: 'muted' }, x.type) : null),
        h('td', null, h('span', { class: `badge ${x.state === 'ok' ? 'ok' : x.state === 'err' ? 'err' : ''}` }, x.running ? t('en cours') : labels[x.state])),
        h('td', null, x.schedule || '—'), h('td', { class: 'r num' }, dur(x.durationMs)),
        h('td', { class: 'nowrap', title: x.lastMessage || '' }, x.lastRunAt ? ago(x.lastRunAt) : '—'))))))
    : empty(t('Aucune tâche planifiée.')), { badge: m.tasks.length });

  const durations = m.tasks.filter((x) => x.durationMs).length ? card(t('Durée de la dernière exécution'), hbars(m.tasks.filter((x) => x.durationMs).sort((a, b) => b.durationMs - a.durationMs).map((x) => ({ label: x.name, value: x.durationMs, cls: x.state === 'err' ? 'err' : 'c1' })), { format: dur, limit: 8 })) : null;

  const hist = m.runs.length ? card(t('Historique des exécutions'), columns(m.runs.filter((r) => r.at).map((r) => ({ t: Math.floor(r.at / 3600e3) * 3600e3, ok: r.ok ? 1 : 0, ko: r.ok ? 0 : 1 })).reduce((a, p) => { const e = a.find((x) => x.t === p.t); if (e) { e.ok += p.ok; e.ko += p.ko; } else a.push(p); return a; }, []).sort((a, b) => a.t - b.t), [{ key: 'ko', label: t('En échec'), cls: 'err' }, { key: 'ok', label: t('Réussies'), cls: 'ok' }])) : null;

  const dg = card('Digests', m.digests.length
    ? h('div', { class: 'tl' }, m.digests.slice(0, 8).map((x) => h('div', { class: 'tl-row' }, h('i', { class: 'tl-dot c4' }), h('div', null, h('b', null, dateTime(x.at)), x.hours ? h('small', null, t('période {n} h', { n: x.hours })) : null))))
    : empty(t('Aucun digest généré.')), { badge: m.digests.length });

  return h('div', { class: 'stack vz-root' }, tiles, h('div', { class: 'vz-grid' }, states, next, list, durations, hist, dg));
}
