// Composants graphiques SVG/DOM des vues (ticket #67). Aucun HTML injecté, aucun style inline en attribut (CSP) :
// les largeurs passent par l'API CSSOM (el.style.width), les couleurs par des classes (c1…c6, ok, warn, err).
import { h, svg } from '../dom.js';
import { fmt, compact } from '../util.js';
import { t, locale } from '../i18n.js';

/** Carte (panneau) avec titre, badge optionnel et corps. */
export function card(title, body, { badge, note, cls } = {}) {
  return h('section', { class: `panel vz ${cls || ''}` },
    h('div', { class: 'panel-h' }, h('h2', null, title, badge !== undefined && badge !== null ? h('span', { class: 'badge inl' }, String(badge)) : null), note ? h('span', { class: 'muted' }, note) : null),
    h('div', { class: 'panel-b' }, body));
}

export const empty = (msg) => h('div', { class: 'vz-empty' }, msg || t('Aucune donnée sur la période.'));

/** Tuile KPI avec valeur, détail et ton (ok|warn|err). */
export function tile(label, value, note, tone) {
  return h('div', { class: `kpi vz-tile ${tone ? `t-${tone}` : ''}` }, h('span', { class: 'l' }, label), h('span', { class: 'v' }, value), h('span', { class: 'n' }, note || ''));
}

/** Pastille d'état d'un composant (ok|warn|err|off). */
export function status(label, st, detail) {
  const word = { ok: t('Actif'), warn: t('À vérifier'), err: t('En panne'), off: t('Inactif') }[st] || st;
  return h('div', { class: `vz-status s-${st}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), h('div', null, h('b', null, label), h('small', null, detail ? `${word} · ${detail}` : word)));
}

const setW = (el, p) => { el.style.width = `${Math.max(0, Math.min(100, p))}%`; return el; };

/** Barres horizontales triées. items: [{label, value, sub?, cls?}] */
export function hbars(items, { format = fmt, max, mono = false, limit } = {}) {
  const rows = (limit ? items.slice(0, limit) : items);
  if (!rows.length) return empty();
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  // Libellés longs : libellé + valeur sur une ligne, barre pleine largeur dessous (aucune troncature) ; sinon colonnes alignées.
  const long = rows.some((r) => r.label.length > 18);
  return h('div', { class: `hb ${long ? 'two' : 'cols3'}`, role: 'list' }, rows.map((r) => h('div', { class: 'hb-row', role: 'listitem' },
    h('span', { class: `hb-l ${mono ? 'mono' : ''}`, title: r.label }, r.label),
    h('span', { class: 'hb-t' }, setW(h('i', { class: r.cls || 'c1' }), (r.value / top) * 100)),
    h('span', { class: 'hb-v num' }, format(r.value), r.sub ? h('small', null, r.sub) : null))));
}

/** Anneau + légende. items: [{label, value, cls}] */
export function donut(items, { center, sub, size = 132 } = {}) {
  const data = items.filter((i) => i.value > 0);
  const total = data.reduce((a, i) => a + i.value, 0);
  if (!total) return empty();
  const r = 15.9155; // circonférence = 100
  let off = 25;
  const arcs = data.map((i) => {
    const len = (i.value / total) * 100;
    const el = svg('circle', { cx: 21, cy: 21, r, fill: 'none', 'stroke-width': 5.5, 'stroke-dasharray': `${Math.max(0, len - (data.length > 1 ? 0.6 : 0)).toFixed(2)} ${(100 - len + (data.length > 1 ? 0.6 : 0)).toFixed(2)}`, 'stroke-dashoffset': off.toFixed(2), class: `seg ${i.cls || 'c1'}` }, svg('title', null, `${i.label} : ${fmt(i.value)}`));
    off -= len;
    return el;
  });
  const chart = svg('svg', { viewBox: '0 0 42 42', width: size, height: size, role: 'img', 'aria-label': data.map((i) => `${i.label} ${fmt(i.value)}`).join(', ') },
    svg('circle', { cx: 21, cy: 21, r, fill: 'none', 'stroke-width': 5.5, class: 'ring-bg' }), ...arcs,
    svg('text', { x: 21, y: sub ? 20.5 : 22.5, 'text-anchor': 'middle', class: 'dn-c' }, center ?? compact(total)),
    sub ? svg('text', { x: 21, y: 26.5, 'text-anchor': 'middle', class: 'dn-s' }, sub) : null);
  return h('div', { class: 'donut' }, chart, h('ul', { class: 'lg' }, data.map((i) => h('li', null, h('i', { class: i.cls || 'c1' }), h('span', { class: 'lg-l' }, i.label), h('b', { class: 'num' }, fmt(i.value), ' ', h('small', null, `${Math.round((i.value / total) * 100)} %`))))));
}

/** Entonnoir / étapes : barres pleines proportionnelles à la première étape. steps: [{label, value, cls}] */
export function funnel(steps) {
  const top = Math.max(1, ...steps.map((s) => s.value));
  if (!steps.some((s) => s.value > 0)) return empty();
  return h('div', { class: 'fn' }, steps.map((s) => h('div', { class: 'fn-row' }, h('span', { class: 'fn-l' }, s.label), h('span', { class: 'fn-t' }, setW(h('i', { class: s.cls || 'c1' }), (s.value / top) * 100)), h('b', { class: 'num' }, fmt(s.value)))));
}

const hh = (ms) => new Date(ms).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' });
const dd = (ms) => new Date(ms).toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' });

/**
 * Histogramme empilé par heure. points: [{t, …}] ; series: [{key, label, cls}] (empilées dans l'ordre).
 * Heures sans donnée = colonne vide (l'axe reste continu).
 */
export function columns(points, series, { height = 150, step = 3600e3 } = {}) {
  if (!points.length) return empty();
  const W = 560; const H = height; const pad = { l: 34, r: 6, t: 8, b: 20 };
  const t0 = points[0].t; const t1 = points[points.length - 1].t;
  const n = Math.max(1, Math.round((t1 - t0) / step) + 1);
  const byT = new Map(points.map((p) => [Math.round((p.t - t0) / step), p]));
  const maxV = Math.max(1, ...points.map((p) => series.reduce((a, s) => a + (p[s.key] || 0), 0)));
  const bw = (W - pad.l - pad.r) / n;
  const y = (v) => H - pad.b - (v / maxV) * (H - pad.t - pad.b);
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': series.map((s) => s.label).join(', '), class: 'cols-svg' });
  for (const f of (maxV < 4 ? [0, 1] : [0, 0.5, 1])) {
    root.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y(maxV * f), y2: y(maxV * f), class: 'gl' }), svg('text', { x: pad.l - 4, y: y(maxV * f) + 3.5, 'text-anchor': 'end', class: 'ax' }, compact(maxV * f)));
  }
  for (let i = 0; i < n; i++) {
    const p = byT.get(i); if (!p) continue;
    let acc = 0;
    const g = svg('g', null, svg('title', null, `${dd(p.t)}${step < 86400e3 ? ` ${hh(p.t)}` : ''} — ${series.map((s) => `${s.label} ${fmt(p[s.key] || 0)}`).join(' · ')}`));
    for (const s of series) {
      const v = p[s.key] || 0; if (!v) continue;
      g.append(svg('rect', { x: (pad.l + i * bw + bw * 0.12).toFixed(1), width: Math.max(1, bw * 0.76).toFixed(1), y: y(acc + v).toFixed(1), height: Math.max(0.5, y(acc) - y(acc + v)).toFixed(1), class: `col ${s.cls}` }));
      acc += v;
    }
    root.append(g);
  }
  root.append(svg('text', { x: pad.l, y: H - 5, class: 'ax' }, `${dd(t0)}${step < 86400e3 ? ` ${hh(t0)}` : ''}`), svg('text', { x: W - pad.r, y: H - 5, 'text-anchor': 'end', class: 'ax' }, `${dd(t1)}${step < 86400e3 ? ` ${hh(t1)}` : ''}`));
  return h('div', { class: 'cols' }, root, h('ul', { class: 'lg inline' }, series.map((s) => h('li', null, h('i', { class: s.cls }), h('span', { class: 'lg-l' }, s.label)))));
}

/** Barre empilée unique (ex. humains / bots). parts: [{label, value, cls}] */
export function stack(parts) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  if (!total) return empty();
  return h('div', { class: 'stk' }, h('div', { class: 'stk-bar', role: 'img', 'aria-label': parts.map((p) => `${p.label} ${fmt(p.value)}`).join(', ') }, parts.filter((p) => p.value > 0).map((p) => setW(h('i', { class: p.cls, title: `${p.label} : ${fmt(p.value)}` }), (p.value / total) * 100))),
    h('ul', { class: 'lg inline' }, parts.map((p) => h('li', null, h('i', { class: p.cls }), h('span', { class: 'lg-l' }, p.label), h('b', { class: 'num' }, fmt(p.value))))));
}

/** Jauge de durée de vie : part restante (daysLeft/totalDays), ton selon les jours restants. */
export function lifebar(daysLeft, totalDays, tone) {
  const p = daysLeft !== null && totalDays ? (daysLeft / totalDays) * 100 : 0;
  return h('span', { class: 'hb-t life' }, setW(h('i', { class: tone || 'ok' }), p));
}

/** Jauge de progression simple (0–100 %). */
export function meter(pct, cls = 'c1') {
  return h('span', { class: 'hb-t meter', role: 'img', 'aria-label': `${Math.round(pct)} %` }, setW(h('i', { class: cls }), pct));
}
