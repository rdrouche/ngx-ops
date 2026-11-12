// Graphiques SVG sans dépendance (construits par DOM, aucune donnée injectée en HTML).
import { h, svg } from './dom.js';
import { compact } from './util.js';
import { locale } from './i18n.js';

const W = 560; const H = 150; const PAD = { l: 40, r: 8, t: 8, b: 20 };

function timeLabel(t, spanMs) {
  const d = new Date(t);
  return spanMs > 36 * 3600e3 ? d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' }) : d.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' });
}

/**
 * @param {Array} points  [{t, ...}]
 * @param {Array} series  [{key, cls:'l1'|'l2'|'l3', area?:boolean}]
 * @param {object} opt    {fixedMax?, format?}
 */
export function lineChart(points, series, opt = {}) {
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img' });
  const valid = points.filter((p) => series.some((s) => p[s.key] !== null && p[s.key] !== undefined));
  if (valid.length < 2) {
    root.append(svg('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'none' }, 'Données insuffisantes'));
    return root;
  }
  const t0 = valid[0].t; const t1 = valid[valid.length - 1].t;
  const maxV = opt.fixedMax ?? Math.max(1, ...valid.flatMap((p) => series.map((s) => p[s.key] || 0)));
  const x = (t) => PAD.l + ((t - t0) / Math.max(1, t1 - t0)) * (W - PAD.l - PAD.r);
  const y = (v) => H - PAD.b - (v / maxV) * (H - PAD.t - PAD.b);
  const fmtY = opt.format || compact;

  for (const f of [0, 0.5, 1]) {
    const yy = y(maxV * f);
    root.append(svg('line', { x1: PAD.l, x2: W - PAD.r, y1: yy, y2: yy, class: 'gl' }));
    root.append(svg('text', { x: PAD.l - 5, y: yy + 3.5, 'text-anchor': 'end', class: 'ax' }, fmtY(maxV * f)));
  }
  root.append(svg('text', { x: PAD.l, y: H - 5, class: 'ax' }, timeLabel(t0, t1 - t0)));
  root.append(svg('text', { x: W - PAD.r, y: H - 5, 'text-anchor': 'end', class: 'ax' }, timeLabel(t1, t1 - t0)));

  for (const s of series) {
    const pts = valid.filter((p) => p[s.key] !== null && p[s.key] !== undefined);
    if (pts.length < 2) continue;
    const line = pts.map((p) => `${x(p.t).toFixed(1)},${y(p[s.key]).toFixed(1)}`).join(' ');
    if (s.area) root.append(svg('polygon', { points: `${x(pts[0].t).toFixed(1)},${y(0)} ${line} ${x(pts[pts.length - 1].t).toFixed(1)},${y(0)}`, class: 'a1' }));
    root.append(svg('polyline', { points: line, class: s.cls }));
  }
  return root;
}

export function chartBox(title, chart, legend) {
  return h('div', { class: 'chart' },
    h('h3', null, h('span', null, title), legend ? h('span', { class: 'legend' }, legend.map(([cls, label]) => h('span', null, h('i', { class: cls }), label))) : null),
    chart);
}
