import { tr } from './i18n.js';
// Construction DOM sûre : tout texte passe par createTextNode/textContent (jamais de HTML injecté).
const SVG_NS = 'http://www.w3.org/2000/svg';
const TR_ATTRS = new Set(['title', 'aria-label', 'placeholder', 'alt']);
const SAFE_URL = /^(https?:\/\/|#\/|\/)/i;

function applyProps(el, props) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'href') { if (SAFE_URL.test(String(v))) el.setAttribute('href', v); }
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = !!v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, TR_ATTRS.has(k) ? tr(String(v)) : String(v));
  }
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(typeof c === 'string' ? tr(c) : String(c)));
  }
}

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  applyProps(el, props); append(el, children);
  return el;
}

export function svg(tag, props, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(props || {})) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
  append(el, children);
  return el;
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...children) { clear(el); append(el, children); return el; }

/** Icônes (chemins SVG statiques, aucune donnée serveur). */
const ICONS = {
  layers: ['M4 7l8-4 8 4-8 4-8-4z', 'M4 12l8 4 8-4', 'M4 17l8 4 8-4'],
  search: ['M20 20l-3.5-3.5'], moon: ['M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z'],
  sun: ['M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'],
  warn: ['M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z', 'M12 9v4M12 17h.01'],
  ext: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5'],
  refresh: ['M20 11a8 8 0 10-2.3 5.7', 'M20 4v7h-7'],
};
export function icon(name, size = 17) {
  const s = svg('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2.2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' });
  if (name === 'search') s.append(svg('circle', { cx: 11, cy: 11, r: 7 }));
  if (name === 'sun') s.append(svg('circle', { cx: 12, cy: 12, r: 4 }));
  for (const d of ICONS[name] || []) s.append(svg('path', { d }));
  return s;
}
