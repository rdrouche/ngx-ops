// Internationalisation FR/EN. Le texte français sert de clé : t('Vue d’ensemble'). Une clé sans traduction s'affiche en français
// (jamais de clé technique à l'écran) ; un test vérifie que chaque t('…') du code possède son entrée anglaise.
import { EN } from './i18n-en.js';

const SUPPORTED = ['fr', 'en'];
const KEY = 'hub_lang';
let lang = 'fr';

export function detectLang(defaultLang) {
  try { const s = localStorage.getItem(KEY); if (SUPPORTED.includes(s)) return s; } catch { /* stockage indisponible */ }
  if (SUPPORTED.includes(defaultLang)) return defaultLang;
  return (navigator.language || 'fr').toLowerCase().startsWith('en') ? 'en' : 'fr';
}

export function initLang(defaultLang) { lang = detectLang(defaultLang); document.documentElement.lang = lang; }
export const getLang = () => lang;
export const locale = () => (lang === 'en' ? 'en-GB' : 'fr-FR');

export function setLang(next) {
  if (!SUPPORTED.includes(next) || next === lang) return;
  lang = next;
  try { localStorage.setItem(KEY, next); } catch { /* ignoré */ }
  document.documentElement.lang = next;
  window.dispatchEvent(new CustomEvent('hub:lang'));
}

function fill(s, p) { return p ? s.replace(/\{(\w+)\}/g, (m, k) => (k in p ? String(p[k]) : m)) : s; }

/** t('Texte français {x}', { x }) */
export function t(fr, p) { return fill(lang === 'en' && EN[fr] !== undefined ? EN[fr] : fr, p); }

/** Pluriel : tp('{n} instance', '{n} instances', n) */
export function tp(one, other, n, p) { return t(n > 1 ? other : one, { n, ...p }); }

/** Traduction d'un texte STATIQUE (sans paramètre) ; utilisée automatiquement par h()/svg() pour les enfants texte et les attributs title/aria-label/placeholder. */
export function tr(s) { return lang === 'en' && typeof s === 'string' && EN[s] !== undefined ? EN[s] : s; }
