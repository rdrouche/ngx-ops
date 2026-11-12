import { h } from './dom.js';
import { t, tr, locale } from './i18n.js';

const nfs = {};
const nf = { format: (n) => (nfs[locale()] ||= new Intl.NumberFormat(locale())).format(n) };
const dec = (v) => v.toFixed(1).replace('.', locale() === 'fr-FR' ? ',' : '.');
export const fmt = (n) => (n === null || n === undefined ? '—' : nf.format(Math.round(n)));

export function compact(n) {
  if (n === null || n === undefined) return '—';
  if (n >= 1e9) return dec(n / 1e9) + ' G';
  if (n >= 1e6) return dec(n / 1e6) + ' M';
  if (n >= 1e4) return Math.round(n / 1e3) + ' k';
  return nf.format(Math.round(n));
}

export function ago(ts) {
  if (!ts) return t('jamais');
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 10) return t('à l’instant');
  if (s < 60) return t('il y a {n} s', { n: s });
  if (s < 3600) return t('il y a {n} min', { n: Math.round(s / 60) });
  if (s < 86400) return t('il y a {n} h', { n: Math.round(s / 3600) });
  return t('il y a {n} j', { n: Math.round(s / 86400) });
}

export function bytes(n) {
  if (n === null || n === undefined) return '—';
  const u = locale() === 'fr-FR' ? ['o', 'Ko', 'Mo', 'Go', 'To'] : ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : dec(v)} ${u[i]}`;
}

export function dateTime(ts) { return ts ? new Date(ts).toLocaleString(locale()) : '—'; }

export function uptime(s) {
  if (!s) return '—';
  const d = Math.floor(s / 86400); const hh = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60);
  return d ? t('{d} j {h} h', { d, h: hh }) : hh ? t('{h} h {m} min', { h: hh, m }) : t('{m} min', { m });
}

export const STATUS = {
  online: { label: 'En ligne', cls: 'ok' }, degraded: { label: 'Dégradé', cls: 'warn' }, offline: { label: 'Hors ligne', cls: 'err' },
  unknown: { label: 'Inconnu', cls: '' }, disabled: { label: 'Désactivé', cls: '' },
};
export const COMPONENT = {
  ok: { label: 'OK', cls: 'ok' }, degraded: { label: 'Dégradé', cls: 'warn' }, down: { label: 'Arrêté', cls: 'err' },
  disabled: { label: 'Désactivé', cls: '' }, unknown: { label: 'Inconnu', cls: '' },
};
export const COMPONENT_NAMES = { analyzer: 'Analyzer', challenge: 'Challenge HTTP', waf: 'WAF', crowdsec: 'CrowdSec', monitoring: 'Monitoring', intelligence: 'NGX Ops Intelligence' };

export function badge(map, key) { const s = map[key] || map.unknown; return h('span', { class: 'badge ' + s.cls }, s.label); }

const ERRORS = {
  auth_failed: 'Jeton refusé par le dashboard (rotation à reporter côté dashboard ?)',
  timeout: 'Délai dépassé', dns: 'Nom d’hôte introuvable', tls: 'Certificat TLS invalide ou non reconnu', connection: 'Connexion impossible',
  redirect_refused: 'Redirection refusée (non suivie par sécurité)', rate_limited: 'Limite de débit du dashboard atteinte (429)', not_supported: 'Le dashboard n’expose pas /api/hub/v1/summary (version trop ancienne ?)',
  bad_json: 'Réponse JSON invalide', bad_schema: 'Schéma de résumé inconnu', bad_content_type: 'Type de contenu inattendu', too_large: 'Réponse trop volumineuse',
  bad_archive: 'Archive de format inattendu (ni tar.gz ni NGXB1)', checksum_mismatch: 'SHA-256 de l’archive incohérent (transfert altéré ?)', bad_manifest: 'Manifeste de sauvegarde invalide',
  no_token: 'Aucun jeton de pull configuré',
  blocked_url: 'URL refusée par la politique réseau du Hub', blocked_address: 'Adresse réservée refusée (0.0.0.0, 169.254.x, multicast : jamais autorisées) — le nom DNS pointe-t-il au bon endroit ?',
  private_address: 'Adresse privée refusée : activez security.allow_private_networks ou ajoutez la plage dans security.allowed_cidrs (hub.yml)',
};
export function errorText(code) { return code ? (ERRORS[code] ? tr(ERRORS[code]) : null) || (/^http_\d+$/.test(code) ? t('Réponse HTTP {c}', { c: code.slice(5) }) : code) : ''; }

const SEV = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible', warning: 'Avertissement', info: 'Info' };
export const sevLabel = (s) => (SEV[s] ? t(SEV[s]) : s || '—');

export function hostOf(url) { try { return new URL(url).host; } catch { return url; } }

export function toast(msg) {
  const el = h('div', { class: 'toast', role: 'status' }, msg);
  document.body.append(el);
  setTimeout(() => el.remove(), 2600);
}

export async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copié'); } catch { toast('Copie impossible — sélectionnez le texte'); }
}

export function ratioBar(humans, robots) {
  const total = (humans || 0) + (robots || 0);
  const i = h('i');
  i.style.width = total ? `${Math.round(((humans || 0) / total) * 100)}%` : '0%';
  return h('div', { class: 'bar', role: 'img', 'aria-label': 'Part de trafic humain' }, i);
}
