import { t, initLang, getLang, setLang } from './i18n.js';
// Point d'entrée UI : session, thème, routage par hash (#/, #/i/<id>, #/backups, #/security, #/audit).
import { h, mount, icon, clear } from './dom.js';
import { get, post, setCsrf } from './api.js';
import { loginView } from './views/login.js';
import { overviewView } from './views/overview.js';
import { instanceView } from './views/instance.js';
import { securityView, enrollmentGate, passwordGate } from './views/security.js';
import { auditView } from './views/audit.js';
import { maintenanceView } from './views/maintenance.js';
import { backupsView } from './views/backups.js';
import { vhostsView } from './views/vhosts.js';
import { alertsView } from './views/alerts.js';
import { indicatorsView } from './views/indicators.js';
import { logstoreView } from './views/logstore.js';
import { explorerView } from './views/explorer.js';
import { openPalette } from './palette.js';

const root = document.getElementById('app');
let session = null; let dispose = null; let menuOpen = false; let logstoreOn = false; let indicatorsLs = false; let explorerLs = false; // #62 : onglet Journaux seulement si le log store est configuré

// ── Thème ──
function currentTheme() {
  try { const t = localStorage.getItem('hub_theme'); if (t === 'light' || t === 'dark') return t; } catch { /* ignoré */ }
  return session?.ui?.default_theme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}
function applyTheme(t) { document.documentElement.setAttribute('data-theme', t); }
function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('hub_theme', next); } catch { /* ignoré */ }
  applyTheme(next); renderShell();
}
applyTheme(currentTheme());
initLang();

// ── Langue ──
function langSelect() {
  return h('select', { class: 'lang', 'aria-label': 'Langue', title: 'Langue', onChange: (e) => setLang(e.target.value) },
    [['fr', 'FR'], ['en', 'EN']].map(([v, l]) => h('option', { value: v, selected: getLang() === v }, l)));
}
function floatLang() { document.querySelector('.lang-float')?.remove(); document.body.append(h('div', { class: 'lang-float' }, langSelect())); }
window.addEventListener('hub:lang', () => { if (session && session.state === 'active') renderShell(); else start(); });

// ── Session ──
async function logout() {
  try { await post('/auth/logout'); } catch { /* session déjà expirée */ }
  session = null; setCsrf(''); start();
}
function setSession(s) { session = s; setCsrf(s.csrf); start(); }

window.addEventListener('hub:unauthenticated', () => { if (session) { session = null; setCsrf(''); start(); } });

async function start() {
  if (dispose) { dispose(); dispose = null; }
  menuOpen = false;
  if (!session) {
    try { session = await get('/auth/me'); setCsrf(session.csrf); } catch (e) {
      if (e.code === 'mfa_required') { loginView(root, { step: 'mfa', onDone: setSession }); floatLang(); return; }
      loginView(root, { step: 'password', onDone: (r) => { session = null; setSession(r); } }); floatLang(); return;
    }
  }
  applyTheme(currentTheme());
  if (session.ui && session.ui.default_language) { const before = getLang(); initLang(session.ui.default_language); if (before !== getLang()) { start(); return; } }
  document.querySelector('.lang-float')?.remove();
  if (session.state === 'pwchange') { passwordGate(root, { onSessionChange: setSession, onLogout: logout }); floatLang(); return; }
  if (session.state === 'mfa') { session = null; loginView(root, { step: 'mfa', onDone: setSession }); return; }
  if (session.state === 'enroll') { enrollmentGate(root, { session, onSessionChange: setSession, onLogout: logout }); floatLang(); return; }
  try { const st = await get('/logstore/status'); logstoreOn = st.enabled === true; indicatorsLs = st.indicators === true; explorerLs = st.explorer === true && session.perms.includes('indicators:view'); } catch { logstoreOn = false; indicatorsLs = false; explorerLs = false; }
  renderShell();
}

// ── Coque + routage ──
const PAGES = () => [
  { href: '#/', label: 'Vue d’ensemble', hint: 'État global des instances' },
  { href: '#/vhosts', label: 'Virtual hosts', hint: 'Tous les vhosts, sur quelle(s) instance(s)' },
  { href: '#/alerts', label: 'Alertes', hint: 'Alertes détaillées de toutes les instances' },
  ...(logstoreOn ? [{ href: '#/logs', label: 'Journaux', hint: 'Visites, sécurité et blocages (log store)' }] : []),
  ...(explorerLs ? [{ href: '#/explorer', label: 'Explorateur', hint: 'Recherche dans les logs bruts et fiche IP (log store)' }] : []),
  ...(session.perms.includes('indicators:view') ? [{ href: '#/indicators', label: 'Indicateurs', hint: 'Corrélation par IP entre instances' }] : []),
  ...(session.perms.includes('backups:view') ? [{ href: '#/backups', label: 'Sauvegardes', hint: 'Archives de configuration des dashboards' }] : []),
  { href: '#/security', label: 'Sécurité du compte', hint: 'MFA et mot de passe' },
  ...(session.perms.includes('audit:view') ? [{ href: '#/audit', label: 'Journal d’audit', hint: 'Actions des utilisateurs' }] : []),
  ...(session.perms.includes('maintenance:manage') ? [{ href: '#/maintenance', label: 'Maintenance de la base', hint: 'Entretien du stockage du Hub' }] : []),
];

function route() {
  const hash = (window.location.hash || '#/').split('?')[0]; // le fragment peut porter des filtres (#/explorer?ip=…)
  const m = hash.match(/^#\/i\/(\d+)(?:\/([a-z]+))?$/);
  return m ? { name: 'instance', id: Number(m[1]), tab: m[2] || 'overview' } : hash === '#/vhosts' ? { name: 'vhosts' } : hash === '#/alerts' ? { name: 'alerts' } : hash === '#/indicators' ? { name: 'indicators' } : hash === '#/logs' ? { name: 'logs' } : hash === '#/explorer' ? { name: 'explorer' } : hash === '#/security' ? { name: 'security' } : hash === '#/audit' ? { name: 'audit' } : hash === '#/backups' ? { name: 'backups' } : hash === '#/maintenance' ? { name: 'maintenance' } : { name: 'overview' };
}

function renderShell() {
  if (!session || session.state !== 'active') return;
  const r = route();
  const dark = currentTheme() === 'dark';
  const initials = session.user.username.slice(0, 2).toUpperCase();
  const main = h('main', { id: 'main' });
  const current = (name) => (r.name === name || (name === 'overview' && r.name === 'instance') ? 'page' : null);

  const menu = h('div', { class: 'menu', role: 'menu' },
    h('div', { class: 'who' }, `${session.user.username} · ${session.user.role === 'admin' ? t('administrateur') : t('lecture seule')}`),
    h('a', { href: '#/security', role: 'menuitem' }, 'Sécurité du compte'),
    session.perms.includes('maintenance:manage') ? h('a', { href: '#/maintenance', role: 'menuitem' }, 'Maintenance de la base') : null,
    h('button', { type: 'button', role: 'menuitem', onClick: logout }, 'Se déconnecter'));

  mount(root,
    h('header', { class: 'hdr' }, h('div', { class: 'hdr-in' },
      h('a', { class: 'brand', href: '#/' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, icon('layers', 16)), h('span', { class: 'brand-name' }, 'NGX Ops Hub')),
      h('nav', { class: 'nav', 'aria-label': 'Navigation principale' },
        h('a', { href: '#/', 'aria-current': current('overview') }, 'Vue d’ensemble'),
        h('a', { href: '#/vhosts', 'aria-current': current('vhosts') }, 'Virtual hosts'),
        h('a', { href: '#/alerts', 'aria-current': current('alerts') }, 'Alertes'),
        logstoreOn ? h('a', { href: '#/logs', 'aria-current': current('logs') }, 'Journaux') : null,
        explorerLs ? h('a', { href: '#/explorer', 'aria-current': current('explorer') }, 'Explorateur') : null,
        session.perms.includes('indicators:view') ? h('a', { href: '#/indicators', 'aria-current': current('indicators') }, 'Indicateurs') : null,
        session.perms.includes('backups:view') ? h('a', { href: '#/backups', 'aria-current': current('backups') }, 'Sauvegardes') : null,
        session.perms.includes('audit:view') ? h('a', { href: '#/audit', 'aria-current': current('audit') }, 'Audit') : null),
      h('div', { class: 'tools' },
        h('button', { class: 'searchbtn', type: 'button', 'aria-label': 'Recherche globale (Ctrl K)', onClick: () => openPalette({ pages: PAGES() }) }, icon('search', 15), h('span', null, 'Rechercher'), h('kbd', null, 'Ctrl K')),
        langSelect(),
        h('button', { class: 'ibtn', type: 'button', 'aria-label': dark ? 'Passer au thème clair' : 'Passer au thème sombre', onClick: toggleTheme }, icon(dark ? 'sun' : 'moon')),
        h('button', { class: 'avatar', type: 'button', 'aria-label': t('Compte : {u}', { u: session.user.username }), 'aria-haspopup': 'menu', 'aria-expanded': String(menuOpen), onClick: () => { menuOpen = !menuOpen; renderShell(); } }, initials),
        menuOpen ? menu : null))),
    main);

  if (dispose) { dispose(); dispose = null; }
  const ctx = { session, onSessionChange: setSession, onLogout: logout };
  if (r.name === 'instance') dispose = instanceView(main, { ...ctx, id: r.id, tab: r.tab });
  else if (r.name === 'vhosts') dispose = vhostsView(main);
  else if (r.name === 'alerts') dispose = alertsView(main, ctx);
  else if (r.name === 'logs' && logstoreOn) dispose = logstoreView(main);
  else if (r.name === 'explorer' && explorerLs) dispose = explorerView(main);
  else if (r.name === 'indicators' && session.perms.includes('indicators:view')) dispose = indicatorsView(main, indicatorsLs, explorerLs);
  else if (r.name === 'security') securityView(main, ctx);
  else if (r.name === 'backups' && session.perms.includes('backups:view')) dispose = backupsView(main);
  else if (r.name === 'maintenance' && session.perms.includes('maintenance:manage')) dispose = maintenanceView(main);
  else if (r.name === 'audit' && session.perms.includes('audit:view')) auditView(main);
  else dispose = overviewView(main, ctx);
}

window.addEventListener('hashchange', () => { menuOpen = false; renderShell(); });
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && session?.state === 'active') { e.preventDefault(); openPalette({ pages: PAGES() }); }
});
document.addEventListener('click', (e) => { if (menuOpen && !e.target.closest('.tools')) { menuOpen = false; renderShell(); } });

clear(root);
start();
