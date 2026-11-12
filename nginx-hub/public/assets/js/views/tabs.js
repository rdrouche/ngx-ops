// Barre d'onglets d'une instance + page d'un onglet (modules 12.78.0). Un module absent/désactivé n'est pas proposé.
import { h, mount } from '../dom.js';
import { get } from '../api.js';
import { toast } from '../util.js';
import { t } from '../i18n.js';
import { MODULES, moduleView } from './modules.js';
import { alertsList } from './alerts.js';

export const TAB_NAMES = () => ({ overview: t('Aperçu'), alerts: t('Alertes'), inventory: t('Inventaire'), traffic: t('Trafic'), security: t('Sécurité'), ops: t('Opérations'), monitoring: t('Supervision'), reports: t('Rapports'), indicators: t('Indicateurs') });

/** @param mods réponse de GET /instances/:id/modules (ou null) */
export function tabBar(id, active, mods, session) {
  const names = TAB_NAMES();
  const have = new Map(((mods && mods.items) || []).map((m) => [m.module, m]));
  const tabs = ['overview'];
  if (mods && mods.enabled) {
    tabs.push('alerts');
    for (const [k] of MODULES) if (have.has(k) && have.get(k).status !== 'absent') tabs.push(k);
    if (mods.indicators_enabled && session.perms.includes('indicators:view') && have.has('indicators') && have.get('indicators').status !== 'absent') tabs.push('indicators');
  }
  if (tabs.length === 1) return null;
  return h('nav', { class: 'tabs', 'aria-label': t('Sections de l’instance') }, tabs.map((k) => {
    const m = have.get(k);
    return h('a', { href: k === 'overview' ? `#/i/${id}` : `#/i/${id}/${k}`, 'aria-current': k === active ? 'page' : null }, names[k], m && m.status === 'error' ? h('span', { class: 'dot', title: t('Dernière collecte en échec') }) : null);
  }));
}

/** Page d'un onglet (hors aperçu). Retourne un disposer. */
export function tabPage(root, { id, tab, session, header }) {
  const content = h('div'); let off = null; let timer = null; let dead = false;
  mount(root, h('div', { class: 'stack' }, header, content));
  (async () => {
    let mods = null;
    try { mods = await get(`/instances/${id}/modules`); } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
    if (dead) return;
    const bar = tabBar(id, tab, mods, session);
    mount(root, h('div', { class: 'stack' }, header, bar, content));
    if (tab === 'alerts') {
      const l = alertsList({ instanceId: id, session }); mount(content, l.el); l.load();
      timer = setInterval(() => { if (!document.hidden) l.load(); }, 60_000);
    } else if (MODULES.some(([k]) => k === tab) || tab === 'indicators') off = moduleView(content, { id, name: tab, session });
    else mount(content, h('div', { class: 'panel' }, h('div', { class: 'empty' }, t('Section inconnue.'))));
  })();
  return () => { dead = true; clearInterval(timer); if (off) off(); };
}
