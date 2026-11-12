// Corrélation par IP entre instances (contrat 12.78.0 §2.9). DONNÉES PERSONNELLES : admin seulement, jamais journalisées.
import { h, mount, icon } from '../dom.js';
import { get } from '../api.js';
import { ago, toast } from '../util.js';
import { t } from '../i18n.js';

const DIAG = {
  ok: ['ok', 'Collecté'], ips_disabled: ['warn', 'expose_ips désactivé côté dashboard'], absent: ['', 'Module non exposé (indicators absent de expose_modules)'],
  error: ['err', 'Erreur de collecte'], pending: ['', 'Pas encore collecté'],
};
/** Diagnostic par instance : pourquoi une instance ne fournit pas d'indicateurs. Affiché seulement s'il y a un problème. */
function diag(sources) {
  const bad = sources.filter((s) => s.status !== 'ok');
  if (!bad.length) return null;
  return h('div', { class: 'banner' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, t('{n} instance(s) ne fournissent pas d’indicateurs', { n: bad.length })),
    h('ul', { class: 'plain' }, bad.map((s) => { const [cls, label] = DIAG[s.status] || ['', s.status]; return h('li', null, h('b', null, s.name), ' — ', h('span', { class: cls === 'err' ? 'err-txt' : '' }, label)); }))));
}

// #93 : lien vers la fiche de l'IP sur NGX Ops Intelligence (nouvel onglet). Seulement pour une vraie IP :
// un réseau /24 ou un pseudonyme n'a pas de fiche. L'adresse n'est transmise qu'au clic de l'administrateur.
const INTEL_IP_URL = 'https://intelligence.ngx-ops.net/ip/';
const IP_OK = /^[0-9a-fA-F:.]{2,45}$/;
let explorerOn = false; // #107 : lien vers l'explorateur (filtré sur l'IP) quand il est activé
function ipLink(x) {
  if (x.scope && x.scope !== 'ip') return x.ip;
  if (!IP_OK.test(x.ip)) return x.ip;
  const explore = explorerOn ? [' ', h('a', { href: '#/explorer?ip=' + encodeURIComponent(x.ip), title: t('Ouvrir dans l’explorateur de logs') }, '↗')] : [];
  return h('span', null, h('a', { href: INTEL_IP_URL + encodeURIComponent(x.ip), target: '_blank', rel: 'noopener noreferrer', title: t('Voir cette IP sur NGX Ops Intelligence (nouvel onglet)') }, x.ip), explore);
}

function seen(x) {
  const ts = [...x.instances.map((i) => i.seen_at), x.logstore && x.logstore.last_seen ? Date.parse(x.logstore.last_seen) : 0].filter((n) => Number.isFinite(n) && n > 0);
  return ts.length ? ago(Math.max(...ts)) : '—';
}

export function indicatorsView(root, withLogstore = false, withExplorer = false) {
  explorerOn = withExplorer === true;
  const body = h('div', { class: 'stack' });
  let only = false; let inRule = false;
  async function load() {
    try {
      // #62 : fusion dashboards + log store quand logstore.indicators est activé côté Hub
      const d = await get(withLogstore ? '/logstore/correlation' : '/indicators');
      const items = d.items.filter((x) => (!only || x.campaign) && (!inRule || (x.campaign_rules || []).length));
      mount(body,
        h('div', { class: 'banner' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, t('Données personnelles : adresses IP de visiteurs')), h('span', null, t('Accès réservé aux administrateurs, non écrites dans les journaux. Campagne probable = IP vue par au moins 2 instances ou par au moins 3 types de sources.')))),
        h('div', { class: 'toolbar' }, h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: only, onChange: (e) => { only = e.target.checked; load(); } }), t('Campagnes probables seulement')),
          h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: inRule, onChange: (e) => { inRule = e.target.checked; load(); } }), t('Impliquées dans une campagne d’analyse')),
          h('span', { class: 'muted grow' }, t('{n} adresse(s) · fenêtre {h} h', { n: items.length, h: d.window_hours }))),
        d.partial ? h('div', { class: 'banner' }, icon('warn', 20), h('div', { class: 't' }, t('Données partielles : une source n’a pas répondu.'))) : null,
        diag(d.sources || []),
        h('section', { class: 'panel' }, items.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
          h('thead', null, h('tr', null, [t('Adresse IP'), t('Campagne'), t('Score'), t('Types de sources'), t('Règles de campagne'), t('Instances'), ...(withLogstore ? [t('Événements'), t('Bloqués')] : []), t('Vue')].map((x) => h('th', { scope: 'col' }, x)))),
          h('tbody', null, items.map((x) => h('tr', null,
            h('td', { class: 'mono' }, ipLink(x), x.scope === 'cidr' ? h('span', { class: 'chip', title: t('Réseau /24 (IP tronquée par le log store)') }, '/24') : x.scope === 'pseudonym' ? h('span', { class: 'chip', title: t('Pseudonyme (IP non stockée par le log store)') }, t('pseudo')) : null), h('td', null, x.campaign ? h('span', { class: 'badge err' }, t('Probable')) : h('span', { class: 'badge' }, '—')),
            h('td', { class: 'num' }, x.score), h('td', null, h('div', { class: 'chips' }, x.kinds.map((k) => h('span', { class: 'chip mono' }, k)))),
            h('td', null, h('div', { class: 'chips' }, (x.campaign_rules || []).map((r) => h('span', { class: 'chip mono', title: t('Règle de campagne d’analyse') }, r)))),
            h('td', null, h('div', { class: 'chips' }, [...x.instances.map((i) => h('a', { class: 'chip', href: `#/i/${i.id}/security` }, i.name)), ...(x.logstore ? x.logstore.instances.map((n) => h('span', { class: 'chip mono' }, n)) : [])])),
            ...(withLogstore ? [h('td', { class: 'num' }, x.logstore ? x.logstore.events : '—'), h('td', { class: 'num' }, x.logstore ? x.logstore.blocked : '—')] : []),
            h('td', { class: 'muted nowrap' }, seen(x))))))) : h('div', { class: 'empty' }, t('Aucun indicateur.'))));
    } catch (e) {
      if (e.status === 404) mount(body, h('div', { class: 'panel' }, h('div', { class: 'empty' }, t('Corrélation par IP désactivée. Pour l’activer : modules.indicators.enabled: true côté Hub et expose_ips: true côté dashboard.'))));
      else if (e.code !== 'unauthenticated') toast(e.message);
    }
  }
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, t('Indicateurs (corrélation IP)')), h('p', null, t('IP vues par plusieurs sources ou plusieurs instances.')))), body);
  load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 120_000);
  return () => clearInterval(timer);
}
