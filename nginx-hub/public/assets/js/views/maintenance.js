import { t } from '../i18n.js';
// Maintenance de la base du Hub (#96) : état + lancement manuel (admin). PostgreSQL : VACUUM ANALYZE ;
// SQLite : checkpoint WAL, optimize, VACUUM, contrôle d'intégrité. Aucun HTML construit depuis des données (h() uniquement).
import { h, mount, icon } from '../dom.js';
import { get, post } from '../api.js';
import { ago, dateTime, bytes, fmt, toast } from '../util.js';

/** @returns {() => void} fonction de nettoyage (arrêt du rafraîchissement) */
export function maintenanceView(root) {
  const host = h('div', { class: 'panel' }, h('div', { class: 'empty' }, 'Chargement…'));
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, 'Maintenance de la base'),
    h('p', null, 'Entretien planifié du stockage du Hub (statistiques, espace récupérable, intégrité).'))), host);
  let timer = null; let stopped = false; let data = null;

  async function start() {
    try { await post('/system/maintenance'); toast(t('Maintenance lancée')); } catch (e) { toast(e.message); }
    await load();
  }

  function lastLine(l) {
    if (!l) return h('b', null, t('jamais depuis le démarrage'));
    const res = l.error ? h('span', { class: 'badge err' }, 'Échec') : h('span', { class: 'badge ok' }, 'Réussie');
    const parts = [`${dateTime(l.started_at)} (${ago(l.started_at)})`, `${fmt(l.duration_ms)} ms`, l.trigger === 'manual' ? t('manuelle') : t('planifiée')];
    if (l.vacuumed !== undefined) parts.push(l.vacuumed ? t('compactage : {b} libérés', { b: bytes(l.freed_bytes) }) : t('pas de compactage nécessaire'));
    if (l.integrity) parts.push(l.integrity === 'ok' ? t('intégrité OK') : t('intégrité en échec'));
    return h('span', null, res, ' ', parts.join(' · '));
  }

  function render() {
    if (!data.supported) { mount(host, h('div', { class: 'empty' }, 'Maintenance non disponible pour ce stockage.')); return; }
    const sqlite = data.engine === 'sqlite';
    mount(host,
      h('div', { class: 'panel-h' }, h('h2', null, sqlite ? 'SQLite' : 'PostgreSQL', ' ', data.running ? h('span', { class: 'badge warn' }, 'En cours') : null),
        h('div', { class: 'actions' }, h('button', { class: 'btn sm primary', type: 'button', disabled: data.running, onClick: start }, icon('refresh', 14), 'Lancer maintenant'))),
      h('div', { class: 'panel-b' },
        h('div', { class: 'kv' },
          h('span', null, 'Planification : ', h('b', null, data.enabled ? t('toutes les {h} h', { h: data.every_hours }) : t('désactivée'))),
          h('span', null, 'Dernier passage : ', lastLine(data.last)),
          sqlite ? h('span', null, 'Base : ', h('b', null, bytes(data.size_bytes)), ' · ', t('espace récupérable : {b}', { b: bytes(data.free_bytes) })) : null),
        !sqlite && data.tables.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
          h('thead', null, h('tr', null, ['Table', 'Taille', 'Lignes', 'Lignes mortes', 'Dernier vacuum', 'Dernière analyse'].map((x) => h('th', { scope: 'col' }, x)))),
          h('tbody', null, data.tables.map((r) => h('tr', null, h('td', { class: 'mono' }, r.name), h('td', { class: 'num' }, bytes(r.size_bytes)), h('td', { class: 'num' }, fmt(r.live_rows)),
            h('td', { class: 'num' }, fmt(r.dead_rows)), h('td', { class: 'num' }, r.last_vacuum ? dateTime(r.last_vacuum) : '—'), h('td', { class: 'num' }, r.last_analyze ? dateTime(r.last_analyze) : '—')))))) : null));
  }

  async function load() {
    clearTimeout(timer);
    try { data = await get('/system/maintenance'); render(); } catch (e) { mount(host, h('div', { class: 'empty' }, e.message)); return; }
    if (!stopped && data.running) timer = setTimeout(load, 3000); // suivi d'un passage en cours
  }
  load();
  return () => { stopped = true; clearTimeout(timer); };
}
