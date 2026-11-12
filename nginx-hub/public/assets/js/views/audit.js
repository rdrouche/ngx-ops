import { h, mount } from '../dom.js';
import { get } from '../api.js';
import { dateTime } from '../util.js';

export function auditView(root) {
  const host = h('div', { class: 'panel' }, h('div', { class: 'empty' }, 'Chargement…'));
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, 'Journal d’audit'), h('p', null, 'Connexions, modifications d’instances, rotations de jetons (365 jours).'))), host);
  get('/audit?limit=200').then(({ items }) => {
    mount(host, items.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Date', 'Utilisateur', 'Action', 'Cible', 'IP'].map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', null, items.map((a) => h('tr', null, h('td', { class: 'num' }, dateTime(a.ts)), h('td', null, a.actor || '—'), h('td', null, h('span', { class: 'chip mono' }, a.action)), h('td', null, a.target || ''), h('td', { class: 'mono' }, a.ip || '')))))) : h('div', { class: 'empty' }, 'Journal vide.'));
  }).catch((e) => mount(host, h('div', { class: 'empty' }, e.message)));
}
