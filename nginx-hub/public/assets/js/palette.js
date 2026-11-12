import { t, tr } from './i18n.js';
// Recherche globale (Ctrl/⌘ + K) : pages + instances. Navigation clavier ↑ ↓ Entrée Échap.
import { h, mount, icon } from './dom.js';
import { get } from './api.js';
import { hostOf, STATUS } from './util.js';

const norm = (x) => String(x).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

export async function openPalette({ pages }) {
  let instances = [];
  try { instances = (await get('/instances')).items; } catch { /* palette limitée aux pages */ }
  const entries = [
    ...pages.map((p) => ({ group: tr('Pages'), label: tr(p.label), hint: tr(p.hint), where: tr('Navigation'), href: p.href })),
    ...instances.map((i) => ({ group: tr('Instances'), label: i.name, hint: `${hostOf(i.url)}${i.tags?.length ? ' · ' + i.tags.join(', ') : ''}`, where: tr((STATUS[i.status] || STATUS.unknown).label), href: `#/i/${i.id}` })),
  ];
  let sel = 0; let shown = [];
  const input = h('input', { type: 'text', placeholder: 'Rechercher une page ou une instance…', 'aria-label': 'Rechercher', autocomplete: 'off', onInput: () => { sel = 0; render(); } });
  const list = h('div', { class: 'pal-list', role: 'listbox' });
  const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey, true); };
  const open = (e) => { if (e) { window.location.hash = e.href; close(); } };

  function render() {
    const q = norm(input.value.trim());
    shown = entries.filter((e) => !q || norm(`${e.label} ${e.hint} ${e.where}`).includes(q)).slice(0, 30);
    if (sel >= shown.length) sel = Math.max(0, shown.length - 1);
    const out = []; let last = '';
    shown.forEach((e, idx) => {
      if (e.group !== last) { out.push(h('div', { class: 'pal-g' }, e.group)); last = e.group; }
      out.push(h('div', { class: 'pal-it', role: 'option', 'aria-selected': String(idx === sel), onClick: () => open(e), onMousemove: () => { if (sel !== idx) { sel = idx; render(); } } },
        h('span', null, h('b', null, e.label), h('small', null, e.hint)), h('small', null, e.where)));
    });
    mount(list, ...(out.length ? out : [h('div', { class: 'empty' }, t('Aucun résultat pour « {q} ».', { q: input.value }))]));
    list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }

  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); render(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); render(); }
    else if (e.key === 'Enter') { e.preventDefault(); open(shown[sel]); }
  }

  const scrim = h('div', { class: 'scrim pal', onMousedown: (e) => { if (e.target === scrim) close(); } },
    h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Recherche globale' },
      h('div', { class: 'pal-in' }, icon('search', 18), input, h('button', { class: 'btn sm', type: 'button', onClick: close }, 'Échap')),
      list, h('div', { class: 'pal-foot' }, h('span', null, '↑ ↓ pour naviguer'), h('span', null, 'Entrée pour ouvrir'), h('span', null, 'Échap pour fermer'))));
  document.addEventListener('keydown', onKey, true);
  document.body.append(scrim);
  render(); input.focus();
}
