// Page « Virtual hosts » : tous les vhosts de toutes les instances, avec recherche. Un même vhost peut exister sur plusieurs instances.
import { h, mount } from '../dom.js';
import { get } from '../api.js';
import { fmt, bytes, toast } from '../util.js';
import { t } from '../i18n.js';
import { smartValue, humanKey } from '../smart.js';

export function vhostsView(root) {
  const st = { q: '', dup: false, sort: 'name', shown: 50 };
  let data = null;
  const list = h('div'); const head = h('div');

  const matches = (v, q) => v.name.includes(q) || v.instances.some((i) => [i.instance, i.upstream, i.file].some((x) => x && String(x).toLowerCase().includes(q)));

  function draw() {
    if (!data) return;
    const q = st.q.trim().toLowerCase();
    let items = data.items.filter((v) => (!q || matches(v, q)) && (!st.dup || v.instance_count > 1));
    const by = { name: (a, b) => a.name.localeCompare(b.name), instances: (a, b) => b.instance_count - a.instance_count || a.name.localeCompare(b.name), requests: (a, b) => b.requests - a.requests, bytes: (a, b) => b.bytes - a.bytes };
    items = [...items].sort(by[st.sort]);
    const dups = data.items.filter((v) => v.instance_count > 1).length;
    mount(list,
      h('div', { class: 'toolbar' },
        h('input', { class: 'field grow', type: 'search', placeholder: 'Rechercher un vhost, une instance, un backend…', 'aria-label': 'Rechercher', value: st.q, autofocus: true, onInput: (e) => { st.q = e.target.value; st.shown = 50; draw(); const i = list.querySelector('input'); if (i) { i.focus(); i.setSelectionRange(st.q.length, st.q.length); } } }),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: st.dup, onChange: (e) => { st.dup = e.target.checked; draw(); } }), t('Doublons seulement ({n})', { n: dups })),
        h('select', { class: 'select', 'aria-label': 'Trier', onChange: (e) => { st.sort = e.target.value; draw(); } },
          [['name', 'Tri : nom'], ['instances', 'Tri : nb d’instances'], ['requests', 'Tri : requêtes'], ['bytes', 'Tri : volume']].map(([v, l]) => h('option', { value: v, selected: st.sort === v }, l)))),
      h('p', { class: 'muted count-line' }, t('{n} vhost(s) sur {m}', { n: fmt(items.length), m: fmt(data.items.length) })),
      h('section', { class: 'panel' }, items.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
        h('thead', null, h('tr', null, [t('Virtual host'), t('Instances'), t('Requêtes (24 h)'), t('Volume'), t('Backend'), t('Certificat')].map((x, i) => h('th', { scope: 'col', class: i === 2 || i === 3 ? 'r' : '' }, x)))),
        h('tbody', null, items.slice(0, st.shown).map((v) => row(v))))) : h('div', { class: 'empty' }, data.items.length ? t('Aucun vhost ne correspond.') : t('Aucun vhost collecté. Le module « inventaire » doit être activé côté dashboard (expose_modules) et collecté par le Hub.'))),
      items.length > st.shown ? h('div', { class: 'actions' }, h('button', { class: 'btn sm', type: 'button', onClick: () => { st.shown += 100; draw(); } }, t('Afficher plus ({n} restants)', { n: fmt(items.length - st.shown) }))) : null);
  }

  const open = new Set();
  function row(v) {
    const days = v.instances.map((i) => i.cert_days).filter((d) => typeof d === 'number');
    const ups = [...new Set(v.instances.map((i) => i.upstream).filter(Boolean))];
    const kinds = [...new Set(v.instances.flatMap((i) => (i.backend_kind ? String(i.backend_kind).split(', ') : [])))];
    const tg = [...new Set(v.instances.flatMap((i) => (Array.isArray(i.targets) ? i.targets : [])))];
    const tr = h('tr', { class: 'click', tabindex: '0', 'aria-expanded': String(open.has(v.name)), onClick: () => { open.has(v.name) ? open.delete(v.name) : open.add(v.name); draw(); }, onKeydown: (e) => { if (e.key === 'Enter') { open.has(v.name) ? open.delete(v.name) : open.add(v.name); draw(); } } },
      h('td', null, h('b', null, v.name), v.instance_count > 1 ? h('span', { class: 'badge warn inl', title: t('Présent sur plusieurs instances') }, t('{n} instances', { n: v.instance_count })) : null),
      h('td', null, h('div', { class: 'chips' }, v.instances.slice(0, 4).map((i) => h('a', { class: 'chip', href: `#/i/${i.id}/inventory`, onClick: (e) => e.stopPropagation() }, i.instance)), v.instances.length > 4 ? h('span', { class: 'muted' }, `+${v.instances.length - 4}`) : null)),
      h('td', { class: 'r num' }, v.requests ? fmt(v.requests) : '—'), h('td', { class: 'r num' }, v.bytes ? bytes(v.bytes) : '—'),
      h('td', null, ups.length ? [h('span', { class: 'mono', title: ups.join(' ; ') }, ups[0] + (ups.length > 1 ? ` (+${ups.length - 1})` : '')), kinds.length ? h('span', { class: 'chip inl', title: tg.join(' ; ') }, kinds.join(', ')) : null] : h('span', { class: 'muted' }, '—')),
      h('td', null, days.length ? smartValue('days_left', Math.min(...days)).node : h('span', { class: 'muted' }, '—')));
    if (!open.has(v.name)) return tr;
    const cols = ['state', 'backend_kind', 'targets', 'file', 'listen', 'requests', 'errors', 'bytes'].filter((k) => v.instances.some((i) => i[k] !== undefined));
    return [tr, h('tr', { class: 'detail' }, h('td', { colspan: 6 }, h('div', { class: 'tbl-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, t('Instance')), cols.map((k) => h('th', { scope: 'col' }, humanKey(k))))),
      h('tbody', null, v.instances.map((i) => h('tr', null, h('td', null, h('a', { href: `#/i/${i.id}/inventory` }, i.instance)), cols.map((k) => h('td', null, smartValue(k, i[k]).node)))))))))];
  }

  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, t('Virtual hosts')), h('p', null, t('Tous les vhosts de toutes les instances — un vhost présent sur plusieurs instances est signalé.')))), head, list);
  (async () => {
    try {
      data = await get('/vhosts');
      if (data.instances_missing.length) mount(head, h('div', { class: 'banner' }, h('div', { class: 't' }, h('b', null, t('{n} instance(s) sans inventaire collecté', { n: data.instances_missing.length })), h('span', null, data.instances_missing.map((x) => x.name).join(', ')))));
      draw();
    } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
  })();
  const timer = setInterval(async () => { if (!document.hidden) { try { data = await get('/vhosts'); draw(); } catch { /* prochain cycle */ } } }, 60_000);
  return () => clearInterval(timer);
}
