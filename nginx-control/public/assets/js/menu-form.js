'use strict';
// v12.72.0 — Formulaire "Menu" (page Systeme) : choix des elements affiches dans le menu.
// Ecrit config/menu.yml via POST /api/menu-config/save (admin). L'edition manuelle du YAML reste valable.
// Ajouter un element : entree dans TOGGLES (lib/menu-visibility.js) + cle i18n menuform.item.<id>.

const MENU_FORM_ORDER = ['waf', 'wafemu', 'blocklists', 'godns', 'api', 'webhooks', 'docker_autoconfig', 'agents',
  'sync', 'vhostgen', 'graph', 'deploy', 'geomap', 'digest', 'cache', 'notifications', 'goaccess'];
let menuFormItems = [];

function mfEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function menuFormMsg(text, color) {
  const m = document.getElementById('menu-form-msg');
  m.textContent = text || '';
  m.style.color = color || 'var(--text3)';
}

function menuFormRender() {
  const body = document.getElementById('menu-form-body');
  body.textContent = '';
  const byId = Object.fromEntries(menuFormItems.map(i => [i.id, i]));
  const ids = MENU_FORM_ORDER.filter(id => byId[id]).concat(menuFormItems.map(i => i.id).filter(id => !MENU_FORM_ORDER.includes(id)));
  ids.forEach(id => {
    const it = byId[id];
    const row = mfEl('div');
    row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--border2)';
    const label = mfEl('div', t('menuform.item.' + id));
    label.style.cssText = 'flex:1 1 auto;min-width:0;font-size:12px;color:var(--text2)';
    row.appendChild(label);
    if (it.locked) {
      const lk = mfEl('span', 'ENV ' + it.envVar + '=' + it.mode);
      lk.style.cssText = 'font-size:11px;color:var(--amber);white-space:nowrap';
      lk.title = t('menuform.locked');
      row.appendChild(lk);
    }
    const sel = mfEl('select');
    sel.id = 'menu-form-' + id;
    sel.disabled = !!it.locked;
    sel.style.cssText = 'width:150px;flex:0 0 150px'; // le style global select{width:100%} l'etirait sur toute la ligne
    it.allowed.forEach(v => {
      const o = mfEl('option', t('menuform.mode.' + v));
      o.value = v;
      if (v === it.yamlMode) o.selected = true;
      sel.appendChild(o);
    });
    row.appendChild(sel);
    body.appendChild(row);
  });
}

async function menuFormOpen() {
  menuFormMsg('');
  document.getElementById('menu-form-overlay').style.display = 'flex';
  const d = await api('/menu-config').catch(() => null);
  if (!d || !Array.isArray(d.items)) { menuFormMsg(t('menuform.loadError'), 'var(--red)'); return; }
  menuFormItems = d.items;
  menuFormRender();
}
function menuFormClose() { document.getElementById('menu-form-overlay').style.display = 'none'; }

async function menuFormSave() {
  const values = {};
  menuFormItems.forEach(it => {
    if (it.locked) return;
    const sel = document.getElementById('menu-form-' + it.id);
    if (sel && sel.value !== it.yamlMode) values[it.id] = sel.value;
  });
  if (!Object.keys(values).length) { menuFormMsg(t('menuform.nochange')); return; }
  const r = await api('/menu-config/save', { method: 'POST', body: JSON.stringify({ values }) }).catch(e => ({ error: e.message }));
  if (!r || r.error) { menuFormMsg((r && r.error) || t('menuform.saveError'), 'var(--red)'); return; }
  menuFormItems = r.items || menuFormItems;
  menuFormRender();
  menuFormMsg(t('menuform.saved'), 'var(--green)');
  if (typeof checkOptionalFeatures === 'function') checkOptionalFeatures().catch(() => {});
  if (typeof loadSystemInfo === 'function') loadSystemInfo();
}
