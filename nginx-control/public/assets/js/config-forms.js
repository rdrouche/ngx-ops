// ── Formulaires de configuration generiques (#102) + chemins hote detectes (#103) ─────────────────────────
// Rendu pilote par le schema renvoye par /api/config-forms (lib/config-schemas.js) : un fichier ajoute au serveur
// obtient son formulaire sans nouveau code ici. Modale (ngxModal), createElement/textContent uniquement.
// Secrets jamais affiches : champ vide = conserver, case « Effacer » = supprimer. Administrateur.
const CFF = { ids: 0 };

function cffEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const cffLabel = (file, key) => { const k = 'cfgform.f.' + file + '.' + key; const s = t(k); return s && s !== k ? s : key; };

function cffMsg(text, ok) {
  const m = document.getElementById('cff-msg');
  if (!m) return;
  m.textContent = text || '';
  m.style.color = ok ? 'var(--green)' : 'var(--red)';
}

function cffField(d, f) {
  const id = 'cff-' + (CFF.ids++);
  const val = d.values[f.key];
  const wrap = cffEl('div'); wrap.style.cssText = 'margin-bottom:10px';
  let ctl;
  if (f.type === 'bool') {
    const row = cffEl('label'); row.style.cssText = 'display:flex;gap:8px;align-items:center;cursor:pointer';
    ctl = document.createElement('input'); ctl.type = 'checkbox'; ctl.checked = val === 'true' || val === true;
    row.appendChild(ctl); row.appendChild(cffEl('span', cffLabel(d.key, f.key))).style.fontWeight = '600';
    wrap.appendChild(row);
    ctl.dataset.cff = f.key; ctl.dataset.kind = 'bool';
    return wrap;
  }
  const lab = cffEl('label', cffLabel(d.key, f.key)); lab.htmlFor = id; lab.style.cssText = 'display:block;font-weight:600;margin-bottom:3px';
  wrap.appendChild(lab);
  if (f.type === 'enum') {
    ctl = document.createElement('select'); ctl.className = 'inp';
    const none = document.createElement('option'); none.value = ''; none.textContent = '—'; ctl.appendChild(none);
    (f.options || []).forEach((o) => { const op = document.createElement('option'); op.value = o; op.textContent = o; ctl.appendChild(op); });
    ctl.value = val || '';
  } else {
    ctl = document.createElement('input'); ctl.className = 'inp'; ctl.autocomplete = 'off'; ctl.spellcheck = false;
    if (f.type === 'int' || f.type === 'number') { ctl.type = 'number'; if (f.min != null) ctl.min = f.min; if (f.max != null) ctl.max = f.max; if (f.type === 'number') ctl.step = 'any'; }
    else if (f.type === 'secret') { ctl.type = 'password'; ctl.autocomplete = 'new-password'; ctl.placeholder = d.secretSet[f.key] ? t('cfgform.secretSet') : t('cfgform.secretNone'); }
    else ctl.type = 'text';
    if (f.type !== 'secret') ctl.value = val == null ? '' : val;
  }
  ctl.id = id; ctl.dataset.cff = f.key; ctl.dataset.kind = f.type;
  wrap.appendChild(ctl);
  if (f.type === 'secret' && d.secretSet[f.key]) {
    const cl = cffEl('label'); cl.style.cssText = 'display:flex;gap:6px;align-items:center;margin-top:4px;font-size:12px;cursor:pointer';
    const c = document.createElement('input'); c.type = 'checkbox'; c.dataset.cffClear = f.key;
    cl.appendChild(c); cl.appendChild(cffEl('span', t('cfgform.clear')));
    wrap.appendChild(cl);
  }
  if (f.type === 'url' && d.credentials && d.credentials[f.key]) wrap.appendChild(cffEl('div', t('cfgform.credKept'), 'nf-hint'));
  const sug = f.suggest && d.suggestions && d.suggestions[f.suggest];
  if (sug && sug.host && sug.host !== ctl.value) {
    const b = cffEl('button', t('cfgform.useDetected', { path: sug.host }) + (sug.derived ? ' ' + t('cfgform.derived') : ''), 'btn sm');
    b.type = 'button'; b.style.cssText = 'margin-top:4px;font-family:monospace;font-size:11px';
    b.addEventListener('click', () => { ctl.value = sug.host; });
    wrap.appendChild(b);
  }
  return wrap;
}

function cffCollect(box) {
  const values = {};
  box.querySelectorAll('[data-cff]').forEach((e) => {
    const k = e.dataset.cff;
    if (e.dataset.kind === 'bool') values[k] = e.checked;
    else if (e.dataset.kind === 'secret') { const v = e.value.trim(); if (v) values[k] = v; }
    else values[k] = e.value.trim();
  });
  box.querySelectorAll('[data-cff-clear]').forEach((e) => { if (e.checked) values['clear_' + e.dataset.cffClear] = true; });
  return values;
}

async function cffSave(modal, box, key) {
  cffMsg(t('cfgform.saving'), true);
  const r = await api('/config-forms', { method: 'PUT', body: JSON.stringify({ key, values: cffCollect(box) }) }).catch((e) => ({ error: e && e.message }));
  if (!r || r.error) {
    const errs = r && r.errors ? Object.entries(r.errors).map(([k, m]) => k + ' : ' + m).join(' ; ') : '';
    cffMsg(errs || (r && r.error) || t('common.error'), false);
    return;
  }
  modal.close();
  if (r.regenerateChallenge) alert(t('cfgform.regenerate'));
  if (typeof initConfigEditor === 'function' && document.getElementById('cfged-editor')) cfgEditorSelect(key);
}

/** Ouvre le formulaire d'un fichier ; renvoie vers le formulaire dedie ou l'editeur brut selon le cas. */
async function cfgFormOpen(key) {
  const d = await api('/config-forms?key=' + encodeURIComponent(key)).catch(() => null);
  if (!d || d.error) return;
  if (d.dedicated === 'logstore' && typeof logstoreConfigure === 'function') { openPage('logstore'); setTimeout(logstoreConfigure, 400); return; }
  if (d.dedicated === 'intelligence' && typeof intelConfigure === 'function') { openPage('intelligence'); setTimeout(intelConfigure, 400); return; }
  if (!d.fields) { const m = ngxModal({ title: t('cfgform.title', { name: key }) }); m.body.appendChild(cffEl('div', t('cfgform.pending'), 'nf-hint')); return; }
  const modal = ngxModal({ title: t('cfgform.title', { name: d.label || key }), wide: true });
  const box = modal.body;
  const intro = cffEl('div', t('cfgform.intro'), 'nf-hint'); intro.style.marginBottom = '12px'; box.appendChild(intro);
  const grid = cffEl('div'); grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:0 24px';
  d.fields.forEach((f) => grid.appendChild(cffField(d, f)));
  box.appendChild(grid);
  const bar = cffEl('div'); bar.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;align-items:center';
  const mk = (label, cls, fn) => { const b = cffEl('button', label, 'btn sm' + (cls ? ' ' + cls : '')); b.type = 'button'; b.addEventListener('click', fn); bar.appendChild(b); };
  mk(t('common.save'), 'primary', () => cffSave(modal, box, key));
  mk(t('common.close'), '', () => modal.close());
  box.appendChild(bar);
  const msg = cffEl('div'); msg.id = 'cff-msg'; msg.style.cssText = 'margin-top:8px;font-size:12px'; box.appendChild(msg);
}

/** Bouton « Formulaire » de l'editeur : fichier courant. */
function cfgFormOpenCurrent() { if (typeof cfgEditorCurrent !== 'undefined' && cfgEditorCurrent) cfgFormOpen(cfgEditorCurrent); }

// ── Chemins hote detectes (#103) ──────────────────────────────────────────────────────────────────────────
async function cfgPathsOpen() {
  const d = await api('/system/paths?fresh=1').catch(() => null);
  const modal = ngxModal({ title: t('cfgform.pathsTitle'), wide: true });
  const box = modal.body;
  if (!d || d.error) { box.appendChild(cffEl('div', t('common.error'))); return; }
  if (!d.available) { box.appendChild(cffEl('div', t('cfgform.noDocker'), 'nf-hint')); return; }
  const intro = cffEl('div', t('cfgform.pathsIntro'), 'nf-hint'); intro.style.marginBottom = '10px'; box.appendChild(intro);
  if (d.project && (d.project.dir || d.project.name)) {
    const p = cffEl('div', t('cfgform.project') + ' : ' + [d.project.name, d.project.dir].filter(Boolean).join(' — ')); p.style.cssText = 'margin-bottom:8px;font-family:monospace;font-size:12px'; box.appendChild(p);
  }
  const tbl = cffEl('table', null, 'tbl'); tbl.style.width = '100%';
  const head = cffEl('tr'); [t('cfgform.colContainer'), t('cfgform.colHost'), t('cfgform.colMode')].forEach((h) => head.appendChild(cffEl('th', h)));
  const thead = cffEl('thead'); thead.appendChild(head); tbl.appendChild(thead);
  const tb = cffEl('tbody');
  d.mounts.forEach((m) => {
    const tr = cffEl('tr');
    tr.appendChild(cffEl('td', m.container)).style.fontFamily = 'monospace';
    const host = cffEl('td', m.host || (m.name ? t('cfgform.volume', { name: m.name }) : '—')); host.style.fontFamily = 'monospace'; tr.appendChild(host);
    tr.appendChild(cffEl('td', m.rw ? 'rw' : 'ro'));
    tb.appendChild(tr);
  });
  tbl.appendChild(tb); box.appendChild(tbl);
  const bar = cffEl('div'); bar.style.marginTop = '10px';
  const c = cffEl('button', t('common.close'), 'btn sm'); c.type = 'button'; c.addEventListener('click', () => modal.close()); bar.appendChild(c);
  box.appendChild(bar);
}
