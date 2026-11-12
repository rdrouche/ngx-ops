// ── Journal centralise : formulaire de configuration en modale (ticket #63) ─────
// Lit/ecrit config/logstore.yml via /api/logstore/config (administrateur). Les jetons ne sont jamais affiches :
// champ vide = conserver, case « effacer » = supprimer. Rendu par createElement/textContent uniquement.
// Le mode IP est un reglage du log store (jeton admin) : affiche en lecture seule.
let lsStatusLast = null; // dernier etat recu (logstoreLoad) : sert a afficher le mode IP courant

function lscEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const lscVal = (id) => document.getElementById('lscfg-' + id);

function lscRow(label, hint, control) {
  const row = lscEl('label');
  row.style.cssText = 'display:grid;gap:3px;margin-bottom:10px';
  row.appendChild(lscEl('span', label)).style.fontWeight = '600';
  row.appendChild(control);
  if (hint) row.appendChild(lscEl('span', hint, 'nf-hint'));
  return row;
}
function lscInput(type, id, value, placeholder) {
  const i = document.createElement('input');
  i.type = type; i.id = 'lscfg-' + id; i.className = 'inp'; i.autocomplete = 'off'; i.spellcheck = false;
  if (value != null) i.value = value;
  if (placeholder) i.placeholder = placeholder;
  return i;
}
function lscCheck(id, label, hint, on) {
  const wrap = lscEl('label');
  wrap.style.cssText = 'display:flex;gap:8px;align-items:flex-start;margin-bottom:8px;cursor:pointer';
  const c = document.createElement('input');
  c.type = 'checkbox'; c.id = 'lscfg-' + id; c.checked = !!on;
  const txt = lscEl('span');
  txt.appendChild(lscEl('span', label)).style.fontWeight = '600';
  if (hint) { txt.appendChild(document.createElement('br')); txt.appendChild(lscEl('span', hint, 'nf-hint')); }
  wrap.appendChild(c); wrap.appendChild(txt);
  return wrap;
}
function lscSecret(id, label, hint, isSet, fromEnv) {
  const frag = document.createDocumentFragment();
  const i = lscInput('password', id, '', isSet ? t('logstore.cfg.tokenSet') : t('logstore.cfg.tokenNone'));
  i.disabled = !!fromEnv;
  frag.appendChild(lscRow(label, fromEnv ? t('logstore.cfg.tokenEnv') : hint, i));
  if (isSet && !fromEnv) frag.appendChild(lscCheck('clear-' + id, t('logstore.cfg.clearToken'), null, false));
  return frag;
}
function lscSection(title) {
  const h = lscEl('div', title, 'ctitle');
  h.style.cssText = 'font-size:12px;margin:4px 0 8px';
  return h;
}

const LSC_TEXT = ['url', 'timeout_seconds', 'shipper_name', 'shipper_image', 'shipper_host_logs_path', 'shipper_host_data_path', 'shipper_sink_url', 'instance'];
const LSC_CHECK = ['enable', 'allow_insecure', 'shipper_enable', 'shipper_allow_insecure', 'shipper_blocklist', 'shipper_country'];

function lscCollect() {
  const body = {};
  LSC_CHECK.forEach((k) => { body[k] = lscVal(k).checked; });
  LSC_TEXT.forEach((k) => { body[k] = lscVal(k).value.trim(); });
  const tok = lscVal('token').value.trim(); if (tok) body.token = tok;
  const sink = lscVal('shipper_sink_token').value.trim(); if (sink) body.shipper_sink_token = sink;
  if (lscVal('clear-token') && lscVal('clear-token').checked) body.clearToken = true;
  if (lscVal('clear-shipper_sink_token') && lscVal('clear-shipper_sink_token').checked) body.clearSinkToken = true;
  return body;
}

function lscMsg(text, ok) {
  const m = document.getElementById('lscfg-msg');
  if (!m) return;
  m.textContent = text || '';
  m.style.color = ok ? 'var(--green)' : 'var(--red)';
}

async function lscSave(modal) {
  lscMsg(t('logstore.cfg.saving'), true);
  const r = await api('/logstore/config', { method: 'PUT', body: JSON.stringify(lscCollect()) }).catch((e) => ({ error: e && e.message }));
  if (!r || r.error) { lscMsg((r && r.errors && r.errors.join(' ; ')) || (r && r.error) || t('common.error'), false); return; }
  modal.close();
  logstoreLoad();
}

async function logstoreConfigure() {
  const d = await api('/logstore/config').catch(() => null);
  if (!d || !d.values) return;
  const v = d.values, eff = d.effective || {};
  const modal = ngxModal({ title: t('logstore.cfg.title'), wide: true });
  const box = modal.body;
  const intro = lscEl('div', t('logstore.cfg.intro'), 'nf-hint');
  intro.style.marginBottom = '12px';
  box.appendChild(intro);

  const grid = lscEl('div');
  grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:0 24px';
  const colA = lscEl('div'), colB = lscEl('div');
  grid.appendChild(colA); grid.appendChild(colB);

  colA.appendChild(lscSection(t('logstore.cfg.readTitle')));
  colA.appendChild(lscCheck('enable', t('logstore.cfg.enable'), t('logstore.cfg.enableHint'), v.enable));
  colA.appendChild(lscRow(t('logstore.cfg.url'), t('logstore.cfg.urlHint'), lscInput('text', 'url', v.url, 'https://logs.example.com')));
  colA.appendChild(lscSecret('token', t('logstore.cfg.token'), t('logstore.cfg.tokenHint'), d.tokenSet, d.tokenFromEnv));
  const to = lscInput('number', 'timeout_seconds', v.timeout_seconds); to.min = 2; to.max = 60;
  colA.appendChild(lscRow(t('logstore.cfg.timeout'), t('logstore.cfg.timeoutHint'), to));
  colA.appendChild(lscCheck('allow_insecure', t('logstore.cfg.allowInsecure'), t('logstore.cfg.allowInsecureHint'), v.allow_insecure));
  const ip = lscEl('div', t('logstore.cfg.ipMode', { mode: (lsStatusLast && lsStatusLast.store && lsStatusLast.store.detail && lsStatusLast.store.detail.ip_mode) || '—' }), 'nf-hint');
  ip.style.marginTop = '6px';
  colA.appendChild(ip);

  colB.appendChild(lscSection(t('logstore.cfg.shipperTitle')));
  colB.appendChild(lscCheck('shipper_enable', t('logstore.cfg.shipperEnable'), t('logstore.cfg.shipperEnableHint'), v.shipper_enable));
  colB.appendChild(lscRow(t('logstore.cfg.instance'), t('logstore.cfg.instanceHint'), lscInput('text', 'instance', v.instance, eff.instance || '')));
  colB.appendChild(lscRow(t('logstore.cfg.sinkUrl'), t('logstore.cfg.sinkUrlHint'), lscInput('text', 'shipper_sink_url', v.shipper_sink_url, eff.shipper_sink_url || '')));
  colB.appendChild(lscSecret('shipper_sink_token', t('logstore.cfg.sinkToken'), t('logstore.cfg.sinkTokenHint'), d.sinkTokenSet, d.sinkTokenFromEnv));
  colB.appendChild(lscRow(t('logstore.cfg.hostLogs'), t('logstore.cfg.hostLogsHint'), lscInput('text', 'shipper_host_logs_path', v.shipper_host_logs_path, eff.shipper_host_logs_path || '')));
  colB.appendChild(lscRow(t('logstore.cfg.hostData'), t('logstore.cfg.hostDataHint'), lscInput('text', 'shipper_host_data_path', v.shipper_host_data_path)));
  colB.appendChild(lscRow(t('logstore.cfg.name'), null, lscInput('text', 'shipper_name', v.shipper_name, eff.shipper_name || 'ngx-shipper')));
  colB.appendChild(lscRow(t('logstore.cfg.image'), null, lscInput('text', 'shipper_image', v.shipper_image, eff.shipper_image || '')));
  colB.appendChild(lscCheck('shipper_blocklist', t('logstore.cfg.blocklist'), null, v.shipper_blocklist));
  colB.appendChild(lscCheck('shipper_country', t('logstore.cfg.country'), t('logstore.cfg.countryHint'), v.shipper_country));
  colB.appendChild(lscCheck('shipper_allow_insecure', t('logstore.cfg.sinkAllowInsecure'), null, v.shipper_allow_insecure));
  box.appendChild(grid);

  if (d.errors && d.errors.length) {
    const e = lscEl('div', d.errors.join(' ; ')); e.style.cssText = 'color:var(--amber);font-size:12px;margin-bottom:8px';
    box.appendChild(e);
  }
  const bar = lscEl('div');
  bar.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;align-items:center';
  const mk = (label, cls, fn) => { const b = lscEl('button', label, 'btn sm' + (cls ? ' ' + cls : '')); b.type = 'button'; b.addEventListener('click', fn); bar.appendChild(b); };
  mk(t('common.save'), 'primary', () => lscSave(modal));
  mk(t('common.close'), '', () => modal.close());
  mk(t('logstore.cfg.rawEditor'), '', () => { modal.close(); openPage('config-editor'); setTimeout(() => { if (typeof cfgEditorSelect === 'function') cfgEditorSelect('logstore'); }, 500); });
  box.appendChild(bar);
  const msg = lscEl('div'); msg.id = 'lscfg-msg'; msg.style.cssText = 'margin-top:8px;font-size:12px';
  box.appendChild(msg);
}
