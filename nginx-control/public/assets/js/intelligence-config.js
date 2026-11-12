// ── NGX Ops Intelligence : formulaire de configuration (ticket #88) ─────
// Lit/écrit config/intelligence.yml via /api/intelligence/config. Le jeton n'est jamais affiché.
// Rendu par createElement/textContent uniquement.
const INTEL_FIELDS = {
  numbers: [['interval_seconds', 60, 3600], ['batch_size', 1, 500], ['timeout_seconds', 3, 60], ['backfill_hours', 0, 168], ['ping_interval_minutes', 3, 60]],
  checks: ['enable', 'share_user_agents', 'share_paths', 'share_vhost', 'include_challenge', 'ping_enable'],
  lists: ['exclude_rules', 'include_rules', 'exclude_ips'],
};

function icfgRow(label, hint, control) {
  const row = intelEl('label', null, null);
  row.style.cssText = 'display:grid;gap:3px;margin-bottom:10px';
  row.appendChild(intelEl('span', label, null)).style.fontWeight = '600';
  row.appendChild(control);
  if (hint) row.appendChild(intelEl('span', hint, 'nf-hint'));
  return row;
}

function icfgInput(type, id, value) {
  const i = document.createElement('input');
  i.type = type; i.id = 'icfg-' + id; i.className = 'inp'; i.autocomplete = 'off'; i.spellcheck = false;
  if (value != null) i.value = value;
  return i;
}

function icfgCheck(id, label, hint, on) {
  const wrap = intelEl('label', null, null);
  wrap.style.cssText = 'display:flex;gap:8px;align-items:flex-start;margin-bottom:8px;cursor:pointer';
  const c = document.createElement('input');
  c.type = 'checkbox'; c.id = 'icfg-' + id; c.checked = !!on;
  const txt = intelEl('span', null, null);
  txt.appendChild(intelEl('span', label, null)).style.fontWeight = '600';
  if (hint) { txt.appendChild(document.createElement('br')); txt.appendChild(intelEl('span', hint, 'nf-hint')); }
  wrap.appendChild(c); wrap.appendChild(txt);
  return wrap;
}

function icfgText(id, value) {
  const a = document.createElement('textarea');
  a.id = 'icfg-' + id; a.className = 'inp'; a.rows = 3; a.spellcheck = false; a.value = (value || []).join('\n');
  a.style.cssText = 'width:100%;font-family:monospace';
  return a;
}

function icfgSelect(id, options, value, labelOf) {
  const s = document.createElement('select');
  s.id = 'icfg-' + id; s.className = 'inp';
  options.forEach((o) => { const op = document.createElement('option'); op.value = o; op.textContent = labelOf ? labelOf(o) : o; op.selected = o === value; s.appendChild(op); });
  return s;
}

const icfgVal = (id) => document.getElementById('icfg-' + id);

function icfgCollect() {
  const body = {};
  INTEL_FIELDS.checks.forEach((k) => { body[k] = icfgVal(k).checked; });
  INTEL_FIELDS.numbers.forEach(([k]) => { body[k] = icfgVal(k).value; });
  INTEL_FIELDS.lists.forEach((k) => { body[k] = icfgVal(k).value.split(/[\s,;]+/).filter(Boolean); });
  ['mode', 'min_severity', 'api_url', 'user', 'ping_url'].forEach((k) => { body[k] = icfgVal(k).value.trim(); });
  const tok = icfgVal('token').value.trim();
  if (tok) body.token = tok;
  if (icfgVal('clear-token') && icfgVal('clear-token').checked) body.clearToken = true;
  return body;
}

function icfgMsg(text, ok) {
  const m = document.getElementById('icfg-msg');
  if (!m) return;
  m.textContent = text || '';
  m.style.color = ok ? 'var(--green)' : 'var(--red)';
}

async function icfgSave(thenTest) {
  icfgMsg(t('intel.cfg.saving'), true);
  const r = await api('/intelligence/config', { method: 'PUT', body: JSON.stringify(icfgCollect()) }).catch((e) => ({ error: e && e.message }));
  if (!r || r.error) { icfgMsg((r && r.errors && r.errors.join(' ; ')) || (r && r.error) || t('common.error'), false); return; }
  icfgMsg(t('intel.cfg.saved'), true);
  intelLoad();
  if (thenTest) await icfgTest();
}

async function icfgTest() {
  icfgMsg(t('intel.ping.testing'), true);
  const r = await api('/intelligence/ping', { method: 'POST' }).catch((e) => ({ error: e && e.message }));
  if (!r || r.error) { icfgMsg(t('intel.cfg.testFail', { err: (r && r.error) || t('common.error') }), false); return; }
  const p = r.ping || {};
  if (p.ok) icfgMsg(t('intel.cfg.testOk', { ms: p.latencyMs != null ? p.latencyMs : '—', auth: p.authenticated ? t('intel.cfg.authYes') : t('intel.cfg.authNo') }), true);
  else icfgMsg(t('intel.cfg.testFail', { err: p.code || p.kind || p.detail || '—' }), false);
  intelPingCard();
}

async function icfgDebug() {
  const pre = document.getElementById('icfg-debug');
  pre.style.display = '';
  pre.textContent = t('intel.cfg.loading');
  const [st, pv] = await Promise.all([api('/intelligence/status').catch(() => null), api('/intelligence/preview').catch(() => null)]);
  pre.textContent = '# GET /api/intelligence/status\n' + JSON.stringify(st, null, 2) + '\n\n# GET /api/intelligence/preview\n' + JSON.stringify(pv, null, 2);
}

async function intelConfigure() {
  const d = await api('/intelligence/config').catch(() => null);
  if (!d) return;
  const v = d.values;
  // Modale (#63) : le formulaire ne deplie plus la page.
  const modal = ngxModal({ title: t('intel.cfg.title'), wide: true });
  const box = modal.body;

  const intro = intelEl('div', null, 'nf-hint');
  intro.appendChild(document.createTextNode(t('intel.cfg.intro') + ' '));
  const a = document.createElement('a');
  a.href = d.registerUrl; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = t('intel.cfg.register');
  intro.appendChild(a);
  intro.style.marginBottom = '12px';
  box.appendChild(intro);

  const grid = intelEl('div', null, null);
  grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:0 24px';
  const colA = intelEl('div', null, null), colB = intelEl('div', null, null);
  grid.appendChild(colA); grid.appendChild(colB);

  colA.appendChild(icfgCheck('enable', t('intel.cfg.enable'), t('intel.cfg.enableHint'), v.enable));
  colA.appendChild(icfgRow(t('intel.cfg.mode'), t('intel.cfg.modeHint'), icfgSelect('mode', d.modes, v.mode, (o) => t('intel.mode.' + o))));
  colA.appendChild(icfgRow(t('intel.cfg.apiUrl'), d.apiUrlDefault ? t('intel.cfg.apiUrlEnv', { url: d.apiUrlDefault }) : t('intel.cfg.apiUrlHint'), icfgInput('url', 'api_url', v.api_url)));
  colA.appendChild(icfgRow(t('intel.cfg.user'), t('intel.cfg.userHint'), icfgInput('text', 'user', v.user)));
  const tok = icfgInput('password', 'token', '');
  tok.placeholder = d.tokenSet ? t('intel.cfg.tokenSet') : t('intel.cfg.tokenNone');
  tok.disabled = !!d.tokenFromEnv;
  colA.appendChild(icfgRow(t('intel.cfg.token'), d.tokenFromEnv ? t('intel.cfg.tokenEnv') : t('intel.cfg.tokenHint'), tok));
  if (d.tokenSet && !d.tokenFromEnv) colA.appendChild(icfgCheck('clear-token', t('intel.cfg.clearToken'), null, false));
  colA.appendChild(icfgRow(t('intel.cfg.minSeverity'), t('intel.cfg.minSeverityHint'), icfgSelect('min_severity', d.severities, v.min_severity, (o) => t('analyzer.sev.' + o))));
  INTEL_FIELDS.numbers.slice(0, 4).forEach(([k, min, max]) => {
    const i = icfgInput('number', k, v[k]); i.min = min; i.max = max;
    colA.appendChild(icfgRow(t('intel.cfg.' + k), t('intel.cfg.' + k + 'Hint', { min, max }), i));
  });

  colB.appendChild(icfgRow(t('intel.cfg.excludeRules'), t('intel.cfg.excludeRulesHint'), icfgText('exclude_rules', v.exclude_rules)));
  colB.appendChild(icfgRow(t('intel.cfg.includeRules'), t('intel.cfg.includeRulesHint'), icfgText('include_rules', v.include_rules)));
  colB.appendChild(icfgRow(t('intel.cfg.excludeIps'), t('intel.cfg.excludeIpsHint'), icfgText('exclude_ips', v.exclude_ips)));
  colB.appendChild(icfgCheck('share_user_agents', t('intel.cfg.shareUserAgents'), null, v.share_user_agents));
  colB.appendChild(icfgCheck('share_paths', t('intel.cfg.sharePaths'), null, v.share_paths));
  colB.appendChild(icfgCheck('share_vhost', t('intel.cfg.shareVhost'), t('intel.cfg.shareVhostHint'), v.share_vhost));
  colB.appendChild(icfgCheck('include_challenge', t('intel.cfg.includeChallenge'), t('intel.cfg.includeChallengeHint'), v.include_challenge));
  colB.appendChild(icfgCheck('ping_enable', t('intel.cfg.pingEnable'), null, v.ping_enable));
  const pi = icfgInput('number', 'ping_interval_minutes', v.ping_interval_minutes); pi.min = 3; pi.max = 60;
  colB.appendChild(icfgRow(t('intel.cfg.ping_interval_minutes'), null, pi));
  colB.appendChild(icfgRow(t('intel.cfg.pingUrl'), t('intel.cfg.pingUrlHint'), icfgInput('url', 'ping_url', v.ping_url)));
  box.appendChild(grid);

  if (d.errors && d.errors.length) {
    const e = intelEl('div', d.errors.join(' ; '), null); e.style.cssText = 'color:var(--amber);font-size:12px;margin-bottom:8px';
    box.appendChild(e);
  }
  const bar = intelEl('div', null, null);
  bar.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;align-items:center';
  [['intel.cfg.save', () => icfgSave(false)], ['intel.cfg.saveTest', () => icfgSave(true)], ['intel.cfg.test', icfgTest], ['intel.cfg.debug', icfgDebug], ['intel.cfg.rawEditor', () => { openPage('config-editor'); modal.close(); setTimeout(() => { if (typeof cfgEditorSelect === 'function') cfgEditorSelect('intelligence'); }, 500); }]]
    .forEach(([k, fn]) => { const b = intelEl('button', t(k), 'btn sm'); b.type = 'button'; b.addEventListener('click', fn); bar.appendChild(b); });
  box.appendChild(bar);
  const msg = intelEl('div', null, null); msg.id = 'icfg-msg'; msg.style.cssText = 'margin-top:8px;font-size:12px';
  box.appendChild(msg);
  const dbg = document.createElement('pre'); dbg.id = 'icfg-debug'; dbg.className = 'ct-logout';
  dbg.style.cssText = 'display:none;height:auto;max-height:360px;margin-top:10px';
  box.appendChild(dbg);
}
