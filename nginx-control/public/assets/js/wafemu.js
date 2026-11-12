'use strict';
/**
 * Page "WAF emule" — analyse a posteriori des journaux d'acces (Coraza + OWASP CRS).
 * Script global classique charge apres le script principal : il partage sa portee
 * (api(), t(), h(), hasPerm(), fmtB(), copyToClipboard(), copyFeedback(), openPage()).
 *
 * Securite : TOUT ce qui vient du WAF (URI, User-Agent, message de regle, donnees
 * correspondantes, noms de vhost...) est affiche via textContent / createElement,
 * jamais par innerHTML : une URI d'attaque contient par definition du HTML et des
 * guillemets. Aucun texte francais/anglais en dur ici : tout passe par t() (les
 * dictionnaires sont dans public/assets/lang/{fr,en}.json, cles wafemu.*).
 *
 * Le WAF est EMULE : les enregistrements (reglages, exceptions, vhosts) passent par
 * UN SEUL PUT du JSON complet (wfSaveSettings), lu juste avant pour ne rien ecraser.
 */
const WF = {
  tab: 'overview', status: null, vhosts: null, categories: null,
  hours: 24, hits: [], hitsOffset: 0, hitsTotal: 0, rulesOffset: 0, rulesTotal: 0,
  filters: { ip: '', vhost: '', rule: '', minScore: '', mode: '' },
  ruleFilters: { q: '', category: '', state: '' },
};
const WF_PAGE = 25;
const WF_RULES_PAGE = 50;
const WF_TABS = ['overview', 'rules', 'exceptions', 'vhosts', 'lists', 'settings', 'simulator', 'advice'];
const WF_SETTINGS_KEYS = ['enable', 'mode', 'paranoia', 'thresholds', 'windowMinutes', 'listHours', 'alertMinScore',
  'vhostMode', 'vhosts', 'disabledRules', 'exceptions', 'ignoreStatus', 'excludeIps'];

// ── Petits utilitaires DOM (aucun innerHTML avec des donnees) ────────────────
function wfEl(tag, text, cls, style) {
  const e = document.createElement(tag);
  if (text !== null && text !== undefined && text !== '') e.textContent = String(text);
  if (cls) e.className = cls;
  if (style) e.style.cssText = style;
  return e;
}
function wfBadge(text, cls, title) {
  const b = wfEl('span', text, 'badge ' + (cls || 'gy'));
  if (title) b.title = title;
  return b;
}
function wfBtn(label, onClick, cls) {
  const b = wfEl('button', label, 'btn sm' + (cls ? ' ' + cls : ''));
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}
function wfCan() { return hasPerm('deploy'); }
function wfTime(ms) { return ms ? new Date(ms).toLocaleString(LANG === 'fr' ? 'fr-FR' : 'en-GB') : '—'; }
function wfNum(n) { return Number(n || 0).toLocaleString(LANG === 'fr' ? 'fr-FR' : 'en-GB'); }
function wfShort(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) + '…' : s; }

/** Message d'erreur : traduit par `code` quand le serveur en fournit un, sinon son texte. */
function wfErr(d) {
  if (!d) return t('wafemu.err.unreachable');
  if (d.code) { const k = 'wafemu.err.' + d.code; const v = t(k); if (v !== k) return v; }
  return d.error || t('common.error');
}

function wfTable(headers, rows, emptyText) {
  const wrap = wfEl('div', null, 'tw');
  if (!rows.length) { wrap.appendChild(wfEl('div', emptyText, null, 'color:var(--text3);font-size:12px;padding:6px 0')); return wrap; }
  const table = wfEl('table', null, 'sync-table');
  const head = wfEl('tr');
  headers.forEach(x => head.appendChild(wfEl('th', x)));
  table.appendChild(wfEl('thead')).appendChild(head);
  const body = wfEl('tbody');
  rows.forEach(cells => {
    const tr = wfEl('tr');
    cells.forEach(c => {
      const td = wfEl('td');
      if (c instanceof Node) td.appendChild(c); else td.textContent = c == null ? '' : String(c);
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
  table.appendChild(body);
  wrap.appendChild(table);
  return wrap;
}

function wfField(label, input, hint) {
  const f = wfEl('div', null, 'sched-field');
  f.appendChild(wfEl('label', label, 'sched-lbl'));
  f.appendChild(input);
  if (hint) f.appendChild(wfEl('div', hint, 'nf-hint'));
  return f;
}
function wfInput(id, value, ph, type) {
  const i = wfEl('input', null, 'inp');
  i.id = id; i.type = type || 'text'; i.value = value == null ? '' : String(value);
  if (ph) i.placeholder = ph;
  return i;
}
function wfSelect(id, options, current) {
  const s = wfEl('select', null, 'inp');
  s.id = id;
  options.forEach(([v, label]) => { const o = wfEl('option', label); o.value = v; if (String(v) === String(current)) o.selected = true; s.appendChild(o); });
  return s;
}
function wfMsg(el, text, ok) {
  if (!el) return;
  el.textContent = text || '';
  el.style.color = ok === null ? 'var(--text3)' : ok ? 'var(--green)' : 'var(--red)';
}
function wfGet(id) { return document.getElementById(id); }

// ── Modale ───────────────────────────────────────────────────────────────────
function wfModalOpen(title, bodyNodes, buttons) {
  const box = wfGet('wf-modal-box');
  box.textContent = '';
  box.appendChild(wfEl('div', title, 'ctitle', 'margin-bottom:0'));
  bodyNodes.forEach(n => box.appendChild(n));
  const bar = wfEl('div', null, null, 'display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap');
  buttons.forEach(b => bar.appendChild(b));
  box.appendChild(bar);
  wfGet('wf-modal').style.display = 'flex';
}
function wfModalClose() { const m = wfGet('wf-modal'); if (m) m.style.display = 'none'; }

// ── Reglages : un seul PUT du JSON complet ───────────────────────────────────
async function wfFetchSettings() {
  const cur = await api('/waf/settings');
  return cur && cur.settings ? cur.settings : null;
}

/** Relit les reglages, applique `mutate`, renvoie l'ensemble complet en UN SEUL PUT. */
async function wfSaveSettings(mutate) {
  const cur = await wfFetchSettings();
  if (!cur) return { error: t('wafemu.err.unreachable') };
  const next = {};
  WF_SETTINGS_KEYS.forEach(k => { if (cur[k] !== undefined) next[k] = JSON.parse(JSON.stringify(cur[k])); });
  mutate(next);
  const r = await api('/waf/settings', { method: 'PUT', body: JSON.stringify(next) });
  if (!r || r.error || !r.settings) return { error: wfErr(r) };
  return { ok: true, settings: r.settings };
}

async function wfLoadVhosts(force) {
  if (WF.vhosts && !force) return WF.vhosts;
  const d = await api('/waf/vhosts');
  WF.vhosts = d && d.vhosts ? d.vhosts : [];
  return WF.vhosts;
}

// ── Chargement de la page ────────────────────────────────────────────────────
async function initWafemu() { wfBuildTabs(); await wfLoad(); }

function wfBuildTabs() {
  const box = wfGet('wf-tabs');
  if (!box || box.childNodes.length) return;
  WF_TABS.forEach(name => {
    const b = wfEl('button', t('wafemu.tab.' + name), 'format-tab');
    b.id = 'wf-tab-' + name;
    b.type = 'button';
    b.addEventListener('click', () => wfTab(name));
    box.appendChild(b);
  });
}

async function wfLoad() {
  wfBuildTabs();
  const d = await api('/waf/status');
  WF.status = d;
  const dis = wfGet('wf-disabled');
  const main = wfGet('wf-main');
  if (!d || d.error || !d.enabled) {
    dis.style.display = '';
    main.style.display = 'none';
    const errs = d && d.errors ? d.errors.slice() : [];
    if (!d) errs.push(t('wafemu.err.unreachable'));
    wfGet('wf-disabled-errors').textContent = errs.join(' ; ');
    wfGet('wf-count').textContent = '';
    return;
  }
  dis.style.display = 'none';
  main.style.display = 'flex';
  wfRenderContainer(d);
  wfRenderCrs(d);
  await wfTab(WF.tab);
}

function wfKpi(label, value, cls) {
  const sc = wfEl('div', null, 'sc' + (cls ? ' ' + cls : ''));
  sc.appendChild(wfEl('div', label, 'sl'));
  sc.appendChild(wfEl('div', value, 'sv', 'font-size:16px'));
  return sc;
}

function wfRenderContainer(d) {
  const c = d.container || {};
  const w = d.waf || null;
  const el = wfGet('wf-status');
  el.textContent = '';
  const dot = wfEl('span', null, 'cb-status-dot ' + (c.running ? 'running' : 'stopped'));
  el.appendChild(dot);
  let txt;
  if (!c.exists) txt = t('wafemu.container.absent');
  else if (c.running) txt = t('wafemu.container.running', { image: c.image || '' });
  else txt = t('wafemu.container.stopped', { status: c.status || '' });
  el.appendChild(wfEl('span', txt));
  const warn = (msg) => el.appendChild(wfEl('span', msg, null, 'color:var(--amber);margin-left:10px'));
  if (c.dockerUnavailable) warn(t('analyzer.dockerUnreachable'));
  else if (c.running && !d.reachable) warn(t('wafemu.container.startedUnreachable'));
  else if (w && w.engine && w.engine.ready === false) warn(t('wafemu.engine.notReady'));

  // Prerequis manquants (accept_limits, chemins hote...) : expliques, jamais silencieux.
  const bl = wfGet('wf-blockers');
  bl.textContent = '';
  const blockers = d.blockers || [];
  blockers.forEach(code => {
    const key = 'wafemu.blocker.' + code;
    const label = t(key);
    bl.appendChild(wfEl('div', label === key ? code : label));
  });
  (d.errors || []).forEach(e => bl.appendChild(wfEl('div', e, null, 'color:var(--red)')));
  bl.style.display = blockers.length || (d.errors || []).length ? '' : 'none';

  const can = wfCan();
  const show = (id, on) => { const b = wfGet(id); if (b) b.style.display = on && can ? '' : 'none'; };
  wfGet('wf-image-name').textContent = (d.config && d.config.image) || '—';

  const k = wfGet('wf-kpis');
  k.textContent = '';
  if (w) {
    const s24 = w.stats24h || {};
    const lg = w.logs || {};
    const fm = lg.formats || {};
    k.appendChild(wfKpi(t('wafemu.kpi.requests24'), wfNum(s24.requests)));
    k.appendChild(wfKpi(t('wafemu.kpi.hits24'), wfNum(s24.hits), s24.hits ? 'am' : ''));
    k.appendChild(wfKpi(t('wafemu.kpi.ips24'), wfNum(s24.ips)));
    k.appendChild(wfKpi(t('wafemu.kpi.paranoia'), String(w.effectiveParanoia == null ? '—' : w.effectiveParanoia)));
    k.appendChild(wfKpi(t('wafemu.kpi.linesAnalyzed'), wfNum(lg.linesAnalyzed)));
    k.appendChild(wfKpi(t('wafemu.kpi.files'), wfNum(lg.files) + ' (' + Object.entries(fm).map(([n, v]) => n + ':' + v).join(' ') + ')'));
    k.appendChild(wfKpi(t('wafemu.kpi.vhosts'), wfNum(w.vhostsSeen)));
    k.appendChild(wfKpi(t('wafemu.kpi.dropped'), wfNum(lg.dropped), lg.dropped ? 're' : ''));
    k.appendChild(wfKpi(t('wafemu.kpi.memory'), w.memory && w.memory.rss ? fmtB(w.memory.rss) : '—'));
    k.appendChild(wfKpi(t('wafemu.kpi.evalMs'), s24.avgEvalMs != null ? Number(s24.avgEvalMs).toFixed(2) + ' ms' : '—'));
    wfGet('wf-count').textContent = s24.hits ? String(s24.hits) : '';
  } else {
    wfGet('wf-count').textContent = '';
  }
}

function wfRenderCrs(d) {
  const body = wfGet('wf-crs-body');
  body.textContent = '';
  const crs = d.waf && d.waf.crs ? d.waf.crs : null;
  const can = wfCan();
  const upd = wfGet('wf-btn-crs'); const rel = wfGet('wf-btn-reload');
  if (upd) upd.style.display = can && d.reachable ? '' : 'none';
  if (rel) rel.style.display = can && d.reachable ? '' : 'none';
  if (!crs) { body.appendChild(wfEl('div', t('wafemu.crs.unknown'), null, 'color:var(--text3)')); return; }
  const grid = wfEl('div', null, 'sgrid sgrid-auto');
  grid.appendChild(wfKpi(t('wafemu.crs.version'), crs.version || '—'));
  grid.appendChild(wfKpi(t('wafemu.crs.state'), crs.downloading ? t('wafemu.crs.downloading') : crs.installed ? t('wafemu.crs.installed') : t('wafemu.crs.missing'), crs.installed ? '' : 'am'));
  grid.appendChild(wfKpi(t('wafemu.crs.rulesLoaded'), wfNum(crs.rulesLoaded)));
  grid.appendChild(wfKpi(t('wafemu.crs.filesIgnored'), String((crs.filesIgnored || []).length), (crs.filesIgnored || []).length ? 'am' : ''));
  grid.appendChild(wfKpi(t('wafemu.crs.updatedAt'), crs.updatedAt ? new Date(crs.updatedAt).toLocaleString(LANG === 'fr' ? 'fr-FR' : 'en-GB') : '—'));
  body.appendChild(grid);
  if (crs.lastError) body.appendChild(wfEl('div', t('wafemu.crs.lastError', { err: String(crs.lastError) }), null, 'color:var(--red);margin-top:8px'));
  const ign = crs.filesIgnored || [];
  if (ign.length) {
    const det = wfEl('details', null, null, 'margin-top:8px');
    det.appendChild(wfEl('summary', t('wafemu.crs.ignoredTitle', { n: ign.length }), null, 'cursor:pointer;color:var(--amber)'));
    ign.forEach(f => det.appendChild(wfEl('div', f.file + ' — ' + f.reason, null, 'font-family:monospace;font-size:11px;color:var(--text3);margin-top:3px')));
    body.appendChild(det);
  }
}

async function wfContainer(action) {
  const el = wfGet('wf-status');
  el.textContent = t(action === 'start' ? 'analyzer.starting' : action === 'stop' ? 'analyzer.stopping' : 'wafemu.container.restarting');
  const d = await api('/waf/container/' + action, { method: 'POST' });
  if (!d || d.error) { wfMsg(el, t('common.error') + ' : ' + wfErr(d), false); return; }
  el.style.color = '';
  setTimeout(wfLoad, 1500);
}

async function wfImageUpdate() {
  const btn = wfGet('wf-btn-image');
  if (btn) { btn.disabled = true; btn.textContent = t('analyzer.updateImage.checking'); }
  const d = await api('/waf/image/update', { method: 'POST' });
  if (btn) { btn.disabled = false; btn.textContent = '⬇ ' + t('analyzer.updateImage'); }
  if (!d || d.error || d.ok === false) { alert(t('common.error') + ' : ' + wfErr(d)); return; }
  alert(d.updated ? t('analyzer.imageDownloaded') + (d.recreated ? t('analyzer.containerRecreated') : '.') : t('analyzer.imageUpToDate'));
  await wfLoad();
}

async function wfCrsUpdate() {
  const d = await api('/waf/rules/update', { method: 'POST', body: JSON.stringify({}) });
  if (!d || d.error) { alert(t('common.error') + ' : ' + wfErr(d)); return; }
  alert(t('wafemu.crs.updateStarted'));
  setTimeout(wfLoad, 3000);
  setTimeout(wfLoad, 15000);
}

async function wfEngineReload() {
  const d = await api('/waf/engine/reload', { method: 'POST', body: JSON.stringify({}) });
  if (!d || d.error) { alert(t('common.error') + ' : ' + wfErr(d)); return; }
  alert(t('wafemu.crs.reloaded'));
  wfLoad();
}

// ── Onglets ──────────────────────────────────────────────────────────────────
const WF_RENDER = {
  overview: wfRenderOverview, rules: wfRenderRules, exceptions: wfRenderExceptions, vhosts: wfRenderVhosts, lists: wfRenderLists,
  settings: wfRenderSettings, simulator: wfRenderSimulator, advice: wfRenderAdvice,
};

async function wfTab(name) {
  if (!WF_RENDER[name]) name = 'overview';
  WF.tab = name;
  WF_TABS.forEach(n => { const b = wfGet('wf-tab-' + n); if (b) b.classList.toggle('active', n === name); });
  const panel = wfGet('wf-panel');
  panel.textContent = '';
  panel.appendChild(wfEl('div', t('common.loading'), null, 'color:var(--text3);font-size:12px'));
  const box = wfEl('div');
  try { await WF_RENDER[name](box); }
  catch (e) { box.textContent = ''; box.appendChild(wfEl('div', t('common.error') + ' : ' + e.message, null, 'color:var(--red)')); }
  if (WF.tab !== name) return; // l'utilisateur a change d'onglet pendant le chargement
  panel.textContent = '';
  panel.appendChild(box);
}

function wfSection(title, extra) {
  const s = wfEl('div', null, null, 'margin-bottom:18px');
  const head = wfEl('div', null, 'row', 'margin-bottom:8px;flex-wrap:wrap');
  head.appendChild(wfEl('div', title, 'ctitle', 'margin-bottom:0'));
  if (extra) head.appendChild(extra);
  s.appendChild(head);
  return s;
}

// ── Onglet Apercu ────────────────────────────────────────────────────────────
async function wfRenderOverview(box) {
  const bar = wfEl('div', null, null, 'display:flex;gap:6px;align-items:center;margin-bottom:12px;flex-wrap:wrap');
  [[24, 'common.window.24h'], [168, 'common.window.7d']].forEach(([h, key]) => {
    const b = wfBtn(t(key), () => { WF.hours = h; wfTab('overview'); }, WF.hours === h ? 'primary' : '');
    bar.appendChild(b);
  });
  box.appendChild(bar);

  const [st, al] = await Promise.all([
    api('/waf/hits/stats?hours=' + WF.hours),
    api('/waf/alerts?raw=1&order=desc&limit=10'),
  ]);
  if (!st || st.reachable === false) { box.appendChild(wfEl('div', t('wafemu.err.unreachable'), null, 'color:var(--amber)')); return; }

  const grid = wfEl('div', null, 'sgrid sgrid-auto', 'margin-bottom:16px');
  grid.appendChild(wfKpi(t('wafemu.ov.requests'), wfNum(st.requests)));
  grid.appendChild(wfKpi(t('wafemu.ov.hitRequests'), wfNum(st.hitRequests), st.hitRequests ? 'am' : ''));
  grid.appendChild(wfKpi(t('wafemu.ov.ips'), wfNum(st.ips)));
  box.appendChild(grid);

  // Timeline : une barre par intervalle (hauteur = requetes avec hit)
  const tl = st.timeline || [];
  const sec = wfSection(t('wafemu.ov.timeline'));
  if (tl.length) {
    const maxHits = Math.max(1, ...tl.map(p => p.hits || 0));
    const chart = wfEl('div', null, null, 'display:flex;align-items:flex-end;gap:2px;height:90px;border-bottom:1px solid var(--border2)');
    tl.forEach(p => {
      const col = wfEl('div', null, null, 'flex:1;min-width:3px;background:var(--bg3);border-radius:2px 2px 0 0;position:relative;height:100%');
      const bar2 = wfEl('div', null, null, 'position:absolute;left:0;right:0;bottom:0;background:var(--red);border-radius:2px 2px 0 0;height:' + Math.round(100 * (p.hits || 0) / maxHits) + '%');
      col.title = wfTime(p.t) + ' — ' + t('wafemu.ov.tlTitle', { hits: p.hits || 0, requests: p.requests || 0 });
      col.appendChild(bar2);
      chart.appendChild(col);
    });
    sec.appendChild(chart);
    sec.appendChild(wfEl('div', t('wafemu.ov.timelineHint'), 'nf-hint', 'margin-top:4px'));
  } else sec.appendChild(wfEl('div', t('wafemu.ov.none'), null, 'color:var(--text3);font-size:12px'));
  box.appendChild(sec);

  const two = wfEl('div', null, null, 'display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-bottom:6px');
  const s1 = wfSection(t('wafemu.ov.topRules'));
  s1.appendChild(wfTable([t('wafemu.col.rule'), t('wafemu.col.message'), t('wafemu.col.count'), t('wafemu.col.score')],
    (st.topRules || []).map(r => [String(r.id), wfShort(r.msg, 70), wfNum(r.count), wfNum(r.score)]), t('wafemu.ov.none')));
  const s2 = wfSection(t('wafemu.ov.topIps'));
  s2.appendChild(wfTable([t('wafemu.col.ip'), t('wafemu.col.hits'), t('wafemu.col.score'), t('wafemu.col.lists')],
    (st.topIps || []).map(r => {
      const lists = wfEl('span');
      (r.lists || []).forEach(l => { lists.appendChild(wfBadge(t('wafemu.list.' + l), l === 'block' ? 'rd' : 'am')); lists.appendChild(document.createTextNode(' ')); });
      return [r.ip, wfNum(r.hits), wfNum(r.score), lists];
    }), t('wafemu.ov.none')));
  two.appendChild(s1); two.appendChild(s2);
  box.appendChild(two);

  // Alertes recentes
  const alerts = (al && al.alerts) || [];
  const sA = wfSection(t('wafemu.ov.alerts'));
  sA.appendChild(wfTable([t('wafemu.col.time'), t('wafemu.col.severity'), t('wafemu.col.ip'), t('wafemu.col.vhost'), t('wafemu.col.score'), t('wafemu.col.rules'), ''],
    alerts.map(a => {
      const ev = a.evidence || {};
      const act = wfEl('span');
      if (a.ack) act.appendChild(wfBadge(t('wafemu.alert.acked'), 'gy'));
      else if (wfCan()) act.appendChild(wfBtn(t('wafemu.alert.ack'), async () => { await api('/waf/alerts/ack', { method: 'POST', body: JSON.stringify({ ids: [a.id] }) }); wfTab('overview'); }));
      return [wfTime(a.ts), wfBadge(t('analyzer.sev.' + a.severity), a.severity === 'high' ? 'rd' : a.severity === 'medium' ? 'am' : 'gy'),
        a.ip, a.vhost || '', wfNum(ev.score), (ev.rules || []).map(r => r.id).join(', '), act];
    }), t('wafemu.ov.noAlerts')));
  box.appendChild(sA);

  // Derniers hits
  box.appendChild(await wfHitsSection());
}

function wfHitsFilterBar() {
  const f = WF.filters;
  const bar = wfEl('div', null, 'bl-filters');
  const mk = (id, ph, val, w) => { const i = wfInput(id, val, ph); i.className = 'inp bl-f-ip'; i.style.maxWidth = w || '160px'; return i; };
  bar.appendChild(mk('wf-f-ip', t('wafemu.col.ip'), f.ip));
  bar.appendChild(mk('wf-f-vhost', t('wafemu.col.vhost'), f.vhost, '200px'));
  bar.appendChild(mk('wf-f-rule', t('wafemu.col.rule'), f.rule, '110px'));
  bar.appendChild(mk('wf-f-score', t('wafemu.filter.minScore'), f.minScore, '110px'));
  const mode = wfSelect('wf-f-mode', [['', t('wafemu.filter.allModes')], ['observe', t('wafemu.mode.observe')], ['remediate', t('wafemu.mode.remediate')]], f.mode);
  mode.className = 'inp bl-f-sel';
  bar.appendChild(mode);
  bar.appendChild(wfBtn(t('wafemu.filter.apply'), () => {
    WF.filters = { ip: wfGet('wf-f-ip').value.trim(), vhost: wfGet('wf-f-vhost').value.trim(), rule: wfGet('wf-f-rule').value.trim(),
      minScore: wfGet('wf-f-score').value.trim(), mode: wfGet('wf-f-mode').value };
    WF.hitsOffset = 0;
    wfRefreshHits();
  }));
  return bar;
}

async function wfHitsSection() {
  const sec = wfSection(t('wafemu.ov.recentHits'));
  sec.appendChild(wfHitsFilterBar());
  const holder = wfEl('div');
  holder.id = 'wf-hits';
  sec.appendChild(holder);
  await wfFillHits(holder);
  return sec;
}

async function wfRefreshHits() { const h = wfGet('wf-hits'); if (h) await wfFillHits(h); }

async function wfFillHits(holder) {
  const p = new URLSearchParams({ limit: String(WF_PAGE), offset: String(WF.hitsOffset), order: 'desc' });
  const f = WF.filters;
  if (f.ip) p.set('ip', f.ip);
  if (f.vhost) p.set('vhost', f.vhost);
  if (f.rule) p.set('rule', f.rule);
  if (f.minScore) p.set('minScore', f.minScore);
  if (f.mode) p.set('mode', f.mode);
  const d = await api('/waf/hits?' + p.toString());
  holder.textContent = '';
  if (!d || d.error || d.reachable === false) { holder.appendChild(wfEl('div', d && d.error ? d.error : t('wafemu.err.unreachable'), null, 'color:var(--amber);font-size:12px')); return; }
  WF.hits = d.hits || [];
  WF.hitsTotal = d.total || 0;
  const rows = WF.hits.map(h => {
    const rules = wfEl('span');
    (h.rules || []).forEach(r => { rules.appendChild(wfBadge(String(r.id), 'gy', (r.msg || '') + (r.data ? ' — ' + r.data : ''))); rules.appendChild(document.createTextNode(' ')); });
    if (h.possiblySucceeded) rules.appendChild(wfBadge(t('wafemu.hit.possibly'), 'am', t('wafemu.hit.possiblyHelp')));
    const uri = wfEl('code', wfShort(h.uri, 90)); uri.title = h.uri || '';
    uri.style.fontSize = '11px';
    const act = wfEl('span');
    if (wfCan() && (h.rules || []).length) act.appendChild(wfBtn(t('wafemu.hit.falsePositive'), () => wfExceptionModal({ rules: h.rules, vhost: h.vhost, uri: h.uri })));
    return [wfTime(h.ts), h.vhost || '', h.ip, (h.method || '') + ' ', uri, String(h.status || ''),
      wfBadge(String(h.score), h.score >= 10 ? 'rd' : 'am'), wfBadge(t('wafemu.mode.' + (h.mode || 'observe')), h.mode === 'remediate' ? 'rd' : 'gy'), rules, act];
  });
  // la methode et l'URI partagent une cellule
  const merged = rows.map(r => { const c = wfEl('span'); c.appendChild(document.createTextNode(r[3])); c.appendChild(r[4]); return [r[0], r[1], r[2], c, r[5], r[6], r[7], r[8], r[9]]; });
  holder.appendChild(wfTable([t('wafemu.col.time'), t('wafemu.col.vhost'), t('wafemu.col.ip'), t('wafemu.col.request'), t('wafemu.col.status'),
    t('wafemu.col.score'), t('wafemu.col.mode'), t('wafemu.col.rules'), ''], merged, t('wafemu.ov.noHits')));
  holder.appendChild(wfPager(WF.hitsOffset, WF_PAGE, WF.hitsTotal, (off) => { WF.hitsOffset = off; wfRefreshHits(); }));
}

function wfPager(offset, size, total, go) {
  const pg = wfEl('div', null, 'bl-pager');
  const prev = wfBtn('← ' + t('analyzer.prev'), () => go(Math.max(0, offset - size)));
  prev.disabled = offset <= 0;
  const next = wfBtn(t('analyzer.next') + ' →', () => go(offset + size));
  next.disabled = offset + size >= total;
  pg.appendChild(prev);
  pg.appendChild(wfEl('span', total ? (offset + 1) + '–' + Math.min(total, offset + size) + ' / ' + total : '0'));
  pg.appendChild(next);
  return pg;
}

// ── Exception (faux positif) : modale pre-remplie ────────────────────────────
function wfUriPath(uri) {
  const s = String(uri || '');
  const q = s.search(/[?#]/);
  return q === -1 ? s : s.slice(0, q);
}

function wfExceptionModal({ rules, rule, vhost, uri }) {
  const list = rules || [{ id: rule, msg: '' }];
  // Ajout manuel (aucune regle fournie) : saisie de l'identifiant CRS
  const ruleSel = (!rules && !rule) ? wfInput('wf-ex-rule', '', '942100') : wfSelect('wf-ex-rule', list.map(r => [String(r.id), r.id + (r.msg ? ' — ' + wfShort(r.msg, 60) : '')]), rule || (list[0] && list[0].id));
  const vh = wfInput('wf-ex-vhost', vhost || '', t('wafemu.col.vhost'));
  const path = wfInput('wf-ex-path', wfUriPath(uri), '/');
  const ua = wfInput('wf-ex-ua', '', t('wafemu.ex.uaPh'));
  const ip = wfInput('wf-ex-ip', '', t('wafemu.ex.ipPh'));
  const reason = wfInput('wf-ex-reason', '', t('wafemu.ex.reasonPh'));
  const msg = wfEl('div', null, null, 'font-size:12px;min-height:16px');
  const save = wfBtn(t('common.save'), async () => {
    const ex = { id: 'ex' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), rule: parseInt(ruleSel.value, 10),
      vhost: vh.value.trim(), pathPrefix: path.value.trim(), uaContains: ua.value.trim(), ip: ip.value.trim(),
      reason: reason.value.trim(), createdAt: new Date().toISOString() };
    Object.keys(ex).forEach(k => { if (ex[k] === '') delete ex[k]; });
    if (!Number.isInteger(ex.rule) || ex.rule <= 0) { wfMsg(msg, t('wafemu.ex.ruleRequired'), false); return; }
    wfMsg(msg, t('common.loading'), null);
    const r = await wfSaveSettings(s => { s.exceptions = (s.exceptions || []).concat([ex]); });
    if (r.error) { wfMsg(msg, r.error, false); return; }
    wfModalClose();
    if (['rules', 'overview', 'exceptions', 'settings'].includes(WF.tab)) wfTab(WF.tab);
  }, 'primary');
  const cancel = wfBtn(t('common.cancel'), wfModalClose);
  wfModalOpen(t('wafemu.ex.title'), [
    wfEl('div', t('wafemu.ex.help'), 'nf-hint'),
    wfField(t('wafemu.col.rule'), ruleSel),
    wfField(t('wafemu.col.vhost'), vh, t('wafemu.ex.vhostHint')),
    wfField(t('wafemu.ex.pathPrefix'), path, t('wafemu.ex.pathHint')),
    wfField(t('wafemu.ex.ua'), ua),
    wfField(t('wafemu.col.ip'), ip),
    wfField(t('wafemu.ex.reason'), reason),
    msg,
  ], [cancel, save]);
}

// ── Onglet Regles ────────────────────────────────────────────────────────────
async function wfRenderRules(box) {
  if (!WF.categories) {
    const c = await api('/waf/rules/categories');
    WF.categories = c && c.categories ? c.categories : [];
  }
  const rf = WF.ruleFilters;
  const bar = wfEl('div', null, 'bl-filters');
  const q = wfInput('wf-r-q', rf.q, t('wafemu.rules.search')); q.className = 'inp bl-f-ip';
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') applyRuleFilters(); });
  bar.appendChild(q);
  const cat = wfSelect('wf-r-cat', [['', t('wafemu.rules.allCategories')]].concat(WF.categories.map(c => [c.key, c.label + ' (' + c.rules + ')'])), rf.category);
  cat.className = 'inp bl-f-sel';
  bar.appendChild(cat);
  const st = wfSelect('wf-r-state', [['', t('wafemu.rules.allStates')], ['active', t('wafemu.rstate.active')], ['disabled_global', t('wafemu.rstate.disabled_global')],
    ['disabled_system', t('wafemu.rstate.disabled_system')], ['ignored', t('wafemu.rstate.ignored')]], rf.state);
  st.className = 'inp bl-f-sel';
  bar.appendChild(st);
  function applyRuleFilters() {
    WF.ruleFilters = { q: wfGet('wf-r-q').value.trim(), category: wfGet('wf-r-cat').value, state: wfGet('wf-r-state').value };
    WF.rulesOffset = 0;
    wfTab('rules');
  }
  bar.appendChild(wfBtn(t('wafemu.filter.apply'), applyRuleFilters));
  box.appendChild(bar);
  box.appendChild(wfEl('div', t('wafemu.rules.help'), 'nf-hint', 'margin-bottom:8px'));

  const p = new URLSearchParams({ limit: String(WF_RULES_PAGE), offset: String(WF.rulesOffset) });
  if (rf.q) p.set('q', rf.q);
  if (rf.category) p.set('category', rf.category);
  if (rf.state) p.set('state', rf.state);
  const d = await api('/waf/rules?' + p.toString());
  if (!d || d.error || d.reachable === false) { box.appendChild(wfEl('div', d && d.error ? d.error : t('wafemu.err.unreachable'), null, 'color:var(--amber)')); return; }
  WF.rulesTotal = d.total || 0;
  const rows = (d.rules || []).map(r => {
    const state = wfEl('span');
    if (r.state === 'disabled_system') state.appendChild(wfBadge(t('wafemu.rstate.system'), 'bl', t('wafemu.rstate.systemHelp')));
    else if (r.state === 'disabled_global') state.appendChild(wfBadge(t('wafemu.rstate.disabled_global'), 'am'));
    else if (r.state === 'ignored') state.appendChild(wfBadge(t('wafemu.rstate.ignored'), 'rd', t('wafemu.rstate.ignoredHelp')));
    else state.appendChild(wfBadge(t('wafemu.rstate.active'), 'gn'));
    if ((r.disabledVhosts || []).length) { state.appendChild(document.createTextNode(' ')); state.appendChild(wfBadge(t('wafemu.rules.nVhosts', { n: r.disabledVhosts.length }), 'gy', r.disabledVhosts.join(', '))); }
    if (r.exceptions) { state.appendChild(document.createTextNode(' ')); state.appendChild(wfBadge(t('wafemu.rules.nExceptions', { n: r.exceptions }), 'gy')); }
    const act = wfEl('span', null, null, 'display:flex;gap:4px;flex-wrap:wrap');
    if (wfCan() && r.state !== 'disabled_system' && r.state !== 'ignored') {
      if (r.state === 'disabled_global') act.appendChild(wfBtn(t('wafemu.rules.enable'), () => wfToggleRule(r.id, false)));
      else act.appendChild(wfBtn(t('wafemu.rules.disableGlobal'), () => { if (confirm(t('wafemu.rules.confirmDisable', { id: r.id }))) wfToggleRule(r.id, true); }));
      act.appendChild(wfBtn(t('wafemu.rules.disableVhost'), () => wfRuleVhostModal(r.id)));
      act.appendChild(wfBtn(t('wafemu.rules.exception'), () => wfExceptionModal({ rule: r.id, rules: [{ id: r.id, msg: r.msg }] })));
    }
    return [String(r.id), wfShort(r.msg, 80), r.category || '', wfBadge(r.severity || '', r.severity === 'CRITICAL' ? 'rd' : r.severity === 'ERROR' ? 'am' : 'gy'),
      String(r.paranoia || 1), wfNum(r.hits7d), state, act];
  });
  box.appendChild(wfTable([t('wafemu.col.rule'), t('wafemu.col.message'), t('wafemu.col.category'), t('wafemu.col.severity'), t('wafemu.col.paranoia'),
    t('wafemu.col.hits7d'), t('wafemu.col.state'), ''], rows, t('wafemu.rules.none')));
  box.appendChild(wfPager(WF.rulesOffset, WF_RULES_PAGE, WF.rulesTotal, (off) => { WF.rulesOffset = off; wfTab('rules'); }));
}

async function wfToggleRule(id, disable) {
  const r = await wfSaveSettings(s => {
    const set = new Set(s.disabledRules || []);
    if (disable) set.add(id); else set.delete(id);
    s.disabledRules = [...set].sort((a, b) => a - b);
  });
  if (r.error) { alert(t('common.error') + ' : ' + r.error); return; }
  wfTab('rules');
}

async function wfRuleVhostModal(ruleId) {
  const vhosts = await wfLoadVhosts(true);
  const sel = wfSelect('wf-rv-vhost', vhosts.map(v => [v.name, v.name]), '');
  const msg = wfEl('div', null, null, 'font-size:12px;min-height:16px');
  const save = wfBtn(t('common.save'), async () => {
    const name = sel.value;
    if (!name) return;
    const r = await wfSaveSettings(s => {
      s.vhosts = s.vhosts || {};
      const v = s.vhosts[name] = s.vhosts[name] || {};
      v.disabledRules = [...new Set((v.disabledRules || []).concat([ruleId]))].sort((a, b) => a - b);
    });
    if (r.error) { wfMsg(msg, r.error, false); return; }
    wfModalClose();
    wfTab('rules');
  }, 'primary');
  wfModalOpen(t('wafemu.rules.vhostTitle', { id: ruleId }), [
    wfEl('div', t('wafemu.rules.vhostHelp'), 'nf-hint'),
    wfField(t('wafemu.col.vhost'), sel), msg,
  ], [wfBtn(t('common.cancel'), wfModalClose), save]);
}

// ── Onglet Vhosts ────────────────────────────────────────────────────────────
async function wfRenderVhosts(box) {
  const [settings, vhosts] = [await wfFetchSettings(), await wfLoadVhosts(true)];
  if (!settings) { box.appendChild(wfEl('div', t('wafemu.err.unreachable'), null, 'color:var(--amber)')); return; }
  box.appendChild(wfEl('div', t('wafemu.vh.help'), 'nf-hint', 'margin-bottom:10px'));

  const top = wfEl('div', null, null, 'display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px');
  top.appendChild(wfField(t('wafemu.vh.scope'), wfSelect('wf-vh-scope', [['all', t('wafemu.vh.scopeAll')], ['selected', t('wafemu.vh.scopeSelected')]], settings.vhostMode || 'all')));
  top.appendChild(wfField(t('wafemu.vh.globalMode'), wfSelect('wf-vh-gmode', [['observe', t('wafemu.mode.observe')], ['remediate', t('wafemu.mode.remediate')]], settings.mode || 'observe')));
  top.appendChild(wfField(t('wafemu.vh.globalParanoia'), wfSelect('wf-vh-gpar', [1, 2, 3, 4].map(n => [n, String(n)]), settings.paranoia || 1)));
  box.appendChild(top);

  const overrides = settings.vhosts || {};
  const rows = vhosts.map((v, i) => {
    const o = overrides[v.name] || {};
    const chk = wfEl('input'); chk.type = 'checkbox'; chk.id = 'wf-vh-a-' + i; chk.checked = v.analyzed !== false && v.analyzed !== null ? !!v.analyzed : true;
    chk.disabled = !wfCan();
    const mode = wfSelect('wf-vh-m-' + i, [['', t('wafemu.vh.inherit')], ['observe', t('wafemu.mode.observe')], ['remediate', t('wafemu.mode.remediate')]], o.mode || '');
    const par = wfSelect('wf-vh-p-' + i, [['', t('wafemu.vh.inherit')]].concat([1, 2, 3, 4].map(n => [n, String(n)])), o.paranoia || '');
    mode.disabled = par.disabled = !wfCan();
    const name = wfEl('span');
    name.appendChild(document.createTextNode(v.name));
    if (v.seen === false) { name.appendChild(document.createTextNode(' ')); name.appendChild(wfBadge(t('wafemu.vh.noLog'), 'am', t('wafemu.vh.noLogHelp'))); }
    return [chk, name, wfNum(v.lines), wfNum(v.hits24h), wfTime(v.lastSeen ? Date.parse(v.lastSeen) || v.lastSeen : 0), v.format || '—', mode, par];
  });
  box.appendChild(wfTable([t('wafemu.vh.analyzed'), t('wafemu.col.vhost'), t('wafemu.vh.lines'), t('wafemu.col.hits24'), t('wafemu.vh.lastSeen'),
    t('wafemu.vh.format'), t('wafemu.col.mode'), t('wafemu.col.paranoia')], rows, t('wafemu.vh.none')));

  const msg = wfEl('div', null, null, 'font-size:12px;min-height:16px;margin-top:8px');
  if (wfCan()) {
    const bar = wfEl('div', null, null, 'margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap');
    bar.appendChild(wfBtn(t('wafemu.save'), () => wfSaveVhosts(settings, vhosts, msg), 'primary'));
    bar.appendChild(msg);
    box.appendChild(bar);
  }
}

async function wfSaveVhosts(before, vhosts, msg) {
  const scope = wfGet('wf-vh-scope').value;
  const gmode = wfGet('wf-vh-gmode').value;
  const gpar = parseInt(wfGet('wf-vh-gpar').value, 10);
  const selected = scope === 'selected';
  const next = {};
  const newlyRemediate = [];
  vhosts.forEach((v, i) => {
    const analyze = wfGet('wf-vh-a-' + i).checked;
    const mode = wfGet('wf-vh-m-' + i).value;
    const par = wfGet('wf-vh-p-' + i).value;
    const prev = (before.vhosts || {})[v.name] || {};
    const o = {};
    if (prev.disabledRules && prev.disabledRules.length) o.disabledRules = prev.disabledRules;
    // `analyze` n'est ecrit que s'il differe du defaut du perimetre (all : analyse sauf refus ; selected : refus sauf choix)
    if (selected ? analyze : !analyze) o.analyze = analyze;
    if (mode) o.mode = mode;
    if (par) o.paranoia = parseInt(par, 10);
    const effBefore = prev.mode || before.mode || 'observe';
    const effAfter = mode || gmode;
    if (effAfter === 'remediate' && effBefore !== 'remediate') newlyRemediate.push(v.name);
    if (Object.keys(o).length) next[v.name] = o;
  });
  // Les vhosts de la config avec des surcharges mais absents de la liste (ex. supprimes) sont conserves tels quels.
  Object.keys(before.vhosts || {}).forEach(n => { if (!vhosts.some(v => v.name === n)) next[n] = before.vhosts[n]; });
  if ((gmode === 'remediate' && (before.mode || 'observe') !== 'remediate') || newlyRemediate.length) {
    const names = gmode === 'remediate' && (before.mode || 'observe') !== 'remediate' ? t('wafemu.scopeGlobal') : newlyRemediate.join(', ');
    if (!confirm(t('wafemu.confirmRemediate', { scope: names }))) return;
  }
  wfMsg(msg, t('common.loading'), null);
  const r = await wfSaveSettings(s => { s.vhostMode = scope; s.mode = gmode; s.paranoia = gpar; s.vhosts = next; });
  if (r.error) { wfMsg(msg, r.error, false); return; }
  wfMsg(msg, t('common.saveSuccess'), true);
  WF.vhosts = null;
}

// ── Aide remediation (challenge vs block) ───────────────────────────────────
async function wfHelpModal() {
  const s = await wfFetchSettings().catch(() => null);
  const th = (s && s.thresholds) || {}, lh = (s && s.listHours) || {};
  const v = {
    thc: th.challenge != null ? th.challenge : 10, thb: th.block != null ? th.block : 25,
    lhc: lh.challenge != null ? lh.challenge : 24, lhb: lh.block != null ? lh.block : 72,
    window: s && s.windowMinutes != null ? s.windowMinutes : 60,
  };
  const body = [];
  const cur = wfEl('div', t('wafemu.help.current', v), 'nf-hint', 'margin:8px 0');
  body.push(cur);
  [['how', null], ['challenge', 'var(--amber)'], ['block', 'var(--red)'], ['limits', null], ['advice', null]].forEach(([k, color]) => {
    const box = wfEl('div', null, null, 'margin:10px 0;padding-left:10px;' + (color ? 'border-left:3px solid ' + color : 'border-left:3px solid var(--border2)'));
    box.appendChild(wfEl('div', t('wafemu.help.' + k + '.t', v), null, 'font-weight:600;margin-bottom:3px'));
    box.appendChild(wfEl('div', t('wafemu.help.' + k + '.b', v), null, 'font-size:12px;color:var(--text2);line-height:1.6;white-space:pre-line'));
    body.push(box);
  });
  wfModalOpen(t('wafemu.help.title'), body, [wfBtn(t('common.close'), wfModalClose)]);
  const mb = wfGet('wf-modal-box'); if (mb) { mb.style.maxHeight = '85vh'; mb.style.overflowY = 'auto'; }
}

// ── Onglet Listes ────────────────────────────────────────────────────────────
async function wfRenderLists(box) {
  const link = wfEl('a', t('wafemu.lists.openBlocklists'), null, 'font-size:12px;cursor:pointer');
  link.addEventListener('click', (e) => { e.preventDefault(); openPage('blocklists'); });
  box.appendChild(wfEl('div', t('wafemu.lists.help'), 'nf-hint', 'margin-bottom:4px'));
  box.appendChild(wfBtn(t('wafemu.help.btn'), wfHelpModal)).style.marginBottom = '8px';
  box.appendChild(wfEl('div', null, null, 'margin-bottom:12px')).appendChild(link);
  for (const list of ['challenge', 'block']) {
    const d = await api('/waf/lists?list=' + list);
    const sec = wfSection(t('wafemu.lists.' + list) + (d && d.count != null ? ' (' + d.count + ')' : ''));
    if (!d || d.reachable === false || d.error) { sec.appendChild(wfEl('div', t('wafemu.err.unreachable'), null, 'color:var(--amber);font-size:12px')); box.appendChild(sec); continue; }
    const rows = (d.ips || []).map(e => {
      const act = wfEl('span');
      if (wfCan()) act.appendChild(wfBtn(t('wafemu.lists.unlist'), async () => {
        if (!confirm(t('wafemu.lists.confirmUnlist', { ip: e.ip }))) return;
        const r = await api('/waf/lists/unlist', { method: 'POST', body: JSON.stringify({ ip: e.ip, list }) });
        if (!r || r.error) { alert(t('common.error') + ' : ' + wfErr(r)); return; }
        wfTab('lists');
      }));
      const proof = wfBtn(t('wafemu.proof.btn'), () => wfProofModal(e, list));
      const wrap = wfEl('span', null, null, 'display:inline-flex;gap:6px;flex-wrap:wrap');
      wrap.appendChild(proof); wrap.appendChild(act);
      return [e.ip, wfNum(e.score), wfNum(e.hits), wfTime(e.since), wfTime(e.until), (e.vhosts || []).join(', '), (e.topRules || []).join(', '), wfAppBadge(e.application), wrap];
    });
    sec.appendChild(wfTable([t('wafemu.col.ip'), t('wafemu.col.score'), t('wafemu.col.hits'), t('wafemu.lists.since'), t('wafemu.lists.until'),
      t('wafemu.col.vhost'), t('wafemu.col.rules'), t('wafemu.lists.application'), ''], rows, t('wafemu.lists.empty')));
    box.appendChild(sec);
  }
}

/** Etat d'application d'une IP par les Blocklists (champ `application` ajoute par le dashboard). */
function wfAppBadge(app) {
  if (!app || !app.state) return wfEl('span', '—');
  const cls = app.state === 'applied' ? 'gn' : (app.state === 'pending' ? 'gy' : 'am');
  return wfBadge(t('wafemu.app.' + app.state), cls, t('wafemu.app.' + app.state + 'Help') + (app.detail ? ' — ' + app.detail : ''));
}

// ── Modale « Preuves » : pourquoi cette IP est listee, et appliquee ou non ──────
async function wfProofModal(entry, list) {
  const body = [];
  const kv = (k, v) => { const r = wfEl('div', null, null, 'font-size:12px;margin:2px 0'); r.appendChild(wfEl('b', k + ' : ')); r.appendChild(v instanceof Node ? v : document.createTextNode(String(v))); return r; };
  const h = (txt) => wfEl('div', txt, 'ctitle', 'margin:12px 0 4px;font-size:13px');
  body.push(kv(t('wafemu.col.ip'), entry.ip));
  body.push(kv(t('wafemu.proof.list'), t('wafemu.lists.' + list)));
  body.push(kv(t('wafemu.col.score'), wfNum(entry.score)));
  body.push(kv(t('wafemu.col.hits'), wfNum(entry.hits)));
  body.push(kv(t('wafemu.lists.since'), wfTime(entry.since)));
  body.push(kv(t('wafemu.lists.until'), wfTime(entry.until)));
  body.push(kv(t('wafemu.col.vhost'), (entry.vhosts || []).join(', ') || '—'));
  body.push(h(t('wafemu.proof.application')));
  const app = entry.application;
  if (app && app.state) {
    const line = wfEl('div', null, null, 'font-size:12px');
    line.appendChild(wfAppBadge(app));
    line.appendChild(document.createTextNode(' ' + t('wafemu.app.' + app.state + 'Help') + (app.detail ? ' (' + app.detail + ')' : '')));
    body.push(line);
    if (app.sources && app.sources.length) body.push(kv(t('wafemu.proof.sources'), app.sources.join(', ')));
  } else body.push(wfEl('div', '—', null, 'font-size:12px'));
  const holder = wfEl('div', t('common.loading'), null, 'font-size:12px;color:var(--text3)');
  body.push(holder);
  const close = wfBtn(t('common.close'), wfModalClose);
  wfModalOpen(t('wafemu.proof.title', { ip: entry.ip }), body, [close]);
  const box = wfGet('wf-modal-box');
  box.style.maxHeight = '85vh'; box.style.overflowY = 'auto';

  const [hd, ad] = await Promise.all([
    api('/waf/hits?' + new URLSearchParams({ ip: entry.ip, limit: '100', order: 'desc' }).toString()),
    api('/waf/alerts?' + new URLSearchParams({ limit: '200', order: 'desc', raw: '1' }).toString()),
  ]);
  holder.textContent = '';
  const hits = hd && Array.isArray(hd.hits) ? hd.hits : [];
  // Regles agregees sur les derniers hits
  const agg = new Map();
  hits.forEach(x => (x.rules || []).forEach(r => {
    const a = agg.get(r.id) || { id: r.id, msg: r.msg, count: 0, data: r.data };
    a.count++; agg.set(r.id, a);
  }));
  holder.appendChild(h(t('wafemu.proof.rules')));
  holder.appendChild(wfTable([t('wafemu.col.rules'), t('wafemu.proof.message'), t('wafemu.proof.count')],
    [...agg.values()].sort((a, b) => b.count - a.count).slice(0, 15).map(a => [String(a.id), wfShort(a.msg, 90), String(a.count)]), t('wafemu.proof.noHits')));
  holder.appendChild(h(t('wafemu.proof.hits', { n: hits.length })));
  holder.appendChild(wfTable([t('wafemu.col.time'), t('wafemu.col.vhost'), t('wafemu.col.request'), t('wafemu.col.status'), t('wafemu.col.score'), t('wafemu.col.rules')],
    hits.slice(0, 20).map(x => {
      const uri = wfEl('code', (x.method || '') + ' ' + wfShort(x.uri, 70), null, 'font-size:11px'); uri.title = x.uri || '';
      return [wfTime(x.ts), x.vhost || '', uri, String(x.status || ''), String(x.score), (x.rules || []).map(r => r.id).join(', ')];
    }), t('wafemu.proof.noHits')));
  // Derniere alerte de cette IP : elements de preuve agreges par le scoring
  const al = ((ad && ad.alerts) || []).find(a => a.ip === entry.ip && a.evidence);
  if (al) {
    const ev = al.evidence;
    holder.appendChild(h(t('wafemu.proof.alert')));
    holder.appendChild(kv(t('wafemu.col.time'), wfTime(al.ts)));
    holder.appendChild(kv(t('wafemu.proof.severity'), al.severity || '—'));
    holder.appendChild(kv(t('wafemu.col.score'), String(ev.score) + ' / ' + t('wafemu.proof.requests', { n: ev.requests, m: ev.windowMinutes })));
    if ((ev.paths || []).length) holder.appendChild(kv(t('wafemu.proof.paths'), ev.paths.slice(0, 8).join(', ')));
    if ((ev.userAgents || []).length) holder.appendChild(kv(t('wafemu.proof.agents'), ev.userAgents.slice(0, 4).join(' | ')));
    if (ev.statuses) holder.appendChild(kv(t('wafemu.col.status'), Object.keys(ev.statuses).map(k => k + '×' + ev.statuses[k]).join(', ')));
    if ((ev.categories || []).length) holder.appendChild(kv(t('wafemu.proof.categories'), ev.categories.join(', ')));
  }
}

// ── Onglet Reglages ──────────────────────────────────────────────────────────
async function wfRenderSettings(box) {
  const s = await wfFetchSettings();
  if (!s) { box.appendChild(wfEl('div', t('wafemu.err.unreachable'), null, 'color:var(--amber)')); return; }
  const th = s.thresholds || {};
  const lh = s.listHours || {};
  const can = wfCan();
  const grid = wfEl('div', null, null, 'display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px');
  const add = (label, input, hint) => grid.appendChild(wfField(label, input, hint));
  const en = wfEl('input'); en.type = 'checkbox'; en.id = 'wf-s-enable'; en.checked = s.enable !== false;
  add(t('wafemu.set.enable'), en, t('wafemu.set.enableHint'));
  add(t('wafemu.set.mode'), wfSelect('wf-s-mode', [['observe', t('wafemu.mode.observe')], ['remediate', t('wafemu.mode.remediate')]], s.mode || 'observe'), t('wafemu.set.modeHint'));
  add(t('wafemu.set.paranoia'), wfSelect('wf-s-par', [1, 2, 3, 4].map(n => [n, String(n)]), s.paranoia || 1), t('wafemu.set.paranoiaHint'));
  add(t('wafemu.set.thChallenge'), wfInput('wf-s-thc', th.challenge, '10', 'number'), t('wafemu.set.thHint'));
  add(t('wafemu.set.thBlock'), wfInput('wf-s-thb', th.block, '25', 'number'));
  add(t('wafemu.set.window'), wfInput('wf-s-win', s.windowMinutes, '60', 'number'), t('wafemu.set.windowHint'));
  add(t('wafemu.set.lhChallenge'), wfInput('wf-s-lhc', lh.challenge, '24', 'number'), t('wafemu.set.lhHint'));
  add(t('wafemu.set.lhBlock'), wfInput('wf-s-lhb', lh.block, '72', 'number'));
  add(t('wafemu.set.alertMin'), wfInput('wf-s-alert', s.alertMinScore, '10', 'number'), t('wafemu.set.alertMinHint'));
  add(t('wafemu.set.ignoreStatus'), wfInput('wf-s-ign', (s.ignoreStatus || []).join(', '), '444, 403'), t('wafemu.set.ignoreStatusHint'));
  box.appendChild(grid);
  const ex = wfEl('textarea', null, 'inp'); ex.id = 'wf-s-excl'; ex.rows = 4; ex.value = (s.excludeIps || []).join('\n');
  ex.style.fontFamily = 'monospace';
  box.appendChild(wfEl('div', null, null, 'margin-top:12px')).appendChild(wfField(t('wafemu.set.excludeIps'), ex, t('wafemu.set.excludeIpsHint')));

  const msg = wfEl('div', null, null, 'font-size:12px;min-height:16px');
  if (can) {
    const bar = wfEl('div', null, null, 'margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap');
    bar.appendChild(wfBtn(t('wafemu.save'), () => wfSaveSettingsForm(s, msg), 'primary'));
    bar.appendChild(msg);
    box.appendChild(bar);
  }
  const exLink = wfEl('div', null, 'nf-hint', 'margin-top:8px');
  exLink.appendChild(document.createTextNode(t('wafemu.set.exceptionsInfo', { n: (s.exceptions || []).length }) + ' '));
  exLink.appendChild(wfBtn(t('wafemu.ex.seeTab'), () => wfTab('exceptions')));
  box.appendChild(exLink);

  // Regles personnalisees (SecRule) : validees par le moteur, ancien fichier conserve en cas d'erreur
  const cr = await api('/waf/custom-rules');
  const crSec = wfSection(t('wafemu.cr.title'));
  crSec.style.marginTop = '22px';
  crSec.appendChild(wfEl('div', t('wafemu.cr.help'), 'nf-hint', 'margin-bottom:6px'));
  const ta = wfEl('textarea', null, 'inp'); ta.id = 'wf-cr-text'; ta.rows = 10; ta.value = cr && cr.text ? cr.text : '';
  ta.style.fontFamily = 'monospace'; ta.spellcheck = false;
  crSec.appendChild(ta);
  const crMsg = wfEl('pre', null, null, 'font-size:11px;white-space:pre-wrap;word-break:break-word;margin:6px 0 0;min-height:16px');
  if (can) {
    const bar = wfEl('div', null, null, 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap');
    bar.appendChild(wfBtn(t('wafemu.cr.save'), async () => {
      wfMsg(crMsg, t('common.loading'), null);
      const r = await api('/waf/custom-rules', { method: 'PUT', body: JSON.stringify({ text: ta.value }) });
      if (!r || r.error) { wfMsg(crMsg, wfErr(r), false); return; }
      wfMsg(crMsg, t('wafemu.cr.saved'), true);
    }, 'primary'));
    crSec.appendChild(bar);
  }
  crSec.appendChild(crMsg);
  box.appendChild(crSec);
}

/** Libelle d'une regle (id — message) : une requete par id distinct, mise en cache dans WF.ruleMsgs. */
async function wfRuleMsgs(ids) {
  WF.ruleMsgs = WF.ruleMsgs || {};
  const missing = [...new Set(ids)].filter(id => WF.ruleMsgs[id] === undefined).slice(0, 40);
  await Promise.all(missing.map(async id => {
    const d = await api('/waf/rules?limit=5&q=' + encodeURIComponent(String(id)));
    const hit = d && d.rules ? d.rules.find(r => r.id === id) : null;
    WF.ruleMsgs[id] = hit ? hit.msg : '';
  }));
  return WF.ruleMsgs;
}

async function wfRenderExceptions(box) {
  const s = await wfFetchSettings();
  if (!s) { box.appendChild(wfEl('div', t('wafemu.err.unreachable'), null, 'color:var(--amber)')); return; }
  const exs = s.exceptions || [];
  const globals = s.disabledRules || [];
  const perVhost = [];
  Object.keys(s.vhosts || {}).sort().forEach(v => ((s.vhosts[v] || {}).disabledRules || []).forEach(id => perVhost.push([v, id])));
  const msgs = await wfRuleMsgs(exs.map(e => e.rule).concat(globals, perVhost.map(x => x[1])));
  const label = (id) => String(id) + (msgs[id] ? ' — ' + wfShort(msgs[id], 70) : '');
  const can = wfCan();
  const done = async (r) => { if (r.error) { alert(t('common.error') + ' : ' + r.error); return; } wfTab('exceptions'); };

  box.appendChild(wfEl('div', t('wafemu.exs.help'), 'nf-hint', 'margin-bottom:10px'));

  // 1) Exceptions ciblees
  const addBtn = can ? wfBtn(t('wafemu.exs.add'), () => wfExceptionModal({ rules: null, rule: null })) : null;
  const sec1 = wfSection(t('wafemu.exs.targeted') + ' (' + exs.length + ')', addBtn);
  const rows1 = exs.map(e => {
    const act = wfEl('span');
    if (can) act.appendChild(wfBtn(t('wafemu.ex.remove'), async () => {
      if (!confirm(t('wafemu.ex.confirmRemove', { id: e.rule }))) return;
      await done(await wfSaveSettings(n => { n.exceptions = (n.exceptions || []).filter(x => x.id !== e.id); }));
    }, 'danger'));
    return [label(e.rule), e.vhost || t('wafemu.exs.allVhosts'), e.pathPrefix || '*', e.uaContains || '', e.ip || '', e.reason || '',
      e.createdAt ? String(e.createdAt).slice(0, 10) : '', act];
  });
  sec1.appendChild(wfTable([t('wafemu.col.rule'), t('wafemu.col.vhost'), t('wafemu.ex.pathPrefix'), t('wafemu.ex.ua'), t('wafemu.col.ip'),
    t('wafemu.ex.reason'), t('wafemu.exs.created'), ''], rows1, t('wafemu.ex.none')));
  box.appendChild(sec1);

  // 2) Regles desactivees globalement
  const sec2 = wfSection(t('wafemu.exs.global') + ' (' + globals.length + ')');
  const rows2 = globals.map(id => {
    const act = wfEl('span');
    if (can) act.appendChild(wfBtn(t('wafemu.rules.enable'), async () => { await done(await wfSaveSettings(n => { n.disabledRules = (n.disabledRules || []).filter(x => x !== id); })); }));
    return [label(id), act];
  });
  sec2.appendChild(wfTable([t('wafemu.col.rule'), ''], rows2, t('wafemu.exs.noneGlobal')));
  box.appendChild(sec2);

  // 3) Regles desactivees pour un vhost
  const sec3 = wfSection(t('wafemu.exs.vhost') + ' (' + perVhost.length + ')');
  const rows3 = perVhost.map(([v, id]) => {
    const act = wfEl('span');
    if (can) act.appendChild(wfBtn(t('wafemu.rules.enable'), async () => {
      await done(await wfSaveSettings(n => { if (n.vhosts && n.vhosts[v]) n.vhosts[v].disabledRules = (n.vhosts[v].disabledRules || []).filter(x => x !== id); }));
    }));
    return [v, label(id), act];
  });
  sec3.appendChild(wfTable([t('wafemu.col.vhost'), t('wafemu.col.rule'), ''], rows3, t('wafemu.exs.noneVhost')));
  box.appendChild(sec3);
}

function wfIntOrNull(id) {
  const v = wfGet(id).value.trim();
  return v === '' ? null : (/^\d+$/.test(v) ? parseInt(v, 10) : NaN);
}

async function wfSaveSettingsForm(before, msg) {
  const mode = wfGet('wf-s-mode').value;
  const thc = wfIntOrNull('wf-s-thc'), thb = wfIntOrNull('wf-s-thb'), win = wfIntOrNull('wf-s-win');
  const lhc = wfIntOrNull('wf-s-lhc'), lhb = wfIntOrNull('wf-s-lhb'), alert2 = wfIntOrNull('wf-s-alert');
  if ([thc, thb, win, lhc, lhb, alert2].some(n => Number.isNaN(n))) { wfMsg(msg, t('wafemu.set.invalidNumber'), false); return; }
  if (thc != null && thb != null && thc > thb) { wfMsg(msg, t('wafemu.set.thOrder'), false); return; }
  const ign = wfGet('wf-s-ign').value.split(/[\s,;]+/).filter(Boolean);
  if (ign.some(x => !/^\d{3}$/.test(x))) { wfMsg(msg, t('wafemu.set.invalidStatus'), false); return; }
  const excl = wfGet('wf-s-excl').value.split(/\s+/).filter(Boolean);
  if ((before.mode || 'observe') !== 'remediate' && mode === 'remediate' && !confirm(t('wafemu.confirmRemediate', { scope: t('wafemu.scopeGlobal') }))) return;
  wfMsg(msg, t('common.loading'), null);
  const r = await wfSaveSettings(s => {
    s.enable = wfGet('wf-s-enable').checked;
    s.mode = mode;
    s.paranoia = parseInt(wfGet('wf-s-par').value, 10);
    s.thresholds = Object.assign({}, s.thresholds, thc != null ? { challenge: thc } : {}, thb != null ? { block: thb } : {});
    if (win != null) s.windowMinutes = win;
    s.listHours = Object.assign({}, s.listHours, lhc != null ? { challenge: lhc } : {}, lhb != null ? { block: lhb } : {});
    if (alert2 != null) s.alertMinScore = alert2;
    s.ignoreStatus = ign.map(x => parseInt(x, 10));
    s.excludeIps = excl;
  });
  if (r.error) { wfMsg(msg, r.error, false); return; }
  wfMsg(msg, t('common.saveSuccess'), true);
}

// ── Onglet Simulateur ────────────────────────────────────────────────────────
async function wfRenderSimulator(box) {
  const vhosts = await wfLoadVhosts(false);
  box.appendChild(wfEl('div', t('wafemu.sim.help'), 'nf-hint', 'margin-bottom:10px'));
  const grid = wfEl('div', null, null, 'display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px');
  grid.appendChild(wfField(t('wafemu.sim.method'), wfSelect('wf-sim-m', ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'].map(x => [x, x]), 'GET')));
  grid.appendChild(wfField(t('wafemu.sim.uri'), wfInput('wf-sim-uri', '/?q=<script>alert(1)</script>', '/path?x=1')));
  const vh = wfInput('wf-sim-vhost', vhosts[0] ? vhosts[0].name : '', 'example.com');
  vh.setAttribute('list', 'wf-sim-vhosts');
  const dl = wfEl('datalist'); dl.id = 'wf-sim-vhosts';
  vhosts.forEach(v => { const o = wfEl('option'); o.value = v.name; dl.appendChild(o); });
  const vwrap = wfEl('div'); vwrap.appendChild(vh); vwrap.appendChild(dl);
  grid.appendChild(wfField(t('wafemu.col.vhost'), vwrap));
  grid.appendChild(wfField(t('wafemu.sim.ua'), wfInput('wf-sim-ua', '', 'sqlmap/1.7')));
  grid.appendChild(wfField(t('wafemu.col.ip'), wfInput('wf-sim-ip', '203.0.113.9', '203.0.113.9')));
  grid.appendChild(wfField(t('wafemu.sim.paranoia'), wfSelect('wf-sim-par', [['', t('wafemu.vh.inherit')]].concat([1, 2, 3, 4].map(n => [n, String(n)])), '')));
  box.appendChild(grid);
  const hd = wfEl('textarea', null, 'inp'); hd.id = 'wf-sim-headers'; hd.rows = 3; hd.style.fontFamily = 'monospace';
  hd.placeholder = 'Content-Type: application/json';
  box.appendChild(wfEl('div', null, null, 'margin-top:12px')).appendChild(wfField(t('wafemu.sim.headers'), hd, t('wafemu.sim.headersHint')));
  const out = wfEl('div', null, null, 'margin-top:14px');
  const bar = wfEl('div', null, null, 'margin-top:12px');
  if (wfCan()) bar.appendChild(wfBtn(t('wafemu.sim.run'), () => wfSimulate(out), 'primary'));
  else bar.appendChild(wfEl('div', t('wafemu.sim.needDeploy'), 'nf-hint'));
  box.appendChild(bar);
  box.appendChild(out);
}

async function wfSimulate(out) {
  const body = { method: wfGet('wf-sim-m').value, uri: wfGet('wf-sim-uri').value.trim() };
  const vhost = wfGet('wf-sim-vhost').value.trim(), ua = wfGet('wf-sim-ua').value, ip = wfGet('wf-sim-ip').value.trim();
  const par = wfGet('wf-sim-par').value;
  if (vhost) body.vhost = vhost;
  if (ua) body.ua = ua;
  if (ip) body.ip = ip;
  if (par) body.paranoia = parseInt(par, 10);
  const headers = {};
  wfGet('wf-sim-headers').value.split('\n').forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  if (Object.keys(headers).length) body.headers = headers;
  out.textContent = '';
  out.appendChild(wfEl('div', t('common.loading'), null, 'color:var(--text3);font-size:12px'));
  const r = await api('/waf/simulate', { method: 'POST', body: JSON.stringify(body) });
  out.textContent = '';
  if (!r || r.error) { out.appendChild(wfEl('div', wfErr(r), null, 'color:var(--red)')); return; }
  const grid = wfEl('div', null, 'sgrid sgrid-auto');
  grid.appendChild(wfKpi(t('wafemu.col.score'), String(r.score || 0), r.score >= 10 ? 're' : r.score ? 'am' : ''));
  grid.appendChild(wfKpi(t('wafemu.sim.wouldList'), r.wouldList ? t('wafemu.list.' + r.wouldList) : t('wafemu.sim.noList')));
  grid.appendChild(wfKpi(t('wafemu.col.mode'), t('wafemu.mode.' + (r.mode || 'observe'))));
  out.appendChild(grid);
  const rows = (r.hits || []).map(x => [String(x.id), wfShort(x.msg, 80), wfBadge(x.severity || '', x.severity === 'CRITICAL' ? 'rd' : 'gy'), String(x.score || 0),
    x.suppressed ? wfBadge(t('wafemu.sup.' + x.suppressed), 'am', t('wafemu.sup.help')) : wfBadge(t('wafemu.sim.kept'), 'gn'), wfShort(x.data, 80)]);
  const sec = wfSection(t('wafemu.sim.hits'));
  sec.style.marginTop = '14px';
  sec.appendChild(wfTable([t('wafemu.col.rule'), t('wafemu.col.message'), t('wafemu.col.severity'), t('wafemu.col.score'), t('wafemu.sim.status'), t('wafemu.sim.data')], rows, t('wafemu.sim.noHit')));
  out.appendChild(sec);
}

// ── Onglet Conseils ──────────────────────────────────────────────────────────
async function wfRenderAdvice(box) {
  const d = await api('/waf/diagnostics');
  if (!d || d.error) { box.appendChild(wfEl('div', wfErr(d), null, 'color:var(--amber)')); return; }
  const list = d.advice || [];
  if (!list.length) { box.appendChild(wfEl('div', t('wafemu.adv.none'), null, 'color:var(--text3)')); return; }
  list.forEach((a, i) => {
    const card = wfEl('div', null, null, 'border:1px solid var(--border2);border-radius:var(--r);padding:10px 12px;margin-bottom:10px');
    const head = wfEl('div', null, null, 'display:flex;gap:8px;align-items:center;margin-bottom:4px;flex-wrap:wrap');
    head.appendChild(wfBadge(t('wafemu.adv.level.' + a.level), a.level === 'warn' ? 'am' : a.level === 'ok' ? 'gn' : 'bl'));
    head.appendChild(wfEl('b', t(a.titleKey, a.vars)));
    card.appendChild(head);
    card.appendChild(wfEl('div', t(a.detailKey, a.vars), null, 'font-size:12px;color:var(--text2);line-height:1.6;white-space:pre-line'));
    if (a.snippet) {
      if (a.file) card.appendChild(wfEl('div', t('wafemu.adv.file', { file: a.file }), 'nf-hint', 'margin-top:6px'));
      const pre = wfEl('pre', a.snippet, 'ct-logout', 'height:auto;max-height:240px;margin-top:6px');
      card.appendChild(pre);
      const btn = wfBtn(t('common.copy'), async () => {
        const ok = await copyToClipboard(a.snippet);
        btn.id = 'wf-copy-' + i;
        copyFeedback(btn.id, ok);
      });
      btn.style.marginTop = '6px';
      card.appendChild(btn);
    }
    box.appendChild(card);
  });
}
