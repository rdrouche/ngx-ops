// ── NGX Ops Intelligence (v12.69.0) ────────────────────────────────────
// Carte de statut sur la page Analyse (admin). Rendu par textContent.
function intelEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function intelWhen(ms) { return ms ? new Date(ms).toLocaleString() : '—'; }

async function intelLoad() {
  const card = document.getElementById('intel-card');
  if (!card) return;
  const d = await api('/intelligence/status').catch(() => null);
  if (!d) { card.style.display = 'none'; return; } // non admin ou indisponible
  card.style.display = '';
  const st = d.state;
  document.getElementById('intel-sub').textContent = d.enabled
    ? t('intel.sub.on', { mode: t('intel.mode.' + d.mode), host: d.apiHost || '—' })
    : t('intel.sub.off');
  const grid = document.getElementById('intel-grid');
  grid.textContent = '';
  const tiles = [
    ['state', d.enabled ? (st.authError ? t('intel.state.authError') : (d.ready ? t('intel.state.on') : t('intel.state.incomplete'))) : t('intel.state.off'), d.enabled ? (st.authError || !d.ready ? 'rd' : 'gn') : ''],
    ['instance', d.instanceId.slice(0, 8) + '…', ''],
    ['ping', d.ping && d.ping.last ? (d.ping.last.ok ? t('intel.ping.ok') : t('intel.ping.fail')) : '—', d.ping && d.ping.last ? (d.ping.last.ok ? 'gn' : 'rd') : ''],
    ['lastSuccess', intelWhen(st.lastSuccessAt), ''],
    ['next', st.nextAttemptAt ? intelWhen(st.nextAttemptAt) : '—', st.nextAttemptAt ? 'am' : ''],
    ['sent', String(st.counters.sent), ''], ['accepted', String(st.counters.accepted), ''],
    ['rejected', String(st.counters.rejected + st.counters.dropped), st.counters.rejected + st.counters.dropped ? 'am' : ''],
    ['skipped', String(st.counters.skipped), ''], ['http429', String(st.counters.http429), st.counters.http429 ? 'am' : ''],
  ];
  tiles.forEach(([k, v, cls]) => {
    const sc = intelEl('div', null, 'sc' + (cls ? ' ' + cls : ''));
    sc.appendChild(intelEl('div', t('intel.k.' + k), 'sl'));
    sc.appendChild(intelEl('div', v, 'sv')).style.fontSize = '15px';
    grid.appendChild(sc);
  });
  const errs = [...(d.errors || [])];
  if (st.lastError) errs.push(t('intel.lastError', { err: st.lastError }));
  document.getElementById('intel-errors').textContent = errs.join(' ; ');
  document.getElementById('intel-send').style.display = d.enabled && d.ready ? '' : 'none';
  document.getElementById('intel-reset').style.display = st.authError || st.failures ? '' : 'none';
}

async function intelPreview() {
  const pre = document.getElementById('intel-preview');
  const r = await api('/intelligence/preview').catch(() => null);
  pre.style.display = '';
  if (!r || !r.request) { pre.textContent = t('intel.previewEmpty', { outcome: (r && r.outcome) || '—' }); return; }
  pre.textContent = 'POST ' + r.request.url + '\n' + Object.entries(r.request.headers).map(([k, v]) => k + ': ' + v).join('\n')
    + '\n\n' + JSON.stringify(r.request.body, null, 2);
}

async function intelSendNow() {
  const r = await api('/intelligence/send-now', { method: 'POST' }).catch(() => null);
  document.getElementById('intel-errors').textContent = r ? t('intel.outcome', { outcome: r.outcome, sent: r.sent }) : t('common.error');
  setTimeout(intelLoad, 800);
}

async function intelReset() {
  await api('/intelligence/reset', { method: 'POST' }).catch(() => null);
  intelLoad();
}

// intelConfigure() : formulaire de configuration, voir intelligence-config.js (#88)

// ── Ping de connexion (v12.71.0) : carte de la page Système ──────────────────
function intelPingLines(ping) {
  const rows = [];
  const kv = (k, v, cls) => rows.push([t('intel.ping.k.' + k), v, cls || '']);
  if (!ping) { kv('last', t('intel.ping.never')); return rows; }
  kv('last', intelWhen(ping.at) + ' — ' + (ping.ok ? t('intel.ping.ok') : t('intel.ping.fail')), ping.ok ? 'gn' : 'rd');
  if (ping.ok) {
    if (ping.latencyMs != null) kv('latency', ping.latencyMs + ' ms');
    if (ping.server) kv('server', [ping.server.name, ping.server.version].filter(Boolean).join(' '));
    kv('auth', ping.authenticated ? t('intel.ping.authYes') : t('intel.ping.authNo'));
    if (ping.instance) {
      kv('instance', [ping.instance.isNew ? t('intel.ping.new') : null, ping.instance.trustLevel, ping.instance.pings != null ? t('intel.ping.pings', { n: ping.instance.pings }) : null].filter(Boolean).join(' · '));
    }
    const l = ping.limits || {};
    if (l.maxAlertsPerBatch || l.batchesPerMinute) {
      kv('limits', [l.maxAlertsPerBatch ? t('intel.ping.limAlerts', { n: l.maxAlertsPerBatch }) : null, l.batchesPerMinute ? t('intel.ping.limRate', { n: l.batchesPerMinute }) : null].filter(Boolean).join(' · '));
    }
    (ping.warnings || []).forEach(w => kv('warning', w, 'am'));
  } else {
    const ck = 'intel.ping.code.' + ping.code;
    const msg = t(ck) !== ck ? t(ck) : (ping.code || '');
    kv('error', msg + (ping.detail ? ' — ' + ping.detail : '') + (ping.status ? ' (HTTP ' + ping.status + ')' : ''), 'rd');
    if (ping.nextAt) kv('next', intelWhen(ping.nextAt));
  }
  return rows;
}

function intelPingRender(d, ping) {
  const body = document.getElementById('sysinfo-intel-body');
  if (!body) return;
  body.textContent = '';
  const grid = intelEl('div', null, null);
  grid.style.cssText = 'display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:12px';
  intelPingLines(ping).forEach(([k, v, cls]) => {
    grid.appendChild(intelEl('div', k, null)).style.color = 'var(--text3)';
    const val = intelEl('div', v, null);
    if (cls === 'gn') val.style.color = 'var(--green)'; else if (cls === 'rd') val.style.color = 'var(--red)'; else if (cls === 'am') val.style.color = 'var(--amber)';
    grid.appendChild(val);
  });
  body.appendChild(grid);
  if (d && d.ping && !d.enabled) body.appendChild(intelEl('div', t('intel.ping.disabledNote'), 'nf-hint')).style.marginTop = '8px';
}

async function intelPingCard() {
  const card = document.getElementById('sysinfo-intel-card');
  if (!card) return;
  const d = await api('/intelligence/status').catch(() => null);
  if (!d || !d.ping || !d.ping.url) { card.style.display = 'none'; return; } // non admin ou non configure
  card.style.display = '';
  const sub = document.getElementById('sysinfo-intel-sub');
  sub.textContent = d.ping.enabled
    ? t('intel.ping.sub', { url: d.ping.url, min: d.ping.intervalMinutes })
    : t('intel.ping.subOff', { url: d.ping.url });
  document.getElementById('sysinfo-intel-ping-btn').disabled = !d.ping.canTest;
  intelPingRender(d, d.ping.last);
}

async function intelPingTest() {
  const btn = document.getElementById('sysinfo-intel-ping-btn');
  const body = document.getElementById('sysinfo-intel-body');
  if (btn) btn.disabled = true;
  if (body) body.textContent = t('intel.ping.testing');
  const r = await api('/intelligence/ping', { method: 'POST' }).catch(() => null);
  if (btn) btn.disabled = false;
  if (!r || r.error) { if (body) body.textContent = t('common.error') + (r && r.error ? ' : ' + r.error : ''); return; }
  if (r.busy) { if (body) body.textContent = t('intel.ping.testing'); return; }
  intelPingCard();
}
