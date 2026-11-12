// ── Page « Journaux » (v12.80.0) ───────────────────────────────────────────────
// Lecture du log store (recherche, statistiques, fiche IP) et état / pilotage du shipper.
// Les secrets (jetons) ne transitent jamais par le navigateur : tout passe par /api/logstore/*.
// Aucun innerHTML avec des valeurs serveur : tout passe par textContent.

let lsCursor = null;
let lsParams = null;
let lsTabName = 'search';

function lsEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function lsA(text) { const a = lsEl('a', text); a.href = '#'; a.style.color = 'var(--blue)'; a.style.textDecoration = 'underline'; return a; }
function lsSet(id, text, color) {
  const e = document.getElementById(id);
  if (!e) return;
  e.textContent = text;
  e.style.color = color || '';
}
function lsRow(box, label, value, color) {
  const row = lsEl('div');
  row.appendChild(lsEl('span', label + ' : '));
  const v = lsEl('strong', value);
  if (color) v.style.color = color;
  row.appendChild(v);
  box.appendChild(row);
}
function lsNum(n) { return n == null ? '—' : Number(n).toLocaleString(); }
function lsBytes(n) {
  if (n == null) return '—';
  const u = ['o', 'Kio', 'Mio', 'Gio', 'Tio']; let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i ? v.toFixed(1) : String(v)) + ' ' + u[i];
}
function lsTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleString();
}
function lsErr(d, fallback) {
  if (!d) return t('logstore.err.unreachable');
  const key = 'logstore.err.' + (d.error || fallback || 'unreachable');
  const m = t(key);
  return m === key ? (d.error || fallback || '') : m;
}

// ── Statut ─────────────────────────────────────────────────────────────────────
async function logstoreLoad() {
  const d = await api('/logstore/status').catch(() => null);
  if (!d) return;
  lsStatusLast = d;
  const green = 'var(--green)', red = 'var(--red)', amber = 'var(--amber, #d98e04)';
  const readOk = d.read && !d.read.blockers.length;
  document.getElementById('ls-off').style.display = readOk || (d.shipper && d.shipper.enabled) ? 'none' : '';
  document.getElementById('ls-main').style.display = readOk || (d.shipper && d.shipper.enabled) ? 'flex' : 'none';
  lsSet('ls-errors', (d.errors || []).join(' ; '));

  // Log store
  const st = document.getElementById('ls-store');
  st.textContent = '';
  if (!readOk) {
    lsSet('ls-k-store', t('logstore.k.notConfigured'), amber);
    const why = (d.read.blockers || []).map(b => t('logstore.blocker.' + b)).join(' ; ');
    st.appendChild(lsEl('div', why));
  } else if (!d.store || !d.store.reachable) {
    lsSet('ls-k-store', t('logstore.k.down'), red);
    lsRow(st, t('logstore.url'), d.read.url);
    lsRow(st, t('logstore.err.label'), lsErr(d.store, 'unreachable'), red);
  } else {
    lsSet('ls-k-store', t('logstore.k.up'), green);
    const x = d.store.detail || {};
    lsRow(st, t('logstore.url'), d.read.url);
    // /v1/health ne détaille (version, taille, rétention…) que pour un jeton read valide et sans périmètre.
    if (!d.store.detail) lsRow(st, t('logstore.err.label'), t('logstore.noDetail'), amber);
    lsRow(st, t('logstore.version'), String(d.store.version || '—'));
    lsRow(st, t('logstore.timescale'), x.timescale ? t('common.yes') : t('logstore.timescaleNo'), x.timescale ? green : amber);
    lsRow(st, t('logstore.size'), lsBytes(x.db_size_bytes));
    lsRow(st, t('logstore.lastIngest'), lsTime(x.last_ingest));
    lsRow(st, t('logstore.retention'), x.retention_days != null ? x.retention_days + ' ' + t('logstore.days') : '—');
    lsRow(st, t('logstore.ipMode'), String(x.ip_mode || '—'));
  }

  // Shipper
  const sh = d.shipper || {};
  const box = document.getElementById('ls-shipper');
  box.textContent = '';
  if (!sh.enabled) {
    lsSet('ls-k-shipper', t('logstore.k.external'), '');
    box.appendChild(lsEl('div', t('logstore.shipper.off', { file: d.configFile || 'logstore.yml' })));
  } else {
    const c = sh.container || {};
    let msg, color, short;
    if (c.dockerUnavailable) { msg = t('logstore.dockerDown'); color = red; short = t('logstore.k.dockerDown'); }
    else if (!c.exists) { msg = t('logstore.absent', { name: sh.name }); color = amber; short = t('logstore.k.absent'); }
    else if (c.running) { msg = t('logstore.running', { name: sh.name }); color = green; short = t('logstore.k.running'); }
    else { msg = t('logstore.stopped', { name: sh.name }) + ' (' + (c.status || '?') + ')'; color = red; short = t('logstore.k.stopped'); }
    lsSet('ls-k-shipper', short, color);
    lsRow(box, t('logstore.container'), msg, color);
    lsRow(box, t('logstore.image'), sh.image || '—');
    lsRow(box, t('logstore.sink'), sh.sinkUrl || '—');
    lsRow(box, t('logstore.instance'), sh.instance || '—');
    lsRow(box, t('logstore.localUrl'), sh.localUrl || '—');
    if (sh.blockers && sh.blockers.length) {
      lsRow(box, t('logstore.missing'), sh.blockers.filter(b => b !== 'disabled').map(b => t('logstore.blocker.' + b)).join(' ; '), amber);
    }
    const s = sh.status;
    if (s) {
      const b = s.buffer || {}, snt = s.sent || {};
      lsRow(box, t('logstore.sent'), lsNum(snt.events) + ' ' + t('logstore.events') + ' / ' + lsNum(snt.batches) + ' ' + t('logstore.batches'));
      lsRow(box, t('logstore.pending'), lsNum(b.spool_files) + ' ' + t('logstore.files') + ' (' + lsBytes(b.spool_bytes) + ')', b.spool_files > 20 ? amber : '');
      if (b.spool_dropped || b.commit_errors || b.queue_dropped || (snt.rejected)) {
        lsRow(box, t('logstore.problems'), t('logstore.problemsDetail', {
          dropped: b.spool_dropped || 0, commit: b.commit_errors || 0, queue: b.queue_dropped || 0, rejected: snt.rejected || 0,
        }), red);
      }
      if (s.suspended) lsRow(box, t('logstore.suspended'), t('logstore.suspendedHint'), red);
      lsRow(box, t('logstore.uptime'), Math.round((s.uptime_s || 0) / 60) + ' min');
    } else if (c.running && sh.statusError) {
      lsRow(box, t('logstore.status'), t('logstore.statusErr.' + sh.statusError), amber);
    }
  }

  if (readOk) {
    if (lsTabName === 'stats') lsStatsLoad();
    else if (lsTabName === 'search' && !lsParams) lsSearch(false);
  }
}

async function lsContainerAction(path, confirmKey) {
  if (confirmKey && !confirm(t(confirmKey))) return;
  const box = document.getElementById('ls-shipper');
  box.textContent = t('geoip.starting');
  const d = await api(path, { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d && (d.error || d.ok === false)) {
    box.textContent = t('common.error') + ' : ' + ((d.fr && d.en) ? (typeof currentLang !== 'undefined' && currentLang === 'en' ? d.en : d.fr) : (d.error || ''));
    box.style.color = 'var(--red)';
    return;
  }
  box.style.color = '';
  await logstoreLoad();
}
function logstoreStart() { return lsContainerAction('/logstore/shipper/start'); }
function logstoreStop() { return lsContainerAction('/logstore/shipper/stop', 'logstore.confirmStop'); }
function logstoreImageUpdate() { return lsContainerAction('/logstore/shipper/image/update'); }

// ── Onglets ───────────────────────────────────────────────────────────────────
function lsTab(name) {
  lsTabName = name;
  ['search', 'stats', 'ip'].forEach((n) => {
    document.getElementById('ls-tab-' + n).style.display = n === name ? '' : 'none';
    document.getElementById('ls-btn-' + n).classList.toggle('primary', n === name);
  });
  if (name === 'stats') lsStatsLoad();
  if (name === 'search' && !lsParams) lsSearch(false);
}

// ── Recherche ─────────────────────────────────────────────────────────────────
function lsVal(id) { const e = document.getElementById(id); return e ? e.value.trim() : ''; }

function lsWindowParams(p, prefix) {
  const w = lsVal(prefix + 'window');
  if (w) p.set('since', w);
}

async function lsSearch(more) {
  const body = document.getElementById('ls-rows');
  const note = document.getElementById('ls-note');
  const btnMore = document.getElementById('ls-more');
  if (!more) {
    const p = new URLSearchParams();
    lsWindowParams(p, 'ls-f-');
    [['site', 'ls-f-site'], ['source', 'ls-f-source'], ['action', 'ls-f-action'],
      ['status', 'ls-f-status'], ['ip', 'ls-f-ip'], ['path', 'ls-f-path'], ['ua', 'ls-f-ua']].forEach(([k, id]) => {
      const v = lsVal(id); if (v) p.set(k, v);
    });
    p.set('limit', '100');
    lsParams = p; lsCursor = null;
    body.textContent = '';
  }
  const p = new URLSearchParams(lsParams);
  if (more && lsCursor) p.set('cursor', lsCursor);
  note.textContent = t('logstore.loading');
  btnMore.style.display = 'none';
  const d = await api('/logstore/events?' + p.toString()).catch(() => null);
  if (!d || d.error || !Array.isArray(d.events)) {
    note.textContent = lsErr(d, 'unreachable') + (d && d.detail ? ' — ' + d.detail : '');
    note.style.color = 'var(--red)';
    return;
  }
  note.style.color = '';
  d.events.forEach((e) => body.appendChild(lsEventRow(e)));
  lsCursor = d.next_cursor || null;
  btnMore.style.display = lsCursor ? '' : 'none';
  const n = body.children.length;
  note.textContent = n ? t('logstore.shown', { n: lsNum(n) }) : t('logstore.none');
}

function lsActionColor(a) {
  return a === 'blocked' ? 'var(--red)' : (a === 'challenged' ? 'var(--amber, #d98e04)' : (a === 'logged' ? 'var(--blue, #3b82f6)' : ''));
}

function lsEventRow(e) {
  const tr = document.createElement('tr');
  tr.appendChild(lsEl('td', lsTime(e.ts)));
  tr.appendChild(lsEl('td', e.site || '—'));
  const ipTd = document.createElement('td');
  const link = lsA(e.ip || e.ip_key || '—');
  if (e.ip || e.ip_key) link.addEventListener('click', (ev) => { ev.preventDefault(); lsIpOpen(e.ip || e.ip_key); });
  ipTd.appendChild(link);
  { const b = window.NgxIp && NgxIp.badge(e.ip); if (b) ipTd.append(' ', b); }
  tr.appendChild(ipTd);
  tr.appendChild(lsEl('td', (e.method ? e.method + ' ' : '') + (e.path || '')));
  tr.appendChild(lsEl('td', e.status != null ? String(e.status) : '—'));
  const act = lsEl('td', e.source + ' · ' + e.action);
  const col = lsActionColor(e.action); if (col) act.style.color = col;
  tr.appendChild(act);
  tr.appendChild(lsEl('td', e.rule || ''));
  const ua = lsEl('td', e.ua || ''); ua.style.maxWidth = '240px'; ua.style.overflow = 'hidden'; ua.style.textOverflow = 'ellipsis'; ua.style.whiteSpace = 'nowrap';
  ua.title = e.ua || '';
  tr.appendChild(ua);
  return tr;
}

// ── Fiche IP ──────────────────────────────────────────────────────────────────
function lsIpOpen(ip) {
  document.getElementById('ls-ip-input').value = ip;
  lsTab('ip');
  lsIpLoad(false);
}

// Decision CrowdSec courante (#64) : requete a la demande, masquee si CrowdSec absent ou non autorise.
async function lsIpCrowdsec(ip, sum) {
  const d = await api('/crowdsec/ip?ip=' + encodeURIComponent(ip)).catch(() => null);
  if (!d || d.error || !d.configured || !Array.isArray(d.decisions)) return;
  if (lsVal('ls-ip-input') !== ip) return;
  if (!d.decisions.length) { lsRow(sum, t('logstore.ip.crowdsec'), t('logstore.ip.crowdsecNone')); return; }
  d.decisions.forEach((x) => lsRow(sum, t('logstore.ip.crowdsec'),
    [x.type, x.scenario, x.origin, x.duration].filter(Boolean).join(' · '), 'var(--red)'));
}

let lsIpCursor = null;
async function lsIpLoad(more) {
  const ip = lsVal('ls-ip-input');
  const sum = document.getElementById('ls-ip-summary');
  const body = document.getElementById('ls-ip-rows');
  const note = document.getElementById('ls-ip-note');
  const btnMore = document.getElementById('ls-ip-more');
  if (!ip) { note.textContent = t('logstore.ip.enter'); return; }
  if (!more) { body.textContent = ''; sum.textContent = ''; lsIpCursor = null; }
  const p = new URLSearchParams({ ip, limit: '100' });
  const w = lsVal('ls-ip-window'); if (w) p.set('since', w);
  if (more && lsIpCursor) p.set('cursor', lsIpCursor);
  note.textContent = t('logstore.loading'); note.style.color = '';
  btnMore.style.display = 'none';
  const d = await api('/logstore/ip?' + p.toString()).catch(() => null);
  if (!d || d.error || !Array.isArray(d.events)) {
    note.textContent = lsErr(d, 'unreachable') + (d && d.detail ? ' — ' + d.detail : '');
    note.style.color = 'var(--red)';
    return;
  }
  if (!more && d.summary) {
    const s = d.summary;
    lsRow(sum, t('logstore.ip.total'), lsNum(s.total));
    lsRow(sum, t('logstore.ip.first'), lsTime(s.first_seen));
    lsRow(sum, t('logstore.ip.last'), lsTime(s.last_seen));
    (s.by_source_action || []).forEach((x) => lsRow(sum, x.source + ' · ' + x.action, lsNum(x.count), lsActionColor(x.action)));
    if (d.ip_mode && d.ip_mode !== 'clear') lsRow(sum, t('logstore.ipMode'), d.ip_mode);
  }
  if (!more) lsIpCrowdsec(ip, sum);
  d.events.forEach((e) => body.appendChild(lsEventRow(e)));
  lsIpCursor = d.next_cursor || null;
  btnMore.style.display = lsIpCursor ? '' : 'none';
  note.textContent = body.children.length ? t('logstore.shown', { n: lsNum(body.children.length) }) : t('logstore.none');
}

// ── Statistiques ──────────────────────────────────────────────────────────────
function lsStatsParams() {
  const p = new URLSearchParams();
  lsWindowParams(p, 'ls-s-');
  const site = lsVal('ls-s-site'); if (site) p.set('site', site);
  return p;
}

async function lsStatsLoad() {
  lsVisits(); lsTop(); lsSecurity();
}

function lsSvgBars(points) {
  const NS = 'http://www.w3.org/2000/svg';
  const W = 720, H = 160, padL = 40, padB = 18, padT = 6;
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', t('logstore.stats.visitsTitle'));
  svg.style.width = '100%'; svg.style.height = 'auto';
  const max = Math.max(1, ...points.map(p => p.requests));
  const bw = Math.min((W - padL) / Math.max(1, points.length), 48);
  const mk = (tag, attrs) => { const e = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v)); return e; };
  [0, 0.5, 1].forEach((f) => {
    const y = padT + (H - padB - padT) * (1 - f);
    svg.appendChild(mk('line', { x1: padL, x2: W, y1: y, y2: y, stroke: 'currentColor', 'stroke-opacity': '0.15' }));
    const tx = mk('text', { x: padL - 4, y: y + 3, 'text-anchor': 'end', 'font-size': '9', fill: 'currentColor', 'fill-opacity': '0.6' });
    tx.textContent = lsNum(Math.round(max * f));
    svg.appendChild(tx);
  });
  points.forEach((p, i) => {
    const total = p.requests || 0;
    const err = (p.s4xx || 0) + (p.s5xx || 0);
    const hAll = (H - padB - padT) * total / max;
    const hErr = (H - padB - padT) * err / max;
    const x = padL + i * bw + 1;
    const r = mk('rect', { x, y: H - padB - hAll, width: Math.max(1, bw - 2), height: hAll, fill: 'var(--blue, #3b82f6)' });
    const ttl = document.createElementNS(NS, 'title');
    ttl.textContent = lsTime(p.bucket) + ' — ' + lsNum(total) + ' req, ' + lsNum(err) + ' err' + (p.visitors != null ? ', ' + lsNum(p.visitors) + ' ' + t('logstore.stats.visitors') : '');
    r.appendChild(ttl);
    svg.appendChild(r);
    if (hErr > 0) svg.appendChild(mk('rect', { x, y: H - padB - hErr, width: Math.max(1, bw - 2), height: hErr, fill: 'var(--red)' }));
  });
  if (points.length) {
    const fmt = (iso) => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); };
    [[0, 'start'], [points.length - 1, 'end']].forEach(([i, anchor]) => {
      const tx = mk('text', { x: anchor === 'start' ? padL : W, y: H - 4, 'text-anchor': anchor, 'font-size': '9', fill: 'currentColor', 'fill-opacity': '0.6' });
      tx.textContent = fmt(points[i].bucket);
      svg.appendChild(tx);
    });
  }
  return svg;
}

async function lsVisits() {
  const box = document.getElementById('ls-visits');
  const d = await api('/logstore/visits?' + lsStatsParams().toString()).catch(() => null);
  box.textContent = '';
  if (!d || d.error || !Array.isArray(d.points)) { box.textContent = lsErr(d, 'unreachable'); return; }
  if (!d.points.length) { box.textContent = t('logstore.none'); return; }
  const tot = d.points.reduce((a, p) => a + (p.requests || 0), 0);
  const err = d.points.reduce((a, p) => a + (p.s4xx || 0) + (p.s5xx || 0), 0);
  const bytes = d.points.reduce((a, p) => a + (p.bytes || 0), 0);
  const sum = lsEl('div'); sum.style.cssText = 'display:flex;gap:18px;flex-wrap:wrap;margin-bottom:8px;font-size:12px';
  lsRow(sum, t('logstore.stats.requests'), lsNum(tot));
  lsRow(sum, t('logstore.stats.errors'), lsNum(err), err ? 'var(--red)' : '');
  lsRow(sum, t('logstore.stats.bytes'), lsBytes(bytes));
  box.appendChild(sum);
  box.appendChild(lsSvgBars(d.points));
}

async function lsTop() {
  const box = document.getElementById('ls-top');
  const dim = lsVal('ls-s-dim') || 'path';
  const p = lsStatsParams(); p.set('dimension', dim); p.set('limit', '20');
  const d = await api('/logstore/top?' + p.toString()).catch(() => null);
  box.textContent = '';
  if (!d || d.error || !Array.isArray(d.items)) { box.textContent = lsErr(d, 'unreachable'); return; }
  if (!d.items.length) { box.textContent = t('logstore.none'); return; }
  if (d.approximate) { const note = lsEl('div', t('logstore.topApprox')); note.style.cssText = 'font-size:11px;opacity:.7;margin-bottom:6px'; box.appendChild(note); }
  const max = Math.max(1, ...d.items.map(i => i.count));
  d.items.forEach((i) => {
    const row = lsEl('div'); row.style.cssText = 'display:grid;grid-template-columns:minmax(0,1fr) 70px;gap:8px;align-items:center;margin-bottom:3px;font-size:12px';
    const left = lsEl('div'); left.style.cssText = 'position:relative;min-width:0';
    const bar = lsEl('div'); bar.style.cssText = `position:absolute;inset:0 auto 0 0;width:${Math.round(100 * i.count / max)}%;background:var(--blue, #3b82f6);opacity:.18;border-radius:3px`;
    left.appendChild(bar);
    const key = String(i.key == null ? '' : i.key);
    const lab = (dim === 'ip') ? lsA(key) : lsEl('span', key || '—');
    if (dim === 'ip') { lab.addEventListener('click', (ev) => { ev.preventDefault(); lsIpOpen(key); }); }
    lab.style.cssText = 'position:relative;display:block;padding:2px 6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    lab.title = key;
    left.appendChild(lab);
    row.appendChild(left);
    const n = lsEl('div', lsNum(i.count)); n.style.textAlign = 'right';
    row.appendChild(n);
    box.appendChild(row);
  });
}

async function lsSecurity() {
  const box = document.getElementById('ls-security');
  // La synthese securite n'est pas additive : elle reste limitee a 31 jours (le log store refuse davantage).
  if (parseInt(lsVal('ls-s-window'), 10) > 744) { box.textContent = t('logstore.securityMax31'); return; }
  const d = await api('/logstore/security?' + lsStatsParams().toString()).catch(() => null);
  box.textContent = '';
  if (!d || d.error) { box.textContent = lsErr(d, 'unreachable'); return; }
  const sc = d.status_classes || {};
  const g = lsEl('div'); g.style.cssText = 'display:flex;gap:18px;flex-wrap:wrap;font-size:12px;margin-bottom:8px';
  ['s2xx', 's3xx', 's4xx', 's5xx'].forEach(k => lsRow(g, k.slice(1), lsNum(sc[k]), k === 's5xx' && sc[k] ? 'var(--red)' : ''));
  box.appendChild(g);
  // `fmt(item)` -> { label, value, ip } : libelle, valeur numerique, et IP cliquable le cas echeant.
  const block = (titleKey, items, fmt) => {
    box.appendChild(lsEl('div', t(titleKey), 'ctitle'));
    if (!items || !items.length) { const e = lsEl('div', t('logstore.none')); e.style.cssText = 'font-size:12px;color:var(--text3);margin-bottom:8px'; box.appendChild(e); return; }
    items.slice(0, 10).forEach((i) => {
      const f = fmt(i);
      const row = lsEl('div'); row.style.cssText = 'display:flex;gap:8px;font-size:12px;margin-bottom:2px';
      const lab = f.ip ? lsA(f.label) : lsEl('span', f.label);
      if (f.ip) { lab.addEventListener('click', (ev) => { ev.preventDefault(); lsIpOpen(f.label); }); }
      row.appendChild(lab);
      { const b = f.ip && window.NgxIp && NgxIp.badge(f.label); if (b) row.appendChild(b); }
      if (f.value != null) row.appendChild(lsEl('strong', f.value));
      box.appendChild(row);
    });
  };
  block('logstore.stats.blocked', d.blocked, (i) => ({ label: i.source + ' · ' + i.action, value: lsNum(i.count) }));
  block('logstore.stats.scanners', d.scanners, (i) => ({
    label: String(i.key), ip: true, value: t('logstore.stats.scannerDetail', { errors: lsNum(i.errors), paths: lsNum(i.distinct_paths) }),
  }));
  block('logstore.stats.errorUa', d.error_user_agents, (i) => ({ label: String(i.key), value: lsNum(i.count) }));
}
