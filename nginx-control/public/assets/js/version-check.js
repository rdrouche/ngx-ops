'use strict';
/**
 * Badge de version (dashboard + Nginx) et vérification de mise à jour
 * (bandeau "Updates available"). Extrait de public/index.html (voir
 * CHANGELOG.md). Appelé depuis Boot (index.html) via initVersionBadge().
 */
let _versionChecked = false;

async function initVersionBadge() {
  // Use version injected by server at boot
  const v = window.DASHBOARD_VERSION || '?';
  const el = document.getElementById('dash-version');
  if (el) el.textContent = 'v' + v;

  // Auto-check updates once per session (non-blocking)
  if (!_versionChecked && window.UPDATE_CHECK_URL_CONFIGURED) {
    _versionChecked = true;
    setTimeout(() => checkUpdates(true), 3000);
  }
}

async function checkUpdates(silent) {
  const d = await api('/version?check=1').catch(() => null);
  if (!d) return;

  // Update nginx version badge
  const nv = document.getElementById('nginx-version');
  if (nv && d.nginx?.current) nv.textContent = d.nginx.current;
  if (nv && d.nginx?.image)   nv.title = 'Image: ' + d.nginx.image;

  // Update dashboard version badge
  const dv = document.getElementById('dash-version');
  if (dv) dv.textContent = 'v' + (d.dashboard?.current || '?');

  // Check if updates available
  const msgs = [];
  const dashCurrent = d.dashboard?.current || '';
  const dashLatest  = d.updates?.dashboard;
  // Normalize version — strip "nginx/" prefix, leading "v", and this
  // project's own build-variant suffix (-waf / -coraza). Without the last
  // part, an image tagged "1.30.5-waf" never equals the bare "1.30.5"
  // published by an update-check feed, so the badge flags an update as
  // available forever, even right after upgrading to the latest -waf build.
  // lib/docker.js's stripVariantSuffix() does the same on the server side
  // for its own callers; duplicated here (same regex) since this comparison
  // runs entirely client-side against the raw fields the API returns.
  const stripVer = v => (v || '').replace(/^nginx\//, '').replace(/^v/, '').replace(/-(waf|coraza)$/i, '').trim();
  const nginxCurrent = stripVer(d.nginx?.image || d.nginx?.current || '');
  const nginxLatest  = stripVer(d.updates?.nginx || '');

  // Don't flag non-semver versions (e.g. "vnightly", "dev", "manual-build") as outdated
  const isSemver = v => /^\d+\.\d+/.test(v);
  if (dv) dv.title = 'Current: ' + dashCurrent + (dashLatest ? ' | Latest: ' + dashLatest : '');
  if (nv) {
    const nginxVer  = d.nginx?.current || nginxCurrent || '';
    const nginxImg  = d.nginx?.image || '';
    nv.title = 'Running: ' + nginxVer + (nginxImg ? ' | Image: ' + nginxImg : '') + (nginxLatest ? ' | Latest: ' + nginxLatest : '');
  }
  if (dashLatest && isSemver(dashCurrent) && dashLatest !== dashCurrent && dashLatest !== '?') {
    msgs.push('Dashboard: ' + dashCurrent + ' → <strong>' + h(dashLatest) + '</strong>');
    if (dv) dv.classList.add('update');
  } else if (dv) {
    dv.classList.remove('update');
  }
  if (nginxLatest && nginxLatest && nginxLatest !== nginxCurrent) {
    msgs.push('Nginx: ' + h(nginxCurrent) + ' → <strong>' + h(nginxLatest) + '</strong>');
    if (nv) nv.classList.add('update');
  } else if (nv) {
    nv.classList.remove('update');
  }

  if (msgs.length && !silent) {
    const toast = document.getElementById('update-toast');
    document.getElementById('update-toast-content').innerHTML =
      '<div style="margin-bottom:6px;font-weight:500">Updates available</div>' +
      msgs.map(m => '<div style="color:var(--amber)">' + m + '</div>').join('');
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 10000);
  }
  if (!msgs.length && !silent) {
    alert('All components are up to date.');
  }
}


// ── Carte « Versions et mises à jour » de la page Système (v12.78.0) ─────────
function _svEl(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }

async function versionCardLoad(check) {
  const body = document.getElementById('sysver-body');
  if (!body) return;
  const btn = document.getElementById('sysver-check-btn');
  if (btn) btn.disabled = true;
  const d = await api('/version' + (check ? '?check=1' : '')).catch(() => null);
  if (btn) btn.disabled = false;
  body.replaceChildren();
  if (!d) { body.appendChild(_svEl('div', t('common.error'), 'psub')); return; }
  const strip = v => (v || '').replace(/^nginx\//, '').replace(/^v/, '').replace(/-(waf|coraza)$/i, '').trim();
  const semver = v => /^\d+\.\d+/.test(v);
  const rows = [];
  const dc = d.dashboard && d.dashboard.current || '', dl = d.updates && d.updates.dashboard || '';
  const nc = strip((d.nginx && (d.nginx.image || d.nginx.current)) || ''), nl = strip(d.updates && d.updates.nginx || '');
  const state = (cur, latest) => !check ? ['', ''] : (!latest || latest === '?') ? [t('sysver.unknown'), ''] :
    (semver(cur) && latest !== cur) ? [t('sysver.available', { v: latest }), 'am'] : [t('sysver.upToDate'), 'gn'];
  const ds = state(dc, dl), ns = state(nc, nl);
  rows.push([t('sysver.dashboard'), dc ? 'v' + dc : '—', ds, d.dashboard && d.dashboard.revision ? t('sysver.revision') + ' ' + String(d.dashboard.revision).slice(0, 12) : '']);
  rows.push([t('sysver.nginx'), (d.nginx && d.nginx.current) || '—', ns, d.nginx && d.nginx.image ? t('sysver.image') + ' ' + d.nginx.image : '']);
  const tbl = _svEl('table', null, 'sync-table');
  const head = _svEl('tr');
  ['sysver.component', 'sysver.current', 'sysver.state', 'sysver.detail'].forEach(k => head.appendChild(_svEl('th', t(k))));
  const th = _svEl('thead'); th.appendChild(head); tbl.appendChild(th);
  const tb = _svEl('tbody');
  rows.forEach(([name, cur, st, detail]) => {
    const tr = _svEl('tr');
    tr.appendChild(_svEl('td', name)); tr.appendChild(_svEl('td', cur));
    const td = _svEl('td'); if (st[0]) td.appendChild(_svEl('span', st[0], 'badge ' + st[1])); tr.appendChild(td);
    tr.appendChild(_svEl('td', detail, 'psub')); tb.appendChild(tr);
  });
  tbl.appendChild(tb);
  const w = _svEl('div', null, 'tw'); w.appendChild(tbl); body.appendChild(w);
  if (!check) body.appendChild(_svEl('div', t('sysver.hint'), 'psub'));
  if (check && !window.UPDATE_CHECK_URL_CONFIGURED) body.appendChild(_svEl('div', t('sysver.noSource'), 'psub'));
  // met aussi à jour les pastilles de l'en-tête
  const nv = document.getElementById('nginx-version'); if (nv && d.nginx && d.nginx.current) nv.textContent = d.nginx.current;
}

/** Logo / « NGX Ops » : retour à la vue d'ensemble, quel que soit le thème. */
function goOverview(ev) {
  if (ev) ev.preventDefault();
  const ni = document.querySelector('nav .ni[data-page="overview"]');
  if (ni) ni.click();
  return false;
}
