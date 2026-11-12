'use strict';
// Interface minimale de gestion des jetons (#91). Le jeton admin reste en mémoire (variable), jamais stocké.
// Aucun innerHTML : tout le contenu dynamique passe par textContent.
(() => {
  let token = '';
  const $ = (id) => document.getElementById(id);
  const el = (tag, props, ...kids) => {
    const n = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => { if (k === 'class') n.className = v; else n.setAttribute(k, v); });
    kids.forEach((k) => n.append(k));
    return n;
  };
  const HELP = {
    write: "Envoi des journaux : l'instance est obligatoire (un jeton write = une instance, utilisé par le shipper).",
    read: "Lecture. Avec une instance : le jeton ne voit que cette instance (dashboard). Sans instance : toutes (Hub, administration).",
    admin: "Gestion des jetons et des réglages. Jamais lié à une instance.",
  };

  async function api(method, path, body) {
    const r = await fetch(path, {
      method, cache: 'no-store', credentials: 'omit', redirect: 'error',
      headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    if (r.status !== 204) { try { data = await r.json(); } catch { /* corps vide */ } }
    if (!r.ok) {
      const e = new Error((data && (data.detail || data.error)) || ('HTTP ' + r.status));
      e.status = r.status; throw e;
    }
    return data;
  }

  const fmt = (v) => (v ? new Date(v).toLocaleString() : '—');

  async function load() {
    $('list-err').textContent = '';
    try {
      const d = await api('GET', '/v1/tokens');
      const showRev = $('show-revoked').checked;
      const rows = $('rows'); rows.textContent = '';
      (d.tokens || []).filter((t) => showRev || !t.revoked_at).forEach((t) => {
        const revoked = !!t.revoked_at;
        const tr = el('tr', { class: revoked ? 'rev' : '' },
          el('td', {}, String(t.id)), el('td', {}, t.label), el('td', {}, el('span', { class: 'tag' }, t.role)),
          el('td', {}, t.instance_id || (t.role === 'read' ? 'toutes' : '—')),
          el('td', {}, fmt(t.created_at)), el('td', {}, fmt(t.last_used_at)),
          el('td', {}, revoked ? 'révoqué' : 'actif'));
        const act = el('td', {});
        if (!revoked) {
          const b = el('button', { type: 'button', class: 'ghost' }, 'Révoquer');
          b.addEventListener('click', () => confirmRevoke(b, t));
          act.append(b);
        }
        tr.append(act); rows.append(tr);
      });
    } catch (e) { if (e.status === 401 || e.status === 403) return logout('Jeton refusé ou non admin.'); $('list-err').textContent = 'Erreur : ' + e.message; }
  }

  // Confirmation en deux temps dans la page (pas de boîte de dialogue du navigateur).
  function confirmRevoke(btn, t) {
    if (btn.dataset.armed !== '1') {
      btn.dataset.armed = '1'; btn.textContent = 'Confirmer la révocation'; btn.className = 'danger';
      setTimeout(() => { btn.dataset.armed = ''; btn.textContent = 'Révoquer'; btn.className = 'ghost'; }, 5000);
      return;
    }
    btn.disabled = true;
    api('DELETE', '/v1/tokens/' + encodeURIComponent(t.id)).then(load).catch((e) => {
      $('list-err').textContent = e.status === 409 ? 'Impossible : dernier jeton admin actif.' : 'Erreur : ' + e.message; btn.disabled = false;
    });
  }

  // ───────── Maintenance PostgreSQL (#96) ─────────
  const CHECK_LABEL = {
    retention_effective: 'Rétention respectée', timescaledb: 'TimescaleDB', compression: 'Compression',
    retention_events: 'Rétention des événements', aggregate_events_1h: 'Cumul horaire', aggregate_events_1d: 'Cumul journalier',
    retention_events_1h: 'Rétention du cumul horaire', retention_events_1d: 'Rétention du cumul journalier',
  };
  const STATUS_LABEL = { ok: 'OK', warn: 'À surveiller', fail: 'Échec', na: 'Sans objet', unknown: 'Inconnu' };
  const bytes = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' Go' : n >= 1048576 ? (n / 1048576).toFixed(1) + ' Mo' : Math.round(n / 1024) + ' Ko');
  let mTimer = null;

  async function loadMaintenance() {
    $('m-err').textContent = '';
    try {
      const d = await api('GET', '/v1/maintenance');
      const st = d.status || {};
      const last = st.last;
      $('m-summary').textContent = (d.enabled ? 'Planifiée toutes les ' + d.interval_hours + ' h' : 'Planification désactivée (LOGSTORE_MAINTENANCE=false)')
        + ' — ' + (d.timescale ? 'TimescaleDB' : 'PostgreSQL simple')
        + ' — ' + (st.running ? 'en cours…' : last ? 'dernier passage ' + fmt(last.started_at) + ' (' + last.trigger + ', ' + Math.round(last.duration_ms / 1000) + ' s' + (last.error ? ', erreur : ' + last.error : '') + ')' : 'aucun passage depuis le démarrage');
      $('m-run').disabled = !!st.running;
      const cb = $('m-checks'); cb.textContent = '';
      (d.checks || []).forEach((c) => cb.append(el('tr', {},
        el('td', {}, CHECK_LABEL[c.name] || c.name),
        el('td', {}, el('span', { class: 'tag st-' + c.status }, STATUS_LABEL[c.status] || c.status)),
        el('td', { class: 'wrapcell' }, c.detail))));
      const tb = $('m-tables'); tb.textContent = '';
      (st.tables || []).forEach((t) => tb.append(el('tr', {},
        el('td', {}, t.name), el('td', {}, bytes(t.size_bytes)), el('td', {}, String(t.live_tuples)), el('td', {}, String(t.dead_tuples)),
        el('td', {}, fmt(t.last_vacuum || t.last_autovacuum)), el('td', {}, fmt(t.last_analyze || t.last_autoanalyze)))));
      const c = st.compression;
      $('m-comp').textContent = c ? 'Compression : ' + c.compressed_chunks + ' / ' + c.total_chunks + ' chunks compressés'
        + (c.bytes_before > 0 ? ' (' + bytes(c.bytes_before) + ' → ' + bytes(c.bytes_after) + ')' : '') : '';
      if (st.running) { clearTimeout(mTimer); mTimer = setTimeout(loadMaintenance, 3000); }
    } catch (e) { if (e.status === 401 || e.status === 403) return logout('Jeton refusé ou non admin.'); $('m-err').textContent = 'Erreur : ' + e.message; }
  }

  // ───────── Informations de la base (#127) : mêmes champs que le dashboard (GET /v1/health, détail pour read/admin) ─────────
  const IP_MODE = { clear: 'en clair', pseudonymized: 'pseudonymisées (HMAC)', truncated: 'tronquées (/24, /48)' };
  async function loadDb() {
    $('db-err').textContent = '';
    try {
      const d = await api('GET', '/v1/health'); const x = d.detail;
      const dl = $('db-info'); dl.textContent = '';
      if (!x) { $('db-err').textContent = 'Détail indisponible pour ce jeton.'; return; }
      [['Version', d.version || '—'], ['TimescaleDB', x.timescale ? 'oui' : 'non (PostgreSQL simple)'], ['Taille de la base', bytes(x.db_size_bytes || 0)],
        ['Dernier envoi reçu', fmt(x.last_ingest)], ['Rétention des journaux bruts', x.retention_days ? x.retention_days + ' jours' : '—'],
        ['Adresses IP', IP_MODE[x.ip_mode] || '—']].forEach(([k, v]) => { dl.append(el('dt', {}, k), el('dd', {}, String(v))); });
    } catch (e) { if (e.status === 401 || e.status === 403) return logout('Jeton refusé ou non admin.'); $('db-err').textContent = 'Erreur : ' + e.message; }
  }

  function logout(msg) {
    clearTimeout(mTimer);
    token = ''; $('admin-token').value = ''; $('app').hidden = true; $('login').hidden = false;
    $('new-token').hidden = true; $('new-token-value').textContent = ''; $('rows').textContent = '';
    $('login-err').textContent = msg || '';
  }

  function syncRole() {
    const r = $('c-role').value; const inst = $('c-inst');
    $('c-help').textContent = HELP[r];
    inst.disabled = r === 'admin'; inst.required = r === 'write';
    if (r === 'admin') inst.value = '';
  }

  $('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault(); $('login-err').textContent = '';
    token = $('admin-token').value.trim();
    try {
      await api('GET', '/v1/tokens');
      $('login').hidden = true; $('app').hidden = false; $('admin-token').value = '';
      $('who').textContent = 'Connecté en admin'; syncRole(); load(); loadDb(); loadMaintenance();
    } catch (e) {
      token = '';
      $('login-err').textContent = e.status === 401 || e.status === 403 ? 'Jeton refusé (il faut un jeton admin).' : e.status === 429 ? 'Trop de tentatives, patientez.' : 'Erreur : ' + e.message;
    }
  });
  $('logout').addEventListener('click', () => logout(''));
  $('m-refresh').addEventListener('click', () => { loadDb(); loadMaintenance(); });
  $('m-run').addEventListener('click', async () => {
    $('m-err').textContent = ''; $('m-run').disabled = true;
    try { await api('POST', '/v1/maintenance'); } catch (e) { $('m-err').textContent = e.status === 409 ? 'Déjà en cours.' : 'Erreur : ' + e.message; }
    loadMaintenance();
  });
  $('c-role').addEventListener('change', syncRole);
  $('show-revoked').addEventListener('change', load);
  $('dismiss').addEventListener('click', () => { $('new-token').hidden = true; $('new-token-value').textContent = ''; });
  $('copy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('new-token-value').textContent); $('copy').textContent = 'Copié'; } catch { $('copy').textContent = 'Sélectionner et copier à la main'; }
  });
  $('create-form').addEventListener('submit', async (ev) => {
    ev.preventDefault(); $('c-err').textContent = '';
    const body = { label: $('c-label').value.trim(), role: $('c-role').value };
    const inst = $('c-inst').value.trim(); if (inst && body.role !== 'admin') body.instance_id = inst;
    try {
      const out = await api('POST', '/v1/tokens', body);
      $('new-token-value').textContent = out.token; $('new-token').hidden = false; $('copy').textContent = 'Copier';
      $('c-label').value = ''; $('c-inst').value = ''; load();
    } catch (e) { $('c-err').textContent = 'Erreur : ' + e.message; }
  });
})();
