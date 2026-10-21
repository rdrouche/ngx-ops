'use strict';
// v12.73.0 — Page Challenge HTTP : analyse des IP qui échouent au challenge + blocages automatiques.
// Données : GET /api/challenge/offenders (conteneur nginx-challenge builtin), POST /api/challenge/unban.
// Réglages (config/challenge.yml) : autoblock, autoblock_threshold, autoblock_window_minutes, autoblock_hours, offenders_hours.

function coCell(tr, text, style, title) {
  const td = document.createElement('td');
  td.textContent = text == null ? '' : String(text);
  if (style) td.style.cssText = style;
  if (title) td.title = title;
  tr.appendChild(td);
  return td;
}

function coTable(headers) {
  const tb = document.createElement('table');
  tb.style.cssText = 'width:100%;border-collapse:collapse;font-size:12px';
  const tr = document.createElement('tr');
  headers.forEach(k => {
    const th = document.createElement('th');
    th.textContent = t('challenge.off.col.' + k);
    th.style.cssText = 'text-align:left;padding:4px 8px;color:var(--text3);font-weight:600;border-bottom:1px solid var(--border2);white-space:nowrap';
    tr.appendChild(th);
  });
  tb.appendChild(tr);
  return tb;
}

function coWhen(sec) { return sec ? new Date(sec * 1000).toLocaleString() : '—'; }

async function challengeOffendersLoad() {
  const box = document.getElementById('ch-off-body');
  if (!box) return;
  const hours = document.getElementById('ch-off-hours').value;
  const min = document.getElementById('ch-off-min').value;
  const never = document.getElementById('ch-off-never').checked ? '1' : '0';
  const d = await api(`/challenge/offenders?hours=${encodeURIComponent(hours)}&min=${encodeURIComponent(min)}&neverSolved=${never}`).catch(() => null);
  box.textContent = '';
  const cfgLine = document.getElementById('ch-off-cfg');
  cfgLine.textContent = '';
  if (!d || !d.available) {
    cfgLine.textContent = t('challenge.stats.na.' + ((d && d.reason) || 'unreachable'));
    return;
  }
  const c = d.config || {};
  cfgLine.textContent = c.autoblock
    ? t('challenge.off.cfgOn', { n: c.threshold, w: c.windowMinutes, h: c.banHours })
    : t('challenge.off.cfgOff');
  cfgLine.style.color = c.autoblock ? 'var(--green)' : 'var(--text3)';

  // Blocages automatiques actifs
  const bans = d.bans || [];
  if (bans.length) {
    const title = document.createElement('div');
    title.className = 'ctitle'; title.style.cssText = 'font-size:12px;margin:6px 0';
    title.textContent = t('challenge.off.bansTitle', { n: bans.length });
    box.appendChild(title);
    const tb = coTable(['ip', 'attempts', 'since', 'until', 'ua', 'action']);
    bans.forEach(b => {
      const tr = document.createElement('tr');
      coCell(tr, b.ip, 'padding:4px 8px;font-family:monospace;color:var(--red)');
      coCell(tr, b.attempts + ' / ' + b.windowMinutes + ' min', 'padding:4px 8px');
      coCell(tr, coWhen(b.since), 'padding:4px 8px;white-space:nowrap');
      coCell(tr, coWhen(b.until), 'padding:4px 8px;white-space:nowrap');
      coCell(tr, b.userAgent || '', 'padding:4px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap', b.userAgent || '');
      const td = document.createElement('td'); td.style.padding = '4px 8px';
      const btn = document.createElement('button');
      btn.className = 'btn sm'; btn.textContent = t('challenge.off.unban');
      btn.addEventListener('click', () => challengeUnban(b.ip));
      td.appendChild(btn); tr.appendChild(td);
      tb.appendChild(tr);
    });
    box.appendChild(tb);
  }

  // Analyse
  const list = d.offenders || [];
  const title2 = document.createElement('div');
  title2.className = 'ctitle'; title2.style.cssText = 'font-size:12px;margin:14px 0 6px';
  title2.textContent = t('challenge.off.listTitle', { n: list.length });
  box.appendChild(title2);
  if (!list.length) {
    const e = document.createElement('div'); e.style.color = 'var(--text3)'; e.textContent = t('challenge.off.empty');
    box.appendChild(e);
    return;
  }
  const tb = coTable(['ip', 'attempts', 'redirected', 'pages', 'started', 'failed', 'solved', 'last', 'ua']);
  list.forEach(o => {
    const tr = document.createElement('tr');
    const banned = o.bannedUntil && o.bannedUntil * 1000 > Date.now();
    coCell(tr, o.ip + (banned ? ' ⛔' : ''), 'padding:4px 8px;font-family:monospace' + (banned ? ';color:var(--red)' : ''), banned ? t('challenge.off.bannedTip', { d: coWhen(o.bannedUntil) }) : '');
    coCell(tr, o.attempts, 'padding:4px 8px;font-weight:700');
    coCell(tr, o.redirected, 'padding:4px 8px');
    coCell(tr, o.pages, 'padding:4px 8px');
    coCell(tr, o.started, 'padding:4px 8px');
    coCell(tr, o.failed + (o.rateLimited ? ' (+' + o.rateLimited + ' RL)' : ''), 'padding:4px 8px');
    coCell(tr, o.solved, 'padding:4px 8px');
    coCell(tr, coWhen(o.lastSeen), 'padding:4px 8px;white-space:nowrap');
    coCell(tr, o.userAgent || '', 'padding:4px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap', (o.host ? o.host + ' — ' : '') + (o.userAgent || ''));
    tb.appendChild(tr);
  });
  box.appendChild(tb);
}

async function challengeUnban(ip) {
  if (!confirm(t('challenge.off.unbanConfirm', { ip }))) return;
  const r = await api('/challenge/unban', { method: 'POST', body: JSON.stringify({ ip }) }).catch(() => null);
  if (!r || r.error) { alert((r && r.error) || t('challenge.off.unbanError')); return; }
  challengeOffendersLoad();
}
