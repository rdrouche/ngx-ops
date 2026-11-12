// ── Controle uniforme des conteneurs geres (#104, #105) ─────────────────────
// Un composant unique pour demarrer / redemarrer / recreer / mettre a jour / arreter / supprimer
// le conteneur d'une integration, avec confirmation pour les actions destructives ou la mise a jour.
// API : /api/managed-containers/* (lib/container-lifecycle.js). Rendu par createElement/textContent.
//   <span data-ctl="analyzer"></span>             montage declaratif (ids : analyzer, waf, shipper, certbot, certbot-dns, geoipupdate, error-pages, challenge, godns ;
//   goaccess:<sourceId> monte par programme, une instance par source de logs)
//   ngxContainerControl(mountEl, id, { onDone })  -> { refresh() }
//   ngxContainerControlRefresh()                  -> rafraichit tous les composants montes
const ngxCtlInstances = [];
let ngxCtlCache = { at: 0, p: null };
let ngxCtlLast = null;

function ngxCtlOverview(force) {
  const now = Date.now();
  if (!force && ngxCtlCache.p && now - ngxCtlCache.at < 2000) return ngxCtlCache.p;
  ngxCtlCache = { at: now, p: api('/managed-containers/overview').catch(() => null) };
  return ngxCtlCache.p;
}

function ngxCtlEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function ngxCtlLines(m, lines) {
  lines.forEach(l => { const p = ngxCtlEl('div', null, l); p.style.margin = '8px 0'; m.body.appendChild(p); });
}

function ngxCtlConfirm(title, lines, okLabel, danger) {
  return new Promise(resolve => {
    let answered = false;
    const m = ngxModal({ title, onClose: () => { if (!answered) resolve(false); } });
    ngxCtlLines(m, lines);
    const row = ngxCtlEl('div', 'row');
    row.style.cssText = 'justify-content:flex-end;gap:8px;margin-top:14px';
    const no = ngxCtlEl('button', 'btn sm', t('common.cancel'));
    const ok = ngxCtlEl('button', 'btn sm ' + (danger ? 'danger' : 'primary'), okLabel);
    no.type = ok.type = 'button';
    no.onclick = () => { answered = true; m.close(); resolve(false); };
    ok.onclick = () => { answered = true; m.close(); resolve(true); };
    row.appendChild(no); row.appendChild(ok);
    m.body.appendChild(row);
    ok.focus();
  });
}

function ngxCtlNotice(title, lines) {
  return new Promise(resolve => {
    const m = ngxModal({ title, onClose: resolve });
    ngxCtlLines(m, lines);
  });
}

function ngxCtlErr(d) { return String((d && (d.message || d.error)) || 'unknown'); }
function ngxCtlPost(path, payload) {
  return api(path, { method: 'POST', body: JSON.stringify(payload) });
}

function ngxContainerControl(mount, id, opts) {
  if (!mount) return { refresh() {} };
  const onDone = opts && typeof opts.onDone === 'function' ? opts.onDone : () => {};
  let st = null;
  let busy = false;
  let menuOpen = false;

  const wrap = ngxCtlEl('span', 'ngx-ctl');
  wrap.style.cssText = 'display:none;position:relative;align-items:center;gap:6px';
  const badge = ngxCtlEl('span', 'ngx-ctl-badge');
  badge.style.cssText = 'display:none;color:var(--amber);font-size:12px';
  const main = ngxCtlEl('button', 'btn sm');
  const more = ngxCtlEl('button', 'btn sm', '⋯');
  const menu = ngxCtlEl('div', 'ngx-ctl-menu');
  main.type = more.type = 'button';
  more.setAttribute('aria-haspopup', 'menu');
  menu.setAttribute('role', 'menu');
  menu.style.cssText = 'display:none;position:absolute;top:100%;right:0;z-index:50;min-width:230px;margin-top:4px;padding:4px;'
    + 'background:var(--bg2,#1c1f26);border:1px solid var(--border,#333);border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,.35)';
  wrap.appendChild(badge); wrap.appendChild(main); wrap.appendChild(more); wrap.appendChild(menu);
  mount.textContent = '';
  mount.appendChild(wrap);

  function ctlCloseMenu() { menuOpen = false; menu.style.display = 'none'; }
  more.onclick = (e) => { e.stopPropagation(); menuOpen = !menuOpen; menu.style.display = menuOpen ? 'block' : 'none'; };
  const onDocClick = (e) => {
    if (!wrap.isConnected) { document.removeEventListener('click', onDocClick); return; }
    if (menuOpen && !wrap.contains(e.target)) ctlCloseMenu();
  };
  document.addEventListener('click', onDocClick);

  function item(label, fn, danger) {
    const b = ngxCtlEl('button', 'btn sm' + (danger ? ' danger' : ''), label);
    b.type = 'button'; b.setAttribute('role', 'menuitem');
    b.style.cssText = 'display:block;width:100%;text-align:left;margin:2px 0';
    b.onclick = () => { ctlCloseMenu(); fn(); };
    menu.appendChild(b);
  }

  function setBusy(on, label) {
    busy = on;
    main.disabled = more.disabled = on;
    if (on) main.textContent = label || t('ctl.working');
    else ctlRender();
  }

  async function run(action, label) {
    setBusy(true, label);
    const d = await ngxCtlPost('/managed-containers/action', { id, action });
    ngxCtlCache = { at: 0, p: null };
    setBusy(false);
    if (!d || d.error || d.ok === false) await ngxCtlNotice(t('ctl.failed'), [ngxCtlErr(d)]);
    await refresh(true);
    onDone(action, d);
    return d;
  }

  async function doUpdate() {
    setBusy(true, t('ctl.checking'));
    const c = await ngxCtlPost('/managed-containers/action', { id, action: 'check' });
    setBusy(false);
    if (!c || c.error || c.ok === false) { await ngxCtlNotice(t('ctl.failed'), [ngxCtlErr(c)]); return; }
    if (!c.imageUpdated && !c.updateAvailable) { await ngxCtlNotice(t('ctl.update'), [t('ctl.upToDate')]); await refresh(true); return; }
    const ok = await ngxCtlConfirm(t('ctl.update'), [t('ctl.confirm.update', { name: st ? st.label : id })], t('ctl.update'), false);
    if (!ok) { await refresh(true); return; }
    const r = await run('update', t('ctl.updating'));
    if (r && r.ok) await ngxCtlNotice(t('ctl.update'), [t('ctl.updated')]);
  }

  async function doUpdateAll() {
    const image = st.imageRef;
    const names = [st.label].concat((st.peers || []).map(p => {
      const o = (ngxCtlLast || []).find(x => x.id === p);
      return o ? o.label : p;
    }));
    const ok = await ngxCtlConfirm(t('ctl.updateAll.title'), [t('ctl.updateAll.body', { image: image || '' }), names.join(', ')], t('ctl.updateAll.go'), false);
    if (!ok) return;
    setBusy(true, t('ctl.updating'));
    const r = await ngxCtlPost('/managed-containers/update-all', { image, apply: true });
    setBusy(false);
    if (!r || r.error) await ngxCtlNotice(t('ctl.failed'), [ngxCtlErr(r)]);
    else {
      const lines = [];
      (r.groups || []).forEach(g => {
        if (!g.ok) lines.push(g.image + ' : ' + (g.error || 'error'));
        else (g.results || []).forEach(x => lines.push(x.label + ' : ' + (x.ok === false ? (x.error || 'error') : x.recreated ? t('ctl.result.recreated') : t('ctl.result.unchanged'))));
      });
      await ngxCtlNotice(t('ctl.updateAll.title'), lines.length ? lines : [t('ctl.upToDate')]);
    }
    ngxContainerControlRefresh();
    onDone('update-all', r);
  }

  function ctlRender() {
    if (busy) return;
    if (!st || st.error) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'inline-flex';
    const running = !!st.running;
    more.setAttribute('aria-label', t('ctl.more'));
    main.className = 'btn sm' + (running ? '' : ' primary');
    main.textContent = running ? '↻ ' + t('ctl.restart') : '▶ ' + t('ctl.start');
    main.disabled = !st.enabled;
    more.disabled = !st.enabled && !st.exists;
    main.onclick = () => run(running ? 'restart' : 'start', t('ctl.working'));
    badge.style.display = st.outdated ? '' : 'none';
    badge.textContent = st.outdated ? '⬆ ' + t('ctl.outdated') : '';
    menu.textContent = '';
    if (st.enabled) {
      item('⟳ ' + t('ctl.recreate'), async () => {
        if (await ngxCtlConfirm(t('ctl.recreate'), [t('ctl.confirm.recreate', { name: st.label })], t('ctl.recreate'), false)) run('recreate', t('ctl.working'));
      });
      item('⬇ ' + t('ctl.update'), doUpdate);
      if ((st.peers || []).length) item('⬇⬇ ' + t('ctl.updateAll', { n: st.peers.length + 1 }), doUpdateAll);
    }
    if (st.running) item('■ ' + t('ctl.stop'), () => run('stop', t('ctl.working')));
    if (st.exists) {
      item('✕ ' + t('ctl.down'), async () => {
        if (await ngxCtlConfirm(t('ctl.down'), [t('ctl.confirm.down', { name: st.label })], t('ctl.down'), true)) run('down', t('ctl.working'));
      }, true);
    }
    const tip = [];
    if (st.image) tip.push(st.image);
    if (st.created) tip.push(String(st.created).slice(0, 10));
    wrap.title = tip.join(' · ');
  }

  async function refresh(force) {
    const o = await ngxCtlOverview(force);
    ngxCtlLast = o && o.containers ? o.containers : null;
    st = ngxCtlLast ? (ngxCtlLast.find(x => x.id === id) || null) : null;
    ctlRender();
  }

  // Les composants dont le point de montage a disparu (page reconstruite) sont oublies.
  for (let i = ngxCtlInstances.length - 1; i >= 0; i--) if (!ngxCtlInstances[i].mount.isConnected) ngxCtlInstances.splice(i, 1);
  const inst = { refresh, mount };
  ngxCtlInstances.push(inst);
  refresh();
  return inst;
}

function ngxContainerControlRefresh() {
  ngxCtlCache = { at: 0, p: null };
  ngxCtlInstances.forEach(i => i.refresh(true));
}

// Fonction de rafraichissement de la page hote, appelee apres une action.
const NGX_CTL_AFTER = {
  analyzer: 'anRefreshStatus', waf: 'wfLoad', shipper: 'logstoreLoad',
  certbot: 'certbotRefreshStatus', 'certbot-dns': 'cbdnsRefreshStatus', geoipupdate: 'geoipupdateRefreshStatus',
  'error-pages': 'errorPagesRefreshStatus', challenge: 'challengeLoad', godns: 'godnsRefreshStatus',
};

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-ctl]').forEach(el => {
    ngxContainerControl(el, el.getAttribute('data-ctl'), {
      onDone: () => { const f = window[NGX_CTL_AFTER[el.getAttribute('data-ctl')]]; if (typeof f === 'function') f(); },
    });
  });
});
