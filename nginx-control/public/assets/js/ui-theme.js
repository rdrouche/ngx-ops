// ── Interface « Classique » / « Conductor » clair / sombre — v12.75.0 ───────────
// Le choix (localStorage ngx_ui : classic | light | dark) est appliqué très tôt
// par le petit script du <head> ; ce module ajoute le sélecteur et, pour
// Conductor, la barre de menu déroulante construite à partir du menu existant
// (les entrées .ni d'origine restent la source de vérité : un clic sur un
// élément du menu déroulant déclenche simplement un clic sur l'original).
// Aucun innerHTML avec des valeurs externes.
(function () {
  const KEY = 'ngx_ui';
  const tr = (k, d) => { try { const v = typeof t === 'function' ? t(k) : k; return v && v !== k ? v : d; } catch { return d; } };
  const root = document.documentElement;
  const el = (tag, text, cls, attrs) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    if (attrs) Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
    return e;
  };

  function current() { try { const v = localStorage.getItem(KEY); return v === 'light' || v === 'dark' ? v : 'classic'; } catch { return 'classic'; } }
  function apply(mode) {
    if (mode === 'classic') { root.removeAttribute('data-ui'); root.removeAttribute('data-mode'); }
    else { root.setAttribute('data-ui', 'conductor'); root.setAttribute('data-mode', mode); }
    document.querySelectorAll('.ui-btn').forEach(b => b.classList.toggle('active', b.dataset.ui === mode));
    closeMenu(); rebuild();
  }
  function set(mode) { try { localStorage.setItem(KEY, mode); } catch { /* navigation privée */ } apply(mode); }

  // — Menu déroulant —
  let menu = null;
  function closeMenu() {
    if (menu) menu.classList.remove('show');
    document.querySelectorAll('.cd-grp.open').forEach(b => b.classList.remove('open'));
  }
  function ensureMenu() {
    if (!menu) {
      menu = el('div', null, null, { id: 'cd-menu', role: 'menu' });
      document.body.appendChild(menu);
      document.addEventListener('click', (e) => { if (!e.target.closest('#cd-menu') && !e.target.closest('.cd-grp')) closeMenu(); });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
    }
    return menu;
  }
  const label = (ni) => {
    const s = [...ni.querySelectorAll('span')].find(x => !x.classList.contains('nb'));
    return s ? s.textContent.trim() : ni.textContent.trim();
  };
  function groups() {
    const out = [];
    document.querySelectorAll('nav > .ns').forEach(ns => {
      if (ns.style.display === 'none') return;
      const items = [];
      let n = ns.nextElementSibling;
      while (n && !n.classList.contains('ns')) {
        if (n.classList.contains('ni') && n.style.display !== 'none') items.push(n);
        n = n.nextElementSibling;
      }
      if (items.length) out.push({ title: (ns.querySelector('span') || ns).textContent.trim(), items });
    });
    return out;
  }
  function openGroup(btn, g) {
    const m = ensureMenu();
    if (btn.classList.contains('open')) { closeMenu(); return; }
    closeMenu();
    m.replaceChildren();
    // Menu « Liens » : les liens de pied de page (Ko-fi, site, dépôt, documentation) du menu latéral masqué.
    (g.links || []).forEach(a => {
      const it = el('a', null, 'cd-item', { role: 'menuitem', href: a.href, target: '_blank', rel: 'noopener noreferrer' });
      it.appendChild(el('span', a.text));
      it.addEventListener('click', () => closeMenu());
      m.appendChild(it);
    });
    (g.items || []).forEach(ni => {
      const it = el('div', null, 'cd-item' + (ni.classList.contains('active') ? ' active' : ''), { role: 'menuitem' });
      it.appendChild(el('span', label(ni)));
      const nb = ni.querySelector('.nb');
      if (nb && nb.textContent.trim() && nb.textContent.trim() !== '—') it.appendChild(el('span', nb.textContent.trim(), 'cd-nb'));
      it.addEventListener('click', () => { closeMenu(); ni.click(); setTimeout(refreshActive, 50); });
      m.appendChild(it);
    });
    const r = btn.getBoundingClientRect();
    m.style.top = (r.bottom + 6) + 'px';
    m.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 270)) + 'px';
    m.classList.add('show'); btn.classList.add('open');
  }
  function refreshActive() {
    document.querySelectorAll('#cd-bar .cd-grp').forEach(b => {
      const g = b._g; b.classList.toggle('has-active', !!(g && g.items.some(ni => ni.classList.contains('active'))));
    });
  }
  const CHEV = '<svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>';
  function rebuild() {
    let bar = document.getElementById('cd-bar');
    if (current() === 'classic') { if (bar) bar.replaceChildren(); const lb = document.getElementById('cd-links-btn'); if (lb) lb.remove(); return; }
    const header = document.querySelector('header');
    if (!header) return;
    if (!bar) {
      bar = el('div', null, null, { id: 'cd-bar' });
      const gs = header.querySelector('.gsearch');
      header.insertBefore(bar, gs || header.querySelector('.hsp'));
    }
    bar.replaceChildren();
    groups().forEach(g => {
      const b = el('button', null, 'cd-grp', { type: 'button' });
      b.appendChild(el('span', g.title));
      b.insertAdjacentHTML('beforeend', CHEV);   // constante, jamais de donnée externe
      b._g = g;
      b.addEventListener('click', () => openGroup(b, g));
      bar.appendChild(b);
    });
    // Liens (documentation, site, dépôt…) : le menu latéral est masqué en Conductor, on les remet dans l'en-tête
    // (icône seule, hors de la barre de menus qui est déjà pleine).
    const old = document.getElementById('cd-links-btn'); if (old) old.remove();
    const links = [...document.querySelectorAll('#nav-footer a[href]')].filter(a => /^https?:/i.test(a.getAttribute('href')))
      .map(a => ({ href: a.getAttribute('href'), text: (a.getAttribute('title') || a.textContent).trim() }));
    if (links.length) {
      const b = el('button', null, 'cd-grp cd-links', { id: 'cd-links-btn', type: 'button', title: tr('ui.links', 'Liens'), 'aria-label': tr('ui.links', 'Liens') });
      b.insertAdjacentHTML('beforeend', '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 2.5h7.5A2.5 2.5 0 0 1 13 5v8.5H5.5A2.5 2.5 0 0 1 3 11z"/><path d="M3 11a2.5 2.5 0 0 1 2.5-2.5H13"/></svg>');
      b._g = { links, items: [] };
      b.addEventListener('click', () => openGroup(b, b._g));
      header.insertBefore(b, header.querySelector('.notif-center') || null);
    }
    refreshActive();
  }

  function initSwitcher() {
    if (document.getElementById('ui-switcher')) return;
    const header = document.querySelector('header');
    if (!header) return;
    const sw = el('div', null, 'ui-switcher', { id: 'ui-switcher', title: tr('ui.title', 'Interface') });
    [['classic', tr('ui.classic', 'Classique')], ['light', tr('ui.light', 'Clair')], ['dark', tr('ui.dark', 'Sombre')]].forEach(([k, name]) => {
      const b = el('button', name, 'ui-btn', { type: 'button', 'data-ui': k });
      b.addEventListener('click', () => set(k));
      sw.appendChild(b);
    });
    const ref = header.querySelector('.theme-switcher') || header.querySelector('.lang-switcher');
    header.insertBefore(sw, ref);
  }

  let timer = null;
  function schedule() { clearTimeout(timer); timer = setTimeout(() => { rebuild(); }, 80); }
  function uiInit() {
    initSwitcher();
    apply(current());
    const nav = document.querySelector('nav');
    if (nav) {
      new MutationObserver((muts) => {
        // reconstruit si un titre/visibilité change ; sinon simple rafraîchissement du surlignage
        if (muts.some(m => m.type === 'attributes' && m.attributeName === 'style')) schedule(); else refreshActive();
      }).observe(nav, { subtree: true, attributes: true, attributeFilter: ['class', 'style'] });
    }
    const nf = document.getElementById('nav-footer');
    if (nf) new MutationObserver(schedule).observe(nf, { childList: true });
    if (typeof window.setLang === 'function' && !window.setLang._ui) {
      const orig = window.setLang;
      window.setLang = function () { const r = orig.apply(this, arguments); schedule(); const sw = document.getElementById('ui-switcher'); if (sw) { sw.remove(); initSwitcher(); apply(current()); } return r; };
      window.setLang._ui = true;
    }
    setTimeout(rebuild, 600);   // menu admin / visibilité chargés après /api/auth/me
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', uiInit); else uiInit();
  window.uiThemeSet = set;
})();
