// ── Modale generique (#63) ──────────────────────────────────────────────
// Un bouton ouvre une modale plutot que de deplier la page. Rendu par createElement/textContent uniquement.
// Utilise les classes existantes .sched-modal / .sched-box. Fermeture : croix, clic hors de la boite, Echap.
// ngxModal({ title, wide }) -> { body, close } ; `body` recoit le contenu (aucun innerHTML).
const ngxModalStack = [];

function ngxModal({ title, wide, onClose } = {}) {
  const prevFocus = document.activeElement;
  const overlay = document.createElement('div');
  overlay.className = 'sched-modal';
  overlay.style.display = 'flex';
  const box = document.createElement('div');
  box.className = 'sched-box';
  box.style.maxWidth = wide ? '860px' : '600px';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.tabIndex = -1;

  const head = document.createElement('div');
  head.className = 'row';
  const ttl = document.createElement('div');
  ttl.className = 'ctitle'; ttl.textContent = title || '';
  ttl.id = 'ngx-modal-title-' + (ngxModalStack.length + 1);
  box.setAttribute('aria-labelledby', ttl.id);
  const x = document.createElement('button');
  x.type = 'button'; x.className = 'btn sm'; x.textContent = '✕';
  x.setAttribute('aria-label', typeof t === 'function' ? t('common.close') : 'Close');
  head.appendChild(ttl); head.appendChild(x);
  const body = document.createElement('div');
  box.appendChild(head); box.appendChild(body);
  overlay.appendChild(box);

  let closed = false;
  const modal = {
    body,
    close() {
      if (closed) return;
      closed = true;
      document.removeEventListener('keydown', onKey, true);
      const i = ngxModalStack.indexOf(modal); if (i >= 0) ngxModalStack.splice(i, 1);
      overlay.remove();
      if (prevFocus && typeof prevFocus.focus === 'function') { try { prevFocus.focus(); } catch { /* element disparu */ } }
      if (typeof onClose === 'function') onClose();
    },
  };
  function onKey(e) {
    if (e.key === 'Escape' && ngxModalStack[ngxModalStack.length - 1] === modal) { e.stopPropagation(); modal.close(); }
  }
  x.addEventListener('click', modal.close);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) modal.close(); });
  document.addEventListener('keydown', onKey, true);
  ngxModalStack.push(modal);
  document.body.appendChild(overlay);
  box.focus();
  return modal;
}
