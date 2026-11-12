// ── Sécurité du compte : MFA (TOTP + clé de sécurité) — v12.75.0 ───────────────
// Bouton bouclier dans l'en-tête → fenêtre : activer/désactiver l'application
// d'authentification (QR code), enregistrer des clés YubiKey, régénérer les
// codes de secours. Aucun innerHTML avec des valeurs serveur (textContent).
(function () {
  const tr = (k, v) => (typeof t === 'function' ? t(k, v) : k);
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const el = (tag, text, cls, attrs) => {
    const e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    if (attrs) Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
    return e;
  };
  async function post(path, body) {
    const r = await fetch('/api/mfa/' + path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    let j = {}; try { j = await r.json(); } catch { /* vide */ }
    return { ok: r.ok, status: r.status, ...j };
  }
  async function status() {
    const r = await fetch('/api/mfa/status', { credentials: 'same-origin' });
    return r.ok ? r.json() : { enabled: false, totp: false, keys: [], recoveryLeft: 0 };
  }

  function qrSvg(text) {
    const qr = qrcode(0, 'M'); qr.addData(text); qr.make();
    const n = qr.getModuleCount(), NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${n + 8} ${n + 8}`); svg.setAttribute('width', '200'); svg.setAttribute('height', '200');
    const bg = document.createElementNS(NS, 'rect');
    bg.setAttribute('width', n + 8); bg.setAttribute('height', n + 8); bg.setAttribute('fill', '#fff'); svg.appendChild(bg);
    let d = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
    const p = document.createElementNS(NS, 'path'); p.setAttribute('d', d); p.setAttribute('fill', '#000'); svg.appendChild(p);
    return svg;
  }

  let overlay = null;
  function close() { if (overlay) { overlay.remove(); overlay = null; } }
  function loadQr() {
    return new Promise((res) => {
      if (typeof qrcode === 'function') return res();
      const s = document.createElement('script'); s.src = '/assets/vendor/qrcode.js'; s.onload = () => res(); document.head.appendChild(s);
    });
  }

  async function open() {
    close();
    overlay = el('div', null, null, { style: 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:300;display:flex;align-items:flex-start;justify-content:center;padding:40px 20px;overflow:auto' });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    const box = el('div', null, null, { style: 'background:var(--bg2,#14171d);border:1px solid var(--border,#ffffff1a);border-radius:12px;padding:24px;max-width:520px;width:100%;color:var(--text,#e8eaf0)' });
    overlay.appendChild(box); document.body.appendChild(overlay);
    await render(box);
  }

  const btn = (label, fn, primary) => {
    const b = el('button', label, 'btn' + (primary ? ' btn-primary' : ''), { type: 'button', style: 'margin:4px 6px 4px 0' });
    b.addEventListener('click', fn); return b;
  };
  const askPassword = () => window.prompt(tr('mfa.askPassword')) || '';

  function showCodes(box, codes, after) {
    box.replaceChildren();
    box.appendChild(el('h3', tr('mfa.codes.title'), null, { style: 'margin-bottom:8px' }));
    box.appendChild(el('p', tr('mfa.codes.help'), null, { style: 'font-size:12px;opacity:.8;margin-bottom:12px' }));
    const pre = el('pre', codes.join('\n'), null, { style: 'background:#0006;padding:12px;border-radius:8px;font-size:14px;letter-spacing:1px;user-select:all' });
    box.appendChild(pre);
    box.appendChild(btn(tr('mfa.codes.copy'), () => { if (typeof copyToClipboard === 'function') copyToClipboard(codes.join('\n')); }));
    box.appendChild(btn(tr('mfa.codes.done'), after, true));
  }

  async function render(box) {
    const st = await status();
    box.replaceChildren();
    const head = el('div', null, null, { style: 'display:flex;justify-content:space-between;align-items:center;margin-bottom:12px' });
    head.appendChild(el('h3', tr('mfa.title')));
    head.appendChild(btn('✕', close));
    box.appendChild(head);
    box.appendChild(el('p', tr(st.enabled ? 'mfa.on' : 'mfa.off'), null, { style: 'font-size:13px;margin-bottom:16px;color:' + (st.enabled ? '#00e87a' : '#ffb020') }));
    const msg = el('div', '', null, { style: 'font-size:12px;color:#ff4d6a;min-height:16px;margin-bottom:8px' });

    // — TOTP
    const sec1 = el('div', null, null, { style: 'margin-bottom:18px' });
    sec1.appendChild(el('strong', tr('mfa.totp.title')));
    sec1.appendChild(el('div', tr(st.totp ? 'mfa.totp.on' : 'mfa.totp.off'), null, { style: 'font-size:12px;opacity:.8;margin:4px 0 8px' }));
    if (!st.totp) {
      sec1.appendChild(btn(tr('mfa.totp.enable'), async () => {
        await loadQr();
        const s = await post('totp/setup');
        if (!s.secret) { msg.textContent = tr('mfa.error'); return; }
        const zone = el('div', null, null, { style: 'margin-top:10px;text-align:center' });
        zone.appendChild(qrSvg(s.uri));
        zone.appendChild(el('div', tr('mfa.totp.scan'), null, { style: 'font-size:12px;margin:8px 0' }));
        zone.appendChild(el('code', s.secret, null, { style: 'font-size:12px;user-select:all;word-break:break-all' }));
        const inp = el('input', null, null, { type: 'text', inputmode: 'numeric', maxlength: '7', placeholder: '123456', autocomplete: 'one-time-code', style: 'display:block;margin:12px auto;text-align:center;letter-spacing:4px;width:160px' });
        zone.appendChild(inp);
        zone.appendChild(btn(tr('mfa.totp.confirm'), async () => {
          const r = await post('totp/confirm', { code: inp.value });
          if (!r.ok) { msg.textContent = tr('mfa.totp.badCode'); return; }
          if (r.recoveryCodes) showCodes(box, r.recoveryCodes, () => render(box)); else render(box);
        }, true));
        sec1.appendChild(zone);
      }, true));
    } else {
      sec1.appendChild(btn(tr('mfa.totp.disable'), async () => {
        const pw = askPassword(); if (!pw) return;
        const r = await post('totp/disable', { password: pw });
        if (!r.ok) { msg.textContent = tr('mfa.badPassword'); return; }
        render(box);
      }));
    }
    box.appendChild(sec1);

    // — Clés de sécurité
    const sec2 = el('div', null, null, { style: 'margin-bottom:18px' });
    sec2.appendChild(el('strong', tr('mfa.keys.title')));
    if (!window.PublicKeyCredential) sec2.appendChild(el('div', tr('mfa.keys.unsupported'), null, { style: 'font-size:12px;opacity:.8;margin:4px 0' }));
    (st.keys || []).forEach(k => {
      const row = el('div', null, null, { style: 'display:flex;justify-content:space-between;align-items:center;font-size:12px;margin:6px 0' });
      row.appendChild(el('span', '🔑 ' + k.name + ' — ' + String(k.createdAt || '').slice(0, 10)));
      row.appendChild(btn(tr('mfa.keys.remove'), async () => {
        const pw = askPassword(); if (!pw) return;
        const r = await post('webauthn/delete', { id: k.id, password: pw });
        if (!r.ok) { msg.textContent = tr('mfa.badPassword'); return; }
        render(box);
      }));
      sec2.appendChild(row);
    });
    if (window.PublicKeyCredential) {
      const addWrap = el('div', null, null, { style: 'margin-top:8px' });
      sec2.appendChild(addWrap);
      addWrap.appendChild(btn(tr('mfa.keys.add'), async () => {
        try {
          const name = window.prompt(tr('mfa.keys.askName'), 'YubiKey') || 'Security key';
          const o = await post('webauthn/options');
          const pk = o.publicKey; if (!pk) { msg.textContent = tr('mfa.error'); return; }
          pk.challenge = unb64u(pk.challenge); pk.user.id = unb64u(pk.user.id);
          pk.excludeCredentials = (pk.excludeCredentials || []).map(c => ({ ...c, id: unb64u(c.id) }));
          const cred = await navigator.credentials.create({ publicKey: pk });
          const r = await post('webauthn/register', {
            name, clientDataJSON: b64u(cred.response.clientDataJSON), attestationObject: b64u(cred.response.attestationObject),
          });
          if (!r.ok) { msg.textContent = tr('mfa.error') + ' ' + (r.error || ''); return; }
          if (r.recoveryCodes) showCodes(box, r.recoveryCodes, () => render(box)); else render(box);
        } catch (e) { msg.textContent = tr('mfa.keys.cancelled'); }
      }, true));
    }
    box.appendChild(sec2);

    // — Codes de secours
    if (st.enabled) {
      const sec3 = el('div', null, null);
      sec3.appendChild(el('strong', tr('mfa.codes.title')));
      sec3.appendChild(el('div', tr('mfa.codes.left', { n: st.recoveryLeft }), null, { style: 'font-size:12px;opacity:.8;margin:4px 0 8px' }));
      sec3.appendChild(btn(tr('mfa.codes.regen'), async () => {
        const pw = askPassword(); if (!pw) return;
        const r = await post('recovery/regenerate', { password: pw });
        if (!r.ok) { msg.textContent = tr('mfa.badPassword'); return; }
        showCodes(box, r.recoveryCodes, () => render(box));
      }));
      box.appendChild(sec3);
    }
    box.appendChild(msg);
  }

  function mfaInit() {
    const pill = document.getElementById('user-pill');
    if (!pill || document.getElementById('mfa-btn')) return;
    const b = el('a', null, 'logout-btn', { href: '#', id: 'mfa-btn', title: tr('mfa.title') });
    b.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.5l5 2v4c0 3-2.2 5.3-5 7-2.8-1.7-5-4-5-7v-4z"/><path d="M5.8 8l1.6 1.6L10.4 6.6"/></svg>';
    b.addEventListener('click', (e) => { e.preventDefault(); open(); });
    const logout = pill.querySelector('.logout-btn');
    pill.insertBefore(b, logout);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mfaInit); else mfaInit();
  window.mfaOpen = open;
})();
