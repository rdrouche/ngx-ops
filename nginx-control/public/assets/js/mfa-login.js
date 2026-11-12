// Seconde étape de connexion : clé de sécurité WebAuthn (YubiKey…). Page publique,
// donc pas de dépendance au reste du dashboard.
(function () {
  const btn = document.getElementById('mfa-key');
  if (!btn) return;
  const err = document.getElementById('mfa-err');
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  function fail(msg) { err.textContent = msg; err.style.display = 'block'; btn.disabled = false; }
  btn.addEventListener('click', async () => {
    btn.disabled = true; err.style.display = 'none';
    try {
      const o = await (await fetch('/auth/mfa/webauthn/options', { method: 'POST', credentials: 'same-origin' })).json();
      if (!o.publicKey) throw new Error(o.error || 'options');
      const pk = o.publicKey;
      pk.challenge = unb64u(pk.challenge);
      pk.allowCredentials = (pk.allowCredentials || []).map(c => ({ type: 'public-key', id: unb64u(c.id) }));
      const cred = await navigator.credentials.get({ publicKey: pk });
      const r = await fetch('/auth/mfa/webauthn/verify', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: b64u(cred.rawId),
          clientDataJSON: b64u(cred.response.clientDataJSON),
          authenticatorData: b64u(cred.response.authenticatorData),
          signature: b64u(cred.response.signature),
        }),
      });
      const j = await r.json();
      if (j.ok) { location.href = '/'; return; }
      fail(j.error || btn.dataset.err);
    } catch (e) { fail(btn.dataset.err); }
  });
})();
