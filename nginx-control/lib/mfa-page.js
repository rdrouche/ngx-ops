'use strict';
/** Page de seconde étape de connexion (MFA) — rendue côté serveur, sans dépendance. */
const SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace";
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const TXT = {
  fr: { title: 'Vérification en deux étapes', sub: 'Saisissez le code de votre application d’authentification.',
        code: 'Code à 6 chiffres', btn: 'Valider', key: 'Utiliser ma clé de sécurité', or: 'ou',
        recovery: 'Utiliser un code de secours', recLabel: 'Code de secours', back: 'Retour à la connexion',
        keyOnly: 'Touchez votre clé de sécurité pour continuer.', keyErr: 'Clé refusée ou annulée.' },
  en: { title: 'Two-step verification', sub: 'Enter the code from your authenticator app.',
        code: '6-digit code', btn: 'Verify', key: 'Use my security key', or: 'or',
        recovery: 'Use a recovery code', recLabel: 'Recovery code', back: 'Back to sign in',
        keyOnly: 'Touch your security key to continue.', keyErr: 'Key rejected or cancelled.' },
};

function mfaPage({ error = '', lang = 'en', hasTotp = true, hasKeys = false, recovery = false } = {}) {
  const L = TXT[lang === 'fr' ? 'fr' : 'en'];
  return `<!DOCTYPE html><html lang="${lang === 'fr' ? 'fr' : 'en'}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NGX Ops — MFA</title><link rel="icon" type="image/svg+xml" href="/assets/logo.svg">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:#0a0b0d;display:flex;align-items:center;justify-content:center;font-family:${SANS}}
.wrap{width:100%;max-width:380px;padding:20px}.card{background:#14171d;border:1px solid #ffffff0f;border-radius:14px;padding:40px 36px}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:28px;justify-content:center}.logo-img{width:40px;height:40px}
.logo-text{font-size:20px;font-weight:800;color:#e8eaf0;letter-spacing:-.5px}
h1{font-size:15px;font-weight:700;color:#e8eaf0;margin-bottom:8px;text-align:center}
.sub{font-size:12px;color:#8a93a8;text-align:center;margin-bottom:22px;font-family:${MONO}}
label{display:block;font-family:${MONO};font-size:11px;color:#8a93a8;margin-bottom:5px}
input{width:100%;background:#1c202a;border:1px solid #ffffff18;border-radius:6px;color:#e8eaf0;font-family:${MONO};font-size:18px;letter-spacing:4px;text-align:center;padding:10px 14px;outline:none;margin-bottom:16px}
input:focus{border-color:#00e87a;box-shadow:0 0 0 2px #00e87a22}
button,.lnk{width:100%;padding:12px;background:#00e87a;color:#000;font-family:${SANS};font-size:14px;font-weight:700;border:none;border-radius:6px;cursor:pointer;display:block;text-align:center;text-decoration:none}
button.sec{background:#1c202a;color:#e8eaf0;border:1px solid #ffffff18;margin-top:10px}
.sep{color:#5a6278;text-align:center;font-size:11px;margin:14px 0 4px;font-family:${MONO}}
.small{display:block;text-align:center;margin-top:16px;font-size:12px;color:#8a93a8;font-family:${MONO};text-decoration:underline}
.error{background:#ff4d6a22;border:1px solid #ff4d6a44;border-radius:6px;color:#ff4d6a;font-family:${MONO};font-size:12px;padding:10px 14px;margin-bottom:16px;display:${error ? 'block' : 'none'}}
</style></head><body><div class="wrap"><div class="card">
<div class="logo"><img class="logo-img" src="/assets/logo.svg" alt="" width="40" height="40"><div class="logo-text">NGX Ops</div></div>
<h1>${L.title}</h1><div class="sub">${hasTotp || recovery ? L.sub : L.keyOnly}</div>
<div class="error" id="mfa-err">${esc(error)}</div>
${(hasTotp || recovery) ? `<form method="POST" action="/auth/mfa">
<input type="hidden" name="mode" value="${recovery ? 'recovery' : 'totp'}">
<label>${recovery ? L.recLabel : L.code}</label>
<input type="text" name="code" ${recovery ? 'maxlength="16" placeholder="XXXXX-XXXXX" style="letter-spacing:1px;font-size:14px"' : 'inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autocomplete="one-time-code"'} autofocus required>
<button type="submit">${L.btn}</button></form>` : ''}
${hasKeys ? `${(hasTotp || recovery) ? `<div class="sep">${L.or}</div>` : ''}<button type="button" class="sec" id="mfa-key" data-err="${esc(L.keyErr)}">${L.key}</button>` : ''}
<a class="small" href="/auth/mfa?recovery=${recovery ? '0' : '1'}">${recovery ? '←' : L.recovery}</a>
<a class="small" href="/auth/login">${L.back}</a>
</div></div>${hasKeys ? '<script src="/assets/js/mfa-login.js"></script>' : ''}</body></html>`;
}

module.exports = { mfaPage, esc };
