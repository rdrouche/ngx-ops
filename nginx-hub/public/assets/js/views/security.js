import { t } from '../i18n.js';
import { h, mount } from '../dom.js';
import { post, setCsrf } from '../api.js';
import { copy, toast } from '../util.js';
import { qrSvg } from '../qr.js';

function qrCode(uri) {
  try { return qrSvg(uri, { label: 'QR code d’enrôlement MFA' }); }
  catch { return h('p', { class: 'muted' }, 'QR code indisponible : utilisez la clé ci-dessous.'); }
}

function groups(secret) { return secret.match(/.{1,4}/g).join(' '); }

/** Enrôlement MFA (utilisé aussi en mode « obligatoire » avant d'accéder au Hub). */
export function mfaPanel(session, { onActivated }) {
  const box = h('div', { class: 'panel-b' });
  const err = h('p', { class: 'formerr', role: 'alert' });

  const start = async () => {
    err.textContent = '';
    try {
      const r = await post('/auth/mfa/enroll');
      const code = h('input', { class: 'field', id: 'mfa-code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', required: true });
      mount(box,
        h('p', null, 'Scannez ce QR code avec votre application d’authentification (Google Authenticator, Aegis, 1Password…), puis confirmez avec le code à 6 chiffres.'),
        h('div', { class: 'qr-wrap' }, qrCode(r.otpauth_uri)),
        h('div', { class: 'fld' }, h('label', null, 'Ou saisie manuelle de la clé'), h('div', { class: 'secret mono' }, groups(r.secret)),
          h('div', { class: 'actions' }, h('button', { class: 'btn sm', type: 'button', onClick: () => copy(r.secret) }, 'Copier la clé'), h('button', { class: 'btn sm', type: 'button', onClick: () => copy(r.otpauth_uri) }, 'Copier l’URI otpauth'))),
        h('div', { class: 'fld' }, h('label', { for: 'mfa-code' }, 'Code de confirmation'), code),
        err,
        h('button', { class: 'btn primary', type: 'button', onClick: async () => {
          err.textContent = '';
          try { const s = await post('/auth/mfa/confirm', { code: code.value }); setCsrf(s.csrf); toast('MFA activé'); onActivated(s); }
          catch (ex) { err.textContent = ex.message; }
        } }, 'Activer le MFA'));
    } catch (ex) { err.textContent = ex.message; }
  };

  if (session.mfa_enabled) mount(box, h('p', null, h('span', { class: 'badge ok' }, 'MFA activé'), ' Pour le réinitialiser, un administrateur utilise la CLI : ', h('span', { class: 'mono' }, 'hub-admin reset-mfa <utilisateur>')));
  else mount(box, h('p', { class: 'muted' }, session.mfa_policy === 'required' ? 'Le MFA est obligatoire pour accéder au Hub.' : 'Le MFA est recommandé.'), err, h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'button', onClick: start }, 'Activer le MFA')));
  return h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Double authentification (TOTP)')), box);
}

export function passwordPanel(onChanged, { forced = false } = {}) {
  const cur = h('input', { class: 'field', id: 'pw-cur', type: 'password', autocomplete: 'current-password', required: true });
  const nxt = h('input', { class: 'field', id: 'pw-new', type: 'password', autocomplete: 'new-password', minlength: '12', required: true });
  const err = h('p', { class: 'formerr', role: 'alert' });
  const form = h('form', { class: 'panel-b dialog-b', novalidate: true, onSubmit: async (e) => {
    e.preventDefault(); err.textContent = '';
    try { const s = await post('/auth/password', { current: cur.value, next: nxt.value }); setCsrf(s.csrf); cur.value = ''; nxt.value = ''; toast('Mot de passe modifié (autres sessions révoquées)'); onChanged?.(s); }
    catch (ex) { err.textContent = ex.message; }
  } },
  h('div', { class: 'fld' }, h('label', { for: 'pw-cur' }, forced ? 'Mot de passe initial (affiché dans les logs)' : 'Mot de passe actuel'), cur),
  h('div', { class: 'fld' }, h('label', { for: 'pw-new' }, 'Nouveau mot de passe'), nxt, h('span', { class: 'hint' }, '12 caractères minimum.')),
  err, h('div', null, h('button', { class: 'btn primary', type: 'submit' }, 'Changer le mot de passe')));
  return h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Mot de passe')), form);
}

export function securityView(root, { session, onSessionChange, onLogout }) {
  mount(root,
    h('div', { class: 'page-h' }, h('div', null, h('h1', null, 'Sécurité du compte'), h('p', null, t('Connecté en tant que {u} ({r}).', { u: session.user.username, r: session.user.role === 'admin' ? t('administrateur') : t('lecture seule') }))),
      h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onClick: onLogout }, 'Se déconnecter'))),
    h('div', { class: 'cols' }, h('div', { class: 'main' }, mfaPanel(session, { onActivated: onSessionChange })), h('div', { class: 'side' }, passwordPanel(onSessionChange))));
}

/** Écran bloquant : MFA obligatoire non encore activé. */
export function enrollmentGate(root, { session, onSessionChange, onLogout }) {
  mount(root, h('div', { class: 'auth' }, h('div', { class: 'auth-box' },
    h('div', { class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '▤'), h('span', null, 'NGX Ops Hub')),
    h('h1', { class: 'sr-only' }, 'Activation du MFA'), mfaPanel(session, { onActivated: onSessionChange }),
    h('button', { class: 'btn', type: 'button', onClick: onLogout }, 'Se déconnecter'))));
}

/** Écran bloquant : premier accès avec un mot de passe initial (compte admin créé au démarrage). */
export function passwordGate(root, { onSessionChange, onLogout }) {
  mount(root, h('div', { class: 'auth' }, h('div', { class: 'auth-box' },
    h('div', { class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '▤'), h('span', null, 'NGX Ops Hub')),
    h('h1', { class: 'sr-only' }, 'Changement du mot de passe'),
    h('p', null, 'Premier accès : choisissez un nouveau mot de passe personnel avant de continuer.'),
    passwordPanel(onSessionChange, { forced: true }),
    h('button', { class: 'btn', type: 'button', onClick: onLogout }, 'Se déconnecter'))));
}
