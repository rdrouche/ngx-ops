import { t } from '../i18n.js';
import { h, mount } from '../dom.js';
import { post, setCsrf } from '../api.js';

function brand() {
  return h('div', { class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '▤'), h('span', null, 'NGX Ops Hub'));
}

/** Étape 1 (identifiants) puis étape 2 (code TOTP). `step` = 'password' | 'mfa'. */
export function loginView(root, { step = 'password', onDone }) {
  const err = h('p', { class: 'formerr', role: 'alert' });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, step === 'mfa' ? 'Valider' : 'Se connecter');
  let fields; let path; let build;

  if (step === 'mfa') {
    const code = h('input', { class: 'field', id: 'code', name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '7', pattern: '[0-9 ]*', required: true, autofocus: true });
    fields = [h('div', { class: 'fld' }, h('label', { for: 'code' }, 'Code à 6 chiffres'), code, h('span', { class: 'hint' }, 'Application d’authentification (TOTP).'))];
    path = '/auth/mfa/verify'; build = () => ({ code: code.value });
  } else {
    const user = h('input', { class: 'field', id: 'u', name: 'username', autocomplete: 'username', required: true, autofocus: true });
    const pw = h('input', { class: 'field', id: 'p', name: 'password', type: 'password', autocomplete: 'current-password', required: true });
    fields = [h('div', { class: 'fld' }, h('label', { for: 'u' }, 'Identifiant'), user), h('div', { class: 'fld' }, h('label', { for: 'p' }, 'Mot de passe'), pw)];
    path = '/auth/login'; build = () => ({ username: user.value, password: pw.value });
  }

  const form = h('form', {
    novalidate: true,
    onSubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; submit.disabled = true;
      try { const r = await post(path, build()); setCsrf(r.csrf); onDone(r); }
      catch (ex) { err.textContent = ex.status === 429 ? t('Trop de tentatives, réessayez plus tard.') : ex.message; submit.disabled = false; }
    },
  }, ...fields, err, submit);

  mount(root, h('div', { class: 'auth' }, h('div', { class: 'auth-box' }, brand(), h('h1', { class: 'sr-only' }, 'Connexion'), form)));
}
