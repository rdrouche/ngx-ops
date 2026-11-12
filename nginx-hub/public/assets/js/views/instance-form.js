import { t } from '../i18n.js';
import { h, mount } from '../dom.js';
import { post, patch, del } from '../api.js';
import { copy, toast } from '../util.js';

export function modal(title, body, footer, onClose) {
  const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey); onClose?.(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const scrim = h('div', { class: 'scrim', onMousedown: (e) => { if (e.target === scrim) close(); } },
    h('div', { class: 'dialog wide', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'dialog-h' }, h('h2', null, title), h('button', { class: 'ibtn', type: 'button', 'aria-label': 'Fermer', onClick: close }, '✕')),
      body, footer));
  document.addEventListener('keydown', onKey);
  document.body.append(scrim);
  return { close, scrim };
}

/** Affiche une seule fois le token (création / rotation) + le hash à déposer côté dashboard. */
function revealToken(r, { title, onDone }) {
  const body = h('div', { class: 'dialog-b' },
    h('div', { class: 'banner' }, h('div', { class: 't' }, h('b', null, 'Ce jeton ne sera plus affiché.'), h('span', null, 'Il est stocké chiffré dans le Hub. Notez-le uniquement si vous devez le ressaisir.'))),
    h('div', { class: 'fld' }, h('label', null, 'Jeton Hub (envoyé par le Hub dans X-Hub-Token)'), h('div', { class: 'secret mono' }, r.token_once)),
    h('div', { class: 'fld' }, h('label', null, 'Empreinte SHA-256 à déclarer côté dashboard'), h('div', { class: 'secret mono' }, r.token_sha256),
      h('span', { class: 'hint' }, 'Variable d’environnement du dashboard : HUB_TOKEN_SHA256 (plusieurs empreintes séparées par des virgules pendant une rotation).')));
  const foot = h('div', { class: 'dialog-f' },
    h('button', { class: 'btn', type: 'button', onClick: () => copy(r.token_once) }, 'Copier le jeton'),
    h('button', { class: 'btn', type: 'button', onClick: () => copy(r.token_sha256) }, 'Copier l’empreinte'),
    h('button', { class: 'btn primary', type: 'button', onClick: () => m.close() }, 'Terminé'));
  const m = modal(title, body, foot, onDone);
}

/** Création (instance absente) ou édition. */
export function instanceDialog({ instance, onSaved, onDeleted }) {
  const editing = !!instance;
  const name = h('input', { class: 'field', id: 'f-name', value: instance?.name || '', maxlength: '60', required: true });
  const url = h('input', { class: 'field', id: 'f-url', value: instance?.url || '', placeholder: 'https://dashboard.exemple.org', required: true, inputmode: 'url' });
  const tags = h('input', { class: 'field', id: 'f-tags', value: (instance?.tags || []).join(', '), placeholder: 'prod, paris' });
  const token = h('input', { class: 'field mono', id: 'f-token', autocomplete: 'off', spellcheck: 'false', placeholder: 'Laisser vide pour générer un jeton' });
  const enabled = h('input', { id: 'f-en', type: 'checkbox', checked: instance ? instance.enabled : true });
  const err = h('p', { class: 'formerr', role: 'alert' });

  const parseTags = () => tags.value.split(',').map((t) => t.trim()).filter(Boolean);

  const save = async () => {
    err.textContent = ''; saveBtn.disabled = true;
    try {
      if (editing) {
        const r = await patch(`/instances/${instance.id}`, { name: name.value, url: url.value, tags: parseTags(), enabled: enabled.checked });
        m.close(); toast('Instance mise à jour'); onSaved(r);
      } else {
        const body = { name: name.value, url: url.value, tags: parseTags(), enabled: enabled.checked };
        if (token.value.trim()) body.token = token.value.trim();
        const r = await post('/instances', body);
        m.close();
        revealToken(r, { title: 'Instance créée', onDone: () => onSaved(r.instance) });
      }
    } catch (ex) { err.textContent = ex.message; saveBtn.disabled = false; }
  };

  const rotate = async () => {
    if (!window.confirm(t('Renouveler le jeton ? L’ancien cessera de fonctionner dès que le dashboard aura la nouvelle empreinte.'))) return;
    try { const r = await post(`/instances/${instance.id}/rotate-token`, {}); m.close(); revealToken(r, { title: 'Nouveau jeton', onDone: () => onSaved(instance) }); }
    catch (ex) { err.textContent = ex.message; }
  };
  const remove = async () => {
    if (!window.confirm(t('Supprimer « {n} » et son historique ?', { n: instance.name }))) return;
    try { await del(`/instances/${instance.id}`); m.close(); toast('Instance supprimée'); onDeleted?.(); } catch (ex) { err.textContent = ex.message; }
  };

  const saveBtn = h('button', { class: 'btn primary', type: 'submit' }, editing ? 'Enregistrer' : 'Ajouter');
  const form = h('form', { class: 'dialog-b', novalidate: true, onSubmit: (e) => { e.preventDefault(); save(); } },
    h('div', { class: 'fld' }, h('label', { for: 'f-name' }, 'Nom'), name),
    h('div', { class: 'fld' }, h('label', { for: 'f-url' }, 'URL du dashboard'), url, h('span', { class: 'hint' }, 'HTTPS obligatoire. Sans paramètres ni identifiants.')),
    h('div', { class: 'fld' }, h('label', { for: 'f-tags' }, 'Étiquettes'), tags, h('span', { class: 'hint' }, 'Séparées par des virgules (8 max).')),
    editing ? null : h('div', { class: 'fld' }, h('label', { for: 'f-token' }, 'Jeton Hub (optionnel)'), token),
    h('label', { class: 'check' }, enabled, 'Collecte activée'),
    err,
    h('div', { class: 'actions' }, saveBtn, editing ? h('button', { class: 'btn', type: 'button', onClick: rotate }, 'Renouveler le jeton') : null, editing ? h('button', { class: 'btn danger', type: 'button', onClick: remove }, 'Supprimer') : null));
  const m = modal(editing ? t('Modifier « {n} »', { n: instance.name }) : t('Ajouter une instance'), form, null);
  name.focus();
}
