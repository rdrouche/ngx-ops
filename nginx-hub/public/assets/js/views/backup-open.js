import { t } from '../i18n.js';
// Ouverture d'une sauvegarde dans le navigateur (#118) : téléchargement de l'archive telle que stockée, déchiffrement LOCAL
// (la phrase de passe ne part jamais vers le Hub), navigation dans les fichiers, aperçu texte, téléchargement d'un fichier ou du tar.gz.
import { h, mount } from '../dom.js';
import { bytes, dateTime, toast } from '../util.js';
import { modal } from './instance-form.js';
import { isNgxb, decryptNgxb, gunzip, parseTar, readEntry, looksText } from '../ngxb.js';

const MAX_PREVIEW = 512 * 1024;

function saveBlob(data, name) {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
  // h() filtre les href non http(s)/# : un lien blob: doit être posé directement (URL créée localement, jamais issue du serveur)
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
const base = (p) => String(p).split('/').pop() || 'fichier';

/** @param {{id:string,received_at:number,size_bytes:number,encrypted:boolean}} b  @param {string} label  nom court de l'instance (nom de fichier) */
export function openBackup(b, label = 'sauvegarde') {
  let tarGz = null, tar = null, files = [];
  const body = h('div', { class: 'dialog-b' });
  const foot = h('div', { class: 'dialog-f' });
  const m = modal(t('Ouvrir la sauvegarde du {d}', { d: dateTime(b.received_at) }), body, foot, () => { tarGz = null; tar = null; files = []; });
  const closeBtn = () => h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Fermer');
  const fail = (msg) => { mount(body, h('p', { class: 'err-txt', role: 'alert' }, msg)); mount(foot, closeBtn()); };

  function browse() {
    const viewer = h('pre', { class: 'bk-view mono', tabindex: '0' }, t('Choisissez un fichier à afficher.'));
    const viewHead = h('div', { class: 'bk-viewhead' });
    const list = h('div', { class: 'bk-list', role: 'listbox', 'aria-label': t('Fichiers de la sauvegarde') });
    const filter = h('input', { type: 'search', class: 'input', placeholder: 'Rechercher un fichier', 'aria-label': 'Rechercher un fichier', autocomplete: 'off' });

    function show(e) {
      const data = readEntry(tar, e);
      const dl = h('button', { class: 'btn sm', type: 'button', onClick: () => saveBlob(data, base(e.path)) }, 'Télécharger ce fichier');
      mount(viewHead, h('b', { class: 'mono' }, e.path), h('span', { class: 'muted' }, ` · ${bytes(e.size)}`), ' ', dl);
      if (e.size <= MAX_PREVIEW && looksText(data)) viewer.textContent = new TextDecoder().decode(data);
      else viewer.textContent = t('Fichier binaire ou trop volumineux pour l’aperçu ({b}) : téléchargez-le.', { b: bytes(e.size) });
    }
    function paint() {
      const q = filter.value.trim().toLowerCase();
      const rows = files.filter((e) => !q || e.path.toLowerCase().includes(q));
      mount(list, rows.length ? rows.map((e) => h('button', { class: 'bk-file', type: 'button', role: 'option', onClick: () => show(e) },
        h('span', { class: 'mono' }, e.path), h('span', { class: 'muted num' }, bytes(e.size)))) : h('div', { class: 'empty' }, 'Aucun fichier ne correspond.'));
    }
    filter.addEventListener('input', paint);
    const total = files.reduce((s, e) => s + e.size, 0);
    mount(body,
      h('p', { class: 'muted' }, t('{n} fichier(s) · {b}', { n: files.length, b: bytes(total) })),
      filter,
      h('div', { class: 'bk-split' }, list, h('div', { class: 'bk-pane' }, viewHead, viewer)));
    mount(foot,
      h('button', { class: 'btn', type: 'button', onClick: () => saveBlob(tarGz, `${label}.tar.gz`) }, 'Télécharger le tar.gz'),
      closeBtn());
    paint();
  }

  async function unpack(gz) {
    try {
      tarGz = gz; tar = await gunzip(gz); files = parseTar(tar);
      browse();
    } catch (e) { fail(t(e.message)); }
  }

  function askPassphrase(buf) {
    const pass = h('input', { type: 'password', class: 'input', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Phrase de passe de la sauvegarde' });
    const status = h('p', { class: 'muted', role: 'status' });
    const go = h('button', { class: 'btn primary', type: 'button' }, 'Déchiffrer');
    async function run() {
      if (!pass.value) { status.textContent = t('Saisissez la phrase de passe.'); return; }
      go.disabled = true; pass.disabled = true; status.textContent = t('Déchiffrement… {p} %', { p: 0 });
      try {
        const gz = await decryptNgxb(buf, pass.value, { onProgress: (x) => { status.textContent = t('Déchiffrement… {p} %', { p: Math.round(x * 100) }); } });
        pass.value = '';
        await unpack(gz);
      } catch (e) {
        pass.disabled = false; go.disabled = false; pass.select(); status.textContent = t(e.message);
        status.className = 'err-txt';
      }
    }
    go.addEventListener('click', run);
    pass.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    mount(body,
      h('div', { class: 'fld' }, h('label', null, 'Phrase de passe de la sauvegarde'), pass,
        h('span', { class: 'hint' }, 'Utilisée uniquement dans ce navigateur pour déchiffrer l’archive : elle n’est jamais envoyée au Hub.')),
      status);
    mount(foot, closeBtn(), go);
    pass.focus();
  }

  mount(body, h('p', { class: 'muted', role: 'status' }, 'Téléchargement de l’archive…'));
  mount(foot, closeBtn());
  fetch(`/api/hub/v1/backups/${encodeURIComponent(b.id)}/download`, { credentials: 'same-origin', cache: 'no-store' })
    .then(async (res) => {
      if (!res.ok) throw new Error(res.status === 410 ? t('Archive absente du disque du Hub.') : t('Erreur {s}', { s: res.status }));
      const buf = new Uint8Array(await res.arrayBuffer());
      if (isNgxb(buf)) askPassphrase(buf); else await unpack(buf);
    })
    .catch((e) => { toast(e.message); fail(e.message); });
}
