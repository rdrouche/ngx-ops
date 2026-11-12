import { t, tp } from '../i18n.js';
// Sauvegardes : panneau par instance + page globale. Les archives chiffrées restent opaques (le Hub ne connaît pas la phrase).
import { h, mount, icon } from '../dom.js';
import { get, post, del } from '../api.js';
import { ago, dateTime, bytes, fmt, errorText, copy, toast } from '../util.js';
import { modal } from './instance-form.js';
import { openBackup } from './backup-open.js';

const SOURCE = { push: 'Envoi (push)', pull: 'Récupération (pull)' };

function secretDialog({ title, note, fields, onDone }) {
  const body = h('div', { class: 'dialog-b' },
    h('div', { class: 'banner' }, h('div', { class: 't' }, h('b', null, 'Cette valeur ne sera plus affichée.'), h('span', null, note))),
    fields.map((f) => h('div', { class: 'fld' }, h('label', null, f.label), h('div', { class: 'secret mono' }, f.value), f.hint ? h('span', { class: 'hint' }, f.hint) : null)));
  const foot = h('div', { class: 'dialog-f' },
    fields.map((f) => h('button', { class: 'btn', type: 'button', onClick: () => copy(f.value) }, t('Copier : {s}', { s: f.short }))),
    h('button', { class: 'btn primary', type: 'button', onClick: () => m.close() }, 'Terminé'));
  const m = modal(title, body, foot, onDone);
}

function state(inst) {
  if (!inst.expected) return h('span', { class: 'badge' }, 'Non configuré');
  if (inst.late) return h('span', { class: 'badge err' }, 'En retard');
  if (!inst.last_backup_at) return h('span', { class: 'badge warn' }, 'En attente');
  return h('span', { class: 'badge ok' }, 'À jour');
}

/** Panneau d'une instance. @returns {{el: HTMLElement, load: Function}} */
export function backupsPanel({ id, session, pushUrl }) {
  const canManage = session.perms.includes('backups:manage');
  const canDownload = session.perms.includes('backups:download');
  const el = h('section', { class: 'panel' });
  let data = null;

  async function act(fn, ok) { try { const r = await fn(); if (ok) toast(ok); await load(); return r; } catch (e) { toast(e.message); return null; } }

  async function genPush() {
    if (data.instance.push_enabled && !window.confirm(t('Générer un nouveau jeton d’envoi ? L’ancien cessera de fonctionner immédiatement.'))) return;
    const r = await act(() => post(`/instances/${id}/backups/push-token`));
    if (!r) return;
    secretDialog({
      title: 'Jeton d’envoi (push)', note: 'Seule son empreinte SHA-256 est conservée par le Hub.',
      fields: [
        { label: 'HUB_PUSH_TOKEN (à placer côté dashboard)', value: r.token_once, short: 'jeton' },
        { label: 'URL d’envoi du Hub', value: r.push_url || '(définir server.public_base_url dans le Hub)', short: 'URL', hint: 'Les en-têtes X-Backup-* sont ajoutés par le dashboard.' }].filter((f) => f.value),
    });
  }
  async function genPull() {
    if (data.instance.pull_enabled && !window.confirm(t('Générer un nouveau jeton de pull ? L’ancien cessera de fonctionner dès que le dashboard aura la nouvelle empreinte.'))) return;
    const r = await act(() => post(`/instances/${id}/backups/pull-token`));
    if (!r) return;
    secretDialog({
      title: 'Jeton de récupération (pull)', note: 'Stocké chiffré dans le Hub ; le dashboard ne garde que l’empreinte.',
      fields: [
        { label: 'Empreinte SHA-256 à déclarer côté dashboard', value: r.token_sha256, short: 'empreinte', hint: 'Variable HUB_BACKUP_TOKEN_SHA256 (+ backup_enable côté dashboard).' }],
    });
  }
  const revoke = (kind, label) => async () => { if (window.confirm(t(label))) await act(() => del(`/instances/${id}/backups/${kind}-token`), 'Jeton révoqué'); };
  async function pullNow(e) {
    e.currentTarget.disabled = true;
    const r = await act(() => post(`/instances/${id}/backups/pull`));
    if (r) toast(r.ok ? (r.duplicate ? 'Déjà à jour (archive identique)' : 'Sauvegarde récupérée') : errorText(r.error));
  }
  async function remove(b) {
    if (!window.confirm(t('Supprimer cette sauvegarde ({d}) ?', { d: dateTime(b.received_at) }))) return;
    await act(() => del(`/backups/${b.id}`), 'Sauvegarde supprimée');
  }

  function render() {
    const i = data.instance;
    const rows = data.items;
    mount(el,
      h('div', { class: 'panel-h' }, h('h2', null, 'Sauvegardes ', state(i)),
        canManage ? h('div', { class: 'actions' },
          i.pull_enabled ? h('button', { class: 'btn sm', type: 'button', onClick: pullNow }, icon('refresh', 14), 'Récupérer maintenant') : null,
          h('button', { class: 'btn sm', type: 'button', onClick: genPush }, i.push_enabled ? 'Renouveler le jeton d’envoi' : 'Activer l’envoi (push)'),
          h('button', { class: 'btn sm', type: 'button', onClick: genPull }, i.pull_enabled ? 'Renouveler le jeton de pull' : 'Activer la récupération (pull)')) : null),
      h('div', { class: 'panel-b' },
        h('div', { class: 'kv' },
          h('span', null, 'Dernière sauvegarde : ', h('b', null, i.last_backup_at ? `${ago(i.last_backup_at)} (${dateTime(i.last_backup_at)})` : t('aucune'))),
          h('span', null, 'Envoi : ', h('b', null, i.push_enabled ? t('actif ({h})', { h: i.push_token_hint }) : t('inactif')), canManage && i.push_enabled ? h('button', { class: 'lnk', type: 'button', onClick: revoke('push', 'Révoquer le jeton d’envoi ?') }, 'révoquer') : null),
          h('span', null, 'Pull : ', h('b', null, i.pull_enabled ? t('actif ({h})', { h: i.backup_token_hint }) : t('inactif')), canManage && i.pull_enabled ? h('button', { class: 'lnk', type: 'button', onClick: revoke('pull', 'Révoquer le jeton de pull ?') }, 'révoquer') : null),
          h('span', null, 'Stockage : ', h('b', null, t('{n} archive(s) · {b}', { n: fmt(i.count), b: bytes(i.bytes) })))),
        i.last_error ? h('p', { class: 'err-txt' }, t('Dernière tentative de pull en échec : {e}', { e: errorText(i.last_error) })) : null,
        i.late ? h('p', { class: 'err-txt' }, 'Aucune sauvegarde reçue dans le délai d’alerte configuré.') : null),
      rows.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
        h('thead', null, h('tr', null, ['Reçue', 'Origine', 'Taille', 'Fichiers', 'Version', 'Chiffrée', 'Expire', ''].map((t, k) => h('th', { scope: 'col', class: k === 2 || k === 3 ? 'r' : '' }, t)))),
        h('tbody', null, rows.map((b) => h('tr', null,
          h('td', null, h('b', null, dateTime(b.received_at)), h('div', { class: 'muted mono sha' }, b.sha256.slice(0, 16) + '…')),
          h('td', null, SOURCE[b.source] || b.source), h('td', { class: 'r num' }, bytes(b.size_bytes)), h('td', { class: 'r num' }, b.files ?? '—'),
          h('td', null, b.dashboard_version || '—'),
          h('td', null, b.encrypted ? h('span', { class: 'badge ok' }, 'Oui') : h('span', { class: `badge ${b.manifest && b.manifest.includes_secrets ? 'warn' : ''}` }, b.manifest && b.manifest.includes_secrets ? 'Non — secrets inclus' : 'Non')),
          h('td', null, dateTime(b.expires_at)),
          h('td', { class: 'r nowrap' },
            canDownload ? h('button', { class: 'btn sm', type: 'button', onClick: () => openBackup(b, `${String(i.name || 'sauvegarde').replace(/[^A-Za-z0-9._-]+/g, '_')}-${new Date(b.received_at).toISOString().slice(0, 10)}`) }, 'Ouvrir') : null, ' ',
            canDownload ? h('a', { class: 'btn sm', href: `/api/hub/v1/backups/${b.id}/download`, download: '' }, 'Télécharger') : null, ' ',
            canManage ? h('button', { class: 'btn sm danger', type: 'button', onClick: () => remove(b) }, 'Supprimer') : null)))))) : h('div', { class: 'empty' }, i.expected ? 'Aucune archive reçue pour l’instant.' : 'Activez l’envoi (push) ou la récupération (pull) pour suivre les sauvegardes de cette instance.'),
      h('div', { class: 'panel-b' }, h('p', { class: 'muted' }, 'Le Hub stocke les archives telles que reçues et ne connaît jamais la phrase de passe : une archive chiffrée se déchiffre localement. La restauration n’est pas proposée ici (phase 2).')));
  }

  async function load() {
    try { data = await get(`/instances/${id}/backups`); render(); } catch (e) { if (e.code !== 'unauthenticated') mount(el, h('div', { class: 'empty' }, e.message)); }
  }
  return { el, load };
}

/** Page globale « Sauvegardes ». */
export function backupsView(root) {
  const body = h('div', { class: 'stack' });
  let timer = null;
  async function load() {
    try {
      const d = await get('/backups');
      const exp = d.items.filter((i) => i.expected && i.enabled);
      const late = exp.filter((i) => i.late);
      mount(body,
        late.length ? h('div', { class: 'banner err', role: 'status' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, tp('{n} instance sans sauvegarde récente', '{n} instances sans sauvegarde récente', late.length)), h('span', null, t('Délai d’alerte : {h} h.', { h: d.policy.alert_after_hours })))) : null,
        h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Sauvegardes par instance')),
          d.items.length ? h('div', { class: 'tbl-wrap' }, h('table', null,
            h('thead', null, h('tr', null, ['Instance', 'État', 'Envoi', 'Pull', 'Dernière sauvegarde', 'Archives', 'Volume'].map((t, k) => h('th', { scope: 'col', class: k >= 5 ? 'r' : '' }, t)))),
            h('tbody', null, d.items.map((i) => h('tr', { class: 'click', tabindex: '0', onClick: () => { window.location.hash = `#/i/${i.instance_id}`; }, onKeydown: (e) => { if (e.key === 'Enter') window.location.hash = `#/i/${i.instance_id}`; } },
              h('td', null, h('b', null, i.name)), h('td', null, state(i)), h('td', null, i.push_enabled ? 'actif' : '—'), h('td', null, i.pull_enabled ? 'actif' : '—'),
              h('td', null, i.last_backup_at ? ago(i.last_backup_at) : '—', i.last_error ? h('div', { class: 'err-txt' }, errorText(i.last_error)) : null),
              h('td', { class: 'r num' }, fmt(i.count)), h('td', { class: 'r num' }, bytes(i.bytes)))))))
            : h('div', { class: 'empty' }, 'Aucune instance.')),
        h('section', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', null, 'Politique du Hub')), h('div', { class: 'panel-b kv' },
          h('span', null, 'Rétention maximale : ', h('b', null, t('{n} jours', { n: d.policy.retention_days }))), h('span', null, 'Alerte après : ', h('b', null, `${d.policy.alert_after_hours} h`)),
          h('span', null, 'Pull planifié : ', h('b', null, d.policy.pull_enabled ? t('toutes les {h} h', { h: d.policy.pull_interval_hours }) : t('désactivé'))), h('span', null, 'Taille max. : ', h('b', null, t('{n} Mo', { n: d.policy.max_archive_mb }))),
          h('span', null, 'URL d’envoi : ', h('b', { class: 'mono' }, d.push_url || 'définir server.public_base_url')))));
    } catch (e) { if (e.code !== 'unauthenticated') mount(body, h('div', { class: 'panel' }, h('div', { class: 'empty' }, e.message))); }
  }
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, 'Sauvegardes'), h('p', null, 'Archives de configuration reçues ou récupérées depuis les dashboards NGX Ops.'))), body);
  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 60_000);
  return () => clearInterval(timer);
}
