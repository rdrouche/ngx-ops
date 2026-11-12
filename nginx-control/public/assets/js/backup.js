'use strict';
/**
 * Page "Sauvegardes" — liste, création (local/Git/les deux), téléchargement,
 * restauration et suppression des backups. Extrait de public/index.html
 * (voir CHANGELOG.md). Le bouton Restaurer est masqué côté serveur quand
 * Git est configuré (voir README.md, "Git configuré = source de vérité").
 */
async function loadBackupsPage() {
  loadBackupS3Card(); // #117 : carte « Destination S3 » (indépendante de la liste locale)
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Chargement…</div>';
  const d = await api('/backups').catch(() => null);
  if (!d) { el.innerHTML = '<div style="color:var(--red)">Erreur API</div>'; return; }

  document.getElementById('bkp-count').textContent = d.backups?.length || 0;
  document.getElementById('bkp-keep-label').textContent = d.keep || '—';

  // Restaurer une sauvegarde locale desynchroniserait le depot Git (source
  // de verite une fois configure) sans que rien ne le signale ensuite — le
  // serveur refuse deja la requete (403, voir POST /api/backups/restore),
  // ce bandeau/bouton masque evite juste de laisser cliquer pour rien.
  const gitNote = document.getElementById('bkp-git-note');
  if (gitNote) gitNote.style.display = d.gitConfigured ? '' : 'none';

  if (!d.backups?.length) {
    el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Aucune sauvegarde</div>';
    return;
  }

  el.innerHTML = d.backups.map(b => {
    const safeName = b.name.replace(/'/g, "\'");
    const restoreBtn = d.gitConfigured ? '' : `
        <button class="btn sm" onclick="restoreBackup('${safeName}')" title="Restaurer">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M3 8a5 5 0 1 0 1-2.9"/><polyline points="1,4 3,8 7,6"/></svg>
          Restaurer
        </button>`;
    return `<div class="bkp-row">
      <svg viewBox="0 0 16 16" fill="none" stroke="var(--text3)" stroke-width="1.5" width="14" height="14" style="flex-shrink:0"><path d="M4 2h6l4 4v8a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><path d="M10 2v4h4"/></svg>
      <span class="bkp-name" title="${b.name}">${b.name}</span>
      <span class="bkp-size">${fmtB(b.size)}</span>
      <span style="color:var(--text3);font-family:monospace;font-size:10px;min-width:70px;text-align:right">${timeAgo(b.mtime)}</span>
      <div class="bkp-actions">
        <button class="btn sm" onclick="dlBackup('${safeName}')" title="Telecharger">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="11" height="11"><path d="M8 2v8M5 11l3 3 3-3M2 14h12"/></svg>
          DL
        </button>${restoreBtn}
        <button class="btn sm danger" onclick="deleteBackup('${safeName}')" title="Supprimer">x</button>
      </div>
    </div>`;
  }).join('');
}

function backupChoiceDialog() {
  return new Promise(resolve => {
    // Remove existing dialog if any
    const existing = document.getElementById('bkp-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'bkp-dialog';
    overlay.style.cssText = 'position:fixed;inset:0;background:#00000088;z-index:9999;display:flex;align-items:center;justify-content:center';

    overlay.innerHTML = `
      <div style="background:var(--bg2);border:1px solid var(--border2);border-radius:14px;padding:28px 32px;width:380px;max-width:90vw">
        <div style="font-size:16px;font-weight:700;margin-bottom:6px;color:var(--text)">Sauvegarder maintenant</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:20px">Choisissez la destination et le label</div>
        <div style="margin-bottom:16px">
          <label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px;font-family:monospace">Label (optionnel)</label>
          <input id="bkp-dlg-label" type="text" value="manual" placeholder="manual, pre-deploy, etc."
            style="width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:6px;color:var(--text);font-family:monospace;font-size:12px;padding:8px 12px;outline:none">
        </div>
        <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px">
          <button id="bkp-opt-local" onclick="bkpPick('local')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M2 12V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v7"/><path d="M1 12h14v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-1z"/><path d="M6 8h4"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Local uniquement</div><div style="font-size:11px;color:var(--text3);font-family:monospace">ZIP dans ./backups/</div></div>
          </button>
          <button id="bkp-opt-git" onclick="bkpPick('git')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><circle cx="5" cy="4" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="11" cy="12" r="2"/><path d="M5 6v4M7 12h2"/><path d="M5 6a4 4 0 0 0 4 4"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Git uniquement</div><div style="font-size:11px;color:var(--text3);font-family:monospace">Push branche backup + tag</div></div>
          </button>
          <button id="bkp-opt-both" onclick="bkpPick('both')" class="btn primary" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="15" height="15"><path d="M2 12V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v7"/><path d="M1 12h14v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-1z"/><circle cx="11" cy="4" r="2"/><path d="M7 4h2"/></svg>
            <div style="text-align:left"><div style="font-weight:600">Local + Git</div><div style="font-size:11px;color:var(--text3);font-family:monospace">ZIP + push branche backup + tag</div></div>
          </button>
          <button id="bkp-opt-s3" onclick="bkpPick('s3')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <div style="text-align:left"><div style="font-weight:600">S3 uniquement</div><div style="font-size:11px;color:var(--text3);font-family:monospace">ZIP envoyé vers le bucket (config/backup.yml)</div></div>
          </button>
          <button id="bkp-opt-all" onclick="bkpPick('all')" class="btn" style="justify-content:flex-start;gap:10px;padding:10px 14px">
            <div style="text-align:left"><div style="font-weight:600">Local + Git + S3</div><div style="font-size:11px;color:var(--text3);font-family:monospace">Toutes les destinations configurées</div></div>
          </button>
        </div>
        <button onclick="bkpCancel()" style="width:100%;background:none;border:1px solid var(--border);border-radius:6px;color:var(--text3);padding:7px;cursor:pointer;font-family:monospace;font-size:12px">Annuler</button>
      </div>`;

    document.body.appendChild(overlay);

    window.bkpPick = (mode) => {
      const label = document.getElementById('bkp-dlg-label').value.trim() || 'manual';
      overlay.remove();
      delete window.bkpPick; delete window.bkpCancel;
      resolve({ label, mode });
    };
    window.bkpCancel = () => { overlay.remove(); delete window.bkpPick; delete window.bkpCancel; resolve(null); };
    overlay.addEventListener('click', e => { if (e.target === overlay) window.bkpCancel(); });
  });
}

function dlBackup(name) {
  fetch('/api/backups/download?name=' + encodeURIComponent(name), { credentials: 'same-origin' })
    .then(r => {
      if (!r.ok) { alert('Erreur telechargement : ' + r.status); return null; }
      return r.blob();
    })
    .then(blob => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    })
    .catch(err => alert('Erreur : ' + err.message));
}

async function doManualBackup() {
  // 3-choice modal via custom overlay
  const choice = await backupChoiceDialog();
  if (!choice) return;
  const { label, mode } = choice;
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--blue);font-family:monospace;font-size:12px">Sauvegarde en cours…</div>';
  const d = await api('/backups', { method: 'POST', body: JSON.stringify({ label, mode }) }).catch(e => ({ error: e.message }));
  if (d?.ok) {
    await loadBackupsPage();
    const parts = [];
    if (d.zip && !d.zip.skipped) parts.push('ZIP: ' + d.zip.zipName);
    if (d.git?.ok) parts.push('Git tag: ' + d.git.tag);
    else if (d.git?.error) parts.push('Git erreur: ' + d.git.error);
    else if (d.git?.skipped) parts.push('Git: ignore (' + d.git.reason + ')');
    if (d.s3?.ok) parts.push('S3: ' + d.s3.key + (d.s3.ngxops?.key ? ' (+ YAML)' : ''));
    else if (d.s3?.error) parts.push('S3 erreur: ' + d.s3.error);
    else if (d.s3?.skipped && d.mode !== 'local' && d.mode !== 'git' && d.mode !== 'both') parts.push('S3: ignoré (' + d.s3.reason + ')');
    alert('Sauvegarde OK\n' + parts.join('\n'));
  } else {
    alert('Erreur : ' + (d?.error || 'Inconnue'));
    await loadBackupsPage();
  }
}

async function restoreBackup(name) {
  if (!confirm(`Restaurer la sauvegarde "${name}" ?\n\nUn backup de l etat actuel sera cree avant la restauration.`)) return;
  const el = document.getElementById('bkp-list');
  el.innerHTML = '<div style="color:var(--amber);font-family:monospace;font-size:12px">Restauration en cours…</div>';
  const d = await api('/backups/restore', { method:'POST', body: JSON.stringify({ name }) }).catch(e=>({error:e.message}));
  if (d?.ok) {
    await loadBackupsPage();
    alert(`✓ Restauré depuis "${name}"\nBackup pré-restauration : ${d.preBkp?.zipName || '—'}`);
  } else {
    alert('Erreur restauration : ' + (d?.error || 'Inconnue'));
    await loadBackupsPage();
  }
}

async function deleteBackup(name) {
  if (!confirm(`Supprimer définitivement "${name}" ?`)) return;
  await api('/backups/' + encodeURIComponent(name), { method: 'DELETE' });
  await loadBackupsPage();
}

/**
 * Carte « Destination S3 » (#117). Contenu issu du bucket = non fiable : tout est posé via textContent (jamais innerHTML).
 */
async function loadBackupS3Card() {
  const el = document.getElementById('bkp-s3');
  if (!el) return;
  const line = (txt, color) => { const d = document.createElement('div'); d.textContent = txt; d.style.cssText = 'font-family:monospace;font-size:12px;color:' + (color || 'var(--text3)'); return d; };
  el.replaceChildren(line('Chargement…'));
  const d = await api('/backups/s3').catch(() => null);
  if (!d) { el.replaceChildren(line('Erreur API', 'var(--red)')); return; }
  const rows = [];
  if (!d.enabled) rows.push(line('Désactivée — renseigner la page Configuration → « Sauvegardes (S3, cibles automatiques) » (s3_enable, s3_endpoint, s3_bucket + clés).'));
  else if (!d.configured) rows.push(line('Incomplète — champs manquants : ' + d.missing.join(', '), 'var(--amber)'));
  else {
    rows.push(line(`${d.endpoint} · bucket ${d.bucket} · préfixe « ${d.prefix} » · rotation ${d.keep || 'aucune'} · YAML NGX Ops : ${d.ngxops ? 'oui' : 'non'}`));
    const test = document.createElement('button'); test.className = 'btn sm'; test.textContent = 'Tester la connexion';
    test.onclick = async () => {
      test.disabled = true;
      const r = await api('/backups/s3/test', { method: 'POST', body: '{}' }).catch(e => ({ ok: false, error: e.message }));
      test.disabled = false; alert(r.ok ? 'Connexion S3 OK' : 'Échec S3 : ' + r.error);
    };
    rows.push(test);
    if (d.error) rows.push(line('Liste impossible : ' + d.error, 'var(--red)'));
    else if (!d.objects?.length) rows.push(line('Aucun objet sous ce préfixe.'));
    else for (const o of d.objects) {
      const r = document.createElement('div'); r.className = 'bkp-row';
      const n = document.createElement('span'); n.className = 'bkp-name'; n.textContent = o.key.slice(d.prefix.length); n.title = o.key;
      const s = document.createElement('span'); s.className = 'bkp-size'; s.textContent = fmtB(o.size);
      const t = document.createElement('span'); t.style.cssText = 'color:var(--text3);font-family:monospace;font-size:10px;min-width:70px;text-align:right'; t.textContent = timeAgo(o.lastModified);
      r.append(n, s, t); rows.push(r);
    }
  }
  rows.push(line(d.auto?.explicit
    ? `Sauvegarde automatique (avant édition / déploiement) : local ${d.auto.local ? 'oui' : 'non'} · Git ${d.auto.git ? 'oui' : 'non'} · S3 ${d.auto.s3 ? 'oui' : 'non'}`
    : 'Sauvegarde automatique : comportement historique (ZIP local ; + Git lors du déploiement Git). Définir auto_local / auto_git / auto_s3 pour le changer.'));
  el.replaceChildren(...rows);
}

