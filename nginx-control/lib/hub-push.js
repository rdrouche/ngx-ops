'use strict';
/**
 * Envoi (push) d'une sauvegarde vers le Hub. Anti-SSRF : http(s) seulement,
 * aucune redirection suivie, délai borné, jeton en Authorization (jamais dans l'URL).
 * Contrat : POST {hub_url}/api/hub/v1/backups, corps = archive (octet-stream),
 * en-têtes X-Instance-Id, X-Backup-Sha256, X-Backup-Encrypted, X-Backup-Files,
 * X-Retention-Days, X-Dashboard-Version ; réponse 2xx JSON { id }.
 */
const http = require('http');
const https = require('https');

function sendBackup({ hubUrl, token, archive, sha256, manifest, instanceId, version, timeoutMs = 60000 }) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(hubUrl.replace(/\/$/, '') + '/api/hub/v1/backups'); } catch { return resolve({ ok: false, error: 'bad hub_url' }); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, {
      method: 'POST', timeout: timeoutMs,
      headers: {
        'Content-Type': 'application/octet-stream', 'Content-Length': archive.length,
        Authorization: 'Bearer ' + token, 'X-Instance-Id': instanceId || '', 'X-Backup-Sha256': sha256,
        'X-Backup-Encrypted': manifest.encrypted ? '1' : '0', 'X-Backup-Files': String(manifest.files.length),
        'X-Retention-Days': String(manifest.retention_days), 'X-Dashboard-Version': version || '',
      },
    }, (res) => {
      let b = ''; res.on('data', d => { if (b.length < 4096) b += d; });
      res.on('end', () => {
        let j = null; try { j = JSON.parse(b); } catch { /* texte */ }
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        resolve({ ok, status: res.statusCode, id: j && j.id, error: ok ? undefined : (j && j.error) || `HTTP ${res.statusCode}` });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
    req.end(archive);
  });
}
module.exports = { sendBackup };
