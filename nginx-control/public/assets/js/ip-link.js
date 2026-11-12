// Lien « fiche IP » vers NGX Ops Intelligence (#93) — réglage PAR NAVIGATEUR, désactivé par défaut.
// Le choix (localStorage ngx_ip_links : plain | intel) active une pastille ↗ à côté des adresses IP des
// pages branchées ; l'adresse n'est envoyée à Intelligence qu'au clic (nouvel onglet, noopener noreferrer).
// Aucun innerHTML avec une valeur externe : l'IP est validée (IPv4/IPv6) avant tout lien.
(function () {
  const KEY = 'ngx_ip_links';
  const BASE = 'https://intelligence.ngx-ops.net/ip/';
  const V4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const V6 = /^[0-9a-fA-F:]{2,45}$/;
  const tr = (k, d) => { try { const v = typeof t === 'function' ? t(k) : k; return v && v !== k ? v : d; } catch { return d; } };

  function enabled() { try { return localStorage.getItem(KEY) === 'intel'; } catch { return false; } }
  function valid(ip) { return typeof ip === 'string' && (V4.test(ip) || (V6.test(ip) && ip.includes(':'))); }
  function url(ip) { return valid(ip) ? BASE + encodeURIComponent(ip) : null; }
  /** Pastille ↗ (élément <a>) ou null si le réglage est coupé / l'adresse n'est pas une IP. */
  function badge(ip) {
    if (!enabled() || !valid(ip)) return null;
    const a = document.createElement('a');
    a.href = url(ip); a.target = '_blank'; a.rel = 'noopener noreferrer';
    a.textContent = '↗'; a.className = 'ip-ext';
    a.title = tr('ipLink.open', 'Voir cette IP sur NGX Ops Intelligence');
    a.addEventListener('click', (e) => e.stopPropagation());
    return a;
  }
  /** Même pastille en HTML pour les gabarits en chaîne (l'IP est validée, donc sûre). */
  function badgeHtml(ip) {
    if (!enabled() || !valid(ip)) return '';
    return ' <a class="ip-ext" href="' + url(ip) + '" target="_blank" rel="noopener noreferrer" title="' + tr('ipLink.open', 'Voir cette IP sur NGX Ops Intelligence').replace(/"/g, '&quot;') + '" onclick="event.stopPropagation()">↗</a>';
  }
  function sync() { const b = document.getElementById('ip-link-btn'); if (b) { b.classList.toggle('on', enabled()); b.setAttribute('aria-pressed', enabled() ? 'true' : 'false'); } }
  function toggle() {
    try { localStorage.setItem(KEY, enabled() ? 'plain' : 'intel'); } catch { /* navigation privée */ }
    sync(); location.reload(); // les listes déjà affichées sont reconstruites avec le nouveau réglage
  }
  window.NgxIp = { enabled, valid, url, badge, badgeHtml, toggle };
  document.addEventListener('DOMContentLoaded', () => { const b = document.getElementById('ip-link-btn'); if (b) b.title = tr('ipLink.title', 'Adresses IP : afficher un lien vers NGX Ops Intelligence'); sync(); });
})();
