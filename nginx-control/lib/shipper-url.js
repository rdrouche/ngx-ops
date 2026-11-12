'use strict';
/**
 * URL de l'API locale du shipper : `schema://hote:port`, sans chemin ni identifiants. `http://` seulement
 * vers une boucle locale, un nom de service (un seul label) ou une IP privee : le jeton circule en clair.
 */
function validShipperUrl(u) {
  if (typeof u !== 'string' || u.length > 255) return false;
  let p;
  try { p = new URL(u); } catch { return false; }
  if (p.username || p.password || (p.pathname !== '/' && p.pathname !== '') || p.search || p.hash) return false;
  if (p.protocol === 'https:') return true;
  if (p.protocol !== 'http:') return false;
  const h = p.hostname.replace(/^\[|\]$/g, '');
  if (h === 'localhost' || (!h.includes('.') && !h.includes(':'))) return true;
  if (/^127\./.test(h) || h === '::1') return true;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(h);
}

module.exports = { validShipperUrl };
