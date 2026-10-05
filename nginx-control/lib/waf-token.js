'use strict';
/**
 * Secret partage dashboard <-> conteneur `ngx-waf` (en-tete X-WAF-Token).
 *
 * Meme principe que SESSION_SECRET / lib/analyzer-token.js : le reseau Docker
 * (nginx-net) est partage avec tous les backends du reverse proxy, la position
 * reseau seule ne suffit donc pas a proteger l'API du WAF (qui peut desactiver
 * des regles ou deslister des IP). Priorite : ENV WAF_TOKEN > valeur generee
 * une fois et conservee dans config/.generated-secrets.json (cle `wafToken`).
 * Le jeton est passe au conteneur a sa creation (WAF_TOKEN) et renvoye a chaque
 * appel proxifie ; il n'est JAMAIS expose au navigateur ni journalise.
 */
const crypto = require('crypto');
const cfg = require('./config');

const KEY = 'wafToken';

function getWafToken() {
  if (cfg.WAF_TOKEN) return cfg.WAF_TOKEN;
  const stored = cfg.readGeneratedSecrets()[KEY];
  if (typeof stored === 'string' && /^[a-f0-9]{32,}$/i.test(stored)) return stored;
  const fresh = crypto.randomBytes(24).toString('hex');
  cfg.persistGeneratedSecret(KEY, fresh);
  console.log(`[waf] Jeton partage genere et conserve dans ${cfg.GENERATED_SECRETS_FILE}`);
  return fresh;
}

module.exports = { getWafToken };
