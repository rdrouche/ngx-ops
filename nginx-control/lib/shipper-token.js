'use strict';
/**
 * Jeton local du shipper (log store) : secret partage entre le dashboard, le conteneur
 * `shipper` (LOGSHIP_LOCAL_TOKEN) et les producteurs de decisions (WAF emule : SHIPPER_TOKEN).
 *
 * Meme principe que lib/waf-token.js. Priorite : ENV SHIPPER_LOCAL_TOKEN (>= 24 caracteres,
 * seuil impose par le shipper) > valeur generee une fois et conservee dans
 * config/.generated-secrets.json (cle `shipperToken`). Jamais expose au navigateur ni journalise.
 * Si le shipper est lance par docker-compose (et non par le dashboard), SHIPPER_LOCAL_TOKEN doit
 * etre fourni aux DEUX services avec la meme valeur.
 */
const crypto = require('crypto');
const cfg = require('./config');

const KEY = 'shipperToken';
const MIN_LEN = 24;

function getShipperToken() {
  if (cfg.SHIPPER_LOCAL_TOKEN) {
    if (cfg.SHIPPER_LOCAL_TOKEN.length >= MIN_LEN) return cfg.SHIPPER_LOCAL_TOKEN;
    console.warn(`[shipper] SHIPPER_LOCAL_TOKEN ignore : ${MIN_LEN} caracteres minimum (openssl rand -hex 24)`);
  }
  const stored = cfg.readGeneratedSecrets()[KEY];
  if (typeof stored === 'string' && /^[a-f0-9]{32,}$/i.test(stored)) return stored;
  const fresh = crypto.randomBytes(24).toString('hex');
  cfg.persistGeneratedSecret(KEY, fresh);
  console.log(`[shipper] Jeton local genere et conserve dans ${cfg.GENERATED_SECRETS_FILE}`);
  return fresh;
}

module.exports = { getShipperToken, MIN_LEN };
