'use strict';
/** Point d'entrée : charge la config + la clé maîtresse, démarre l'application, gère l'arrêt propre. */
const { loadConfig } = require('./lib/config');
const { loadMasterKey } = require('./lib/crypto');
const { createApp } = require('./lib/app');
const { createLogger } = require('./lib/logger');

async function main() {
  const config = loadConfig();
  const log = createLogger(config.log.level);
  let key;
  try { key = loadMasterKey(); } catch (e) { log.error(e.message); process.exit(1); }
  if (!config.server.cookie_secure) log.warn('cookie_secure=false : réservé au développement local (HTTP)');
  if (config.security.allow_insecure_http) log.warn('allow_insecure_http=true : réservé au développement');
  const app = await createApp({ config, key, log });
  await app.start();
  const shutdown = async (sig) => { log.info('arrêt demandé', { sig }); await app.stop(); process.exit(0); };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((e) => { process.stderr.write('Échec du démarrage : ' + e.message + '\n'); process.exit(1); });
