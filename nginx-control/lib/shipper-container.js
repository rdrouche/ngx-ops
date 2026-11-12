'use strict';
/**
 * Conteneur shipper gere depuis le dashboard (v12.80.0) — donnees pures (aucune E/S, aucun appel Docker).
 * Le cycle de vie est dans features/logstore.js. Meme image que l'analyseur Go (3e binaire).
 *
 * Durcissement : aucun port publie (l'API locale n'est joignable que sur le reseau Docker), systeme de
 * fichiers racine en lecture seule, journaux nginx montes en lecture seule, toutes les capacites retirees,
 * pas de nouveaux privileges, memoire et processus bornes. /tmp en tmpfs (le shipper n'ecrit que dans /data).
 */
const { SHIPPER_PORT } = require('./logstore-settings');

const MOUNTS = Object.freeze({ logs: '/nginx/logs', data: '/data', geoip: '/geoip' });
const ENTRYPOINT = '/usr/local/bin/shipper';

/**
 * @param {object} config  resultat de normalizeLogstoreConfig().config
 * @param {{localToken:string, network?:string, tz?:string, analyzerUrl?:string, analyzerToken?:string, geoipPath?:string}} opts
 */
function buildShipperSpec(config, { localToken, network, tz, analyzerUrl, analyzerToken, geoipPath } = {}) {
  if (!localToken) throw new Error('jeton local du shipper absent');
  if (!config.sinkUrl || !config.sinkToken) throw new Error('shipper_sink_url / jeton d envoi manquants');
  const env = [
    `LOGSINK_URL=${config.sinkUrl}`,
    `LOGSINK_TOKEN=${config.sinkToken}`,
    `LOGSINK_INSTANCE=${config.instance}`,
    `LOGSINK_ALLOW_INSECURE=${config.sinkAllowInsecure ? 'true' : 'false'}`,
    `LOGSINK_SPOOL_DIR=${MOUNTS.data}/spool`,
    `LOGSHIP_DIR=${MOUNTS.logs}`,
    `LOGSHIP_STATE_FILE=${MOUNTS.data}/offsets.json`,
    `LOGSHIP_LISTEN=0.0.0.0:${SHIPPER_PORT}`,
    `LOGSHIP_LOCAL_TOKEN=${localToken}`,
    `LOGSHIP_BLOCKLIST=${config.shipperBlocklist ? 'true' : 'false'}`,
    `LOGSHIP_COUNTRY=${config.shipperCountry ? 'true' : 'false'}`,
  ];
  // #110 : l'analyseur attribue le nom de liste aux hits blocklist (GET /api/blocklist-sources/lookup) ; absent = hits sans nom de liste
  if (analyzerUrl && analyzerToken && /^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(analyzerUrl)) env.push(`LOGSHIP_ANALYZER_URL=${analyzerUrl}`, `LOGSHIP_ANALYZER_TOKEN=${analyzerToken}`);
  if (tz && /^[A-Za-z0-9_\/+-]{1,64}$/.test(tz)) env.push(`TZ=${tz}`);
  const binds = [
    `${config.shipperHostLogsPath}:${MOUNTS.logs}:ro`,
    `${config.shipperHostDataPath}:${MOUNTS.data}`,
  ];
  // #114 : l'enrichissement pays lit les bases MaxMind (.mmdb) : sans ce montage CountryOf() renvoie toujours "" (aucun pays dans le store)
  if (config.shipperCountry && typeof geoipPath === 'string' && /^\/[^\0:;\s]*$/.test(geoipPath)) binds.push(`${geoipPath}:${MOUNTS.geoip}:ro`);
  return {
    Image: config.shipperImage,
    Entrypoint: [ENTRYPOINT],
    Env: env,
    Labels: { 'managed-by': 'nginx-dashboard', 'nginx-dashboard.role': 'shipper' },
    Healthcheck: {
      Test: ['CMD', ENTRYPOINT, 'healthcheck'],
      Interval: 30e9, Timeout: 5e9, Retries: 3,
    },
    HostConfig: {
      Binds: binds,
      RestartPolicy: { Name: 'unless-stopped' },
      NetworkMode: network || 'nginx-net',
      ReadonlyRootfs: true,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'],
      Memory: 256 * 1024 * 1024,
      PidsLimit: 256,
    },
  };
}

module.exports = { MOUNTS, ENTRYPOINT, buildShipperSpec };
