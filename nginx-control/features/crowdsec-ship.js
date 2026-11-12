'use strict';
/**
 * Expedition des decisions CrowdSec vers le log store (#110, lot 3), via l'API locale du shipper.
 * Actif si : logstore.yml `shipper_enable` + `shipper_crowdsec` (defaut true), CrowdSec configure (URL + cle API).
 * Lecture : /v1/decisions (cle de bouncer, lecture seule) toutes les 60 s. Un evenement par NOUVELLE decision
 * (id jamais vu), l'etat (plus grand id traite) est conserve dans CONFIG_DIR. Jamais bloquant ni fatal.
 */
const fs = require('fs');
const http = require('http');
const path = require('path');
const cfg = require('../lib/config');
const CS = require('../lib/crowdsec-ship');
const LS = require('../lib/logstore-settings');
const { getShipperToken } = require('../lib/shipper-token');

const STATE_FILE = path.join(cfg.CONFIG_DIR, '.crowdsec-ship-state.json');
const INTERVAL_MS = 60_000;
const MAX_FAIL_WARN = 5;
let timer = null;
let failures = 0;

function readState(file) {
  try { const s = JSON.parse(fs.readFileSync(file, 'utf8')); return Number.isInteger(s.maxId) ? { maxId: s.maxId } : null; } catch { return null; }
}
function writeState(file, maxId) {
  try { fs.writeFileSync(file, JSON.stringify({ maxId }), { mode: 0o600 }); } catch (e) { console.warn('[crowdsec-ship] etat non ecrit :', e.message); }
}

/** POST NDJSON vers l'API locale du shipper ; resout true seulement sur 202. */
function postToShipper(baseUrl, token, body) {
  return new Promise((resolve) => {
    let u; try { u = new URL(baseUrl.replace(/\/$/, '') + '/v1/events'); } catch { return resolve(false); }
    const req = http.request({
      hostname: u.hostname, port: u.port || 80, path: u.pathname, method: 'POST', timeout: 5000,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-ndjson', 'Content-Length': Buffer.byteLength(body), 'User-Agent': cfg.HTTP_USER_AGENT },
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode === 202)); });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

/** Un passage : lit les decisions, expedie les nouvelles, avance l'etat seulement si tout est parti. Renvoie un compte-rendu (tests). */
async function tick(deps = {}) {
  const crowdsec = deps.crowdsec || require('./crowdsec');
  const resolveConfig = deps.resolveConfig || (() => require('./logstore').resolveConfig());
  const post = deps.post || postToShipper;
  const now = deps.now ? deps.now() : Date.now();
  const file = deps.stateFile || STATE_FILE;
  const c = (await resolveConfig()).config;
  if (!c.shipperEnable || c.shipperCrowdsec === false || !crowdsec.crowdsecConfigured()) return { skipped: 'disabled' };
  const raw = await crowdsec.crowdsecGet('/v1/decisions?limit=500');
  const state = readState(file);
  const sel = CS.csShipSelect(raw, state, now);
  if (!sel.events.length) { if (sel.maxId !== null && (!state || sel.maxId !== state.maxId)) writeState(file, sel.maxId); return { sent: 0 }; }
  const url = LS.localShipperUrl(c); const token = deps.token || getShipperToken();
  for (const body of CS.csShipBodies(sel.events)) {
    if (!(await post(url, token, body))) return { error: 'shipper', pending: sel.events.length };
  }
  writeState(file, sel.maxId);
  return { sent: sel.events.length };
}

function schedule() {
  timer = setTimeout(async () => {
    try { await tick(); failures = 0; } catch (e) {
      failures += 1;
      if (failures === MAX_FAIL_WARN) console.warn('[crowdsec-ship] echecs repetes (LAPI ou shipper injoignable) :', (e && e.message) || e.status || 'erreur');
    }
    schedule();
  }, INTERVAL_MS);
  if (timer.unref) timer.unref();
}

function start() { if (!timer) schedule(); }
function stop() { if (timer) clearTimeout(timer); timer = null; }

/** Aucune route : le module est un travailleur de fond (convention des features : register(router)). */
function register() {}

module.exports = { register, start, stop, tick };
