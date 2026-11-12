'use strict';
/**
 * Decisions CrowdSec -> log store (#110, lot 3) : donnees pures (aucune E/S).
 * Une decision CrowdSec est un ETAT (ban) et non un evenement par requete : un evenement `crowdsec` est emis
 * UNE fois, a la creation de la decision (id jamais vu), via l'API locale du shipper. Les decisions de la
 * communaute (CAPI, listes) sont ignorees : des milliers d'entrees qui noieraient le journal.
 */
const MAX_BODY_EVENTS = 200;
const SKIPPED_ORIGINS = new Set(['capi', 'lists']);
const BACKFILL_MS = 3_600_000; // premier passage : seulement les decisions creees depuis moins d'une heure

const csIsObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Decision LAPI -> evenement `wire` du log store (ou null si ignoree). */
function csShipEvent(d, nowMs) {
  if (!csIsObj(d) || d.simulated === true) return null;
  const origin = String(d.origin || '');
  if (SKIPPED_ORIGINS.has(origin.toLowerCase())) return null;
  const created = Date.parse(d.created_at);
  const type = String(d.type || 'ban').toLowerCase();
  const ev = {
    ts: new Date(Number.isFinite(created) ? created : nowMs).toISOString(),
    source: 'crowdsec',
    action: type === 'ban' ? 'blocked' : type === 'captcha' ? 'challenged' : 'logged',
    extra: { type: type.slice(0, 20), origin: origin.slice(0, 40) },
  };
  if (Number.isInteger(d.id)) ev.extra.decision_id = d.id;
  if (typeof d.duration === 'string' && d.duration.length <= 40) ev.extra.duration = d.duration;
  const scope = String(d.scope || '').toLowerCase();
  const value = typeof d.value === 'string' ? d.value.slice(0, 120) : '';
  if (typeof d.scenario === 'string' && d.scenario) ev.rule = d.scenario.slice(0, 120);
  if (scope === 'ip' && value) ev.ip = value;
  else if (value) { ev.extra.scope = scope.slice(0, 20); ev.extra.value = value; }
  else return null;
  return ev;
}

/**
 * Choisit les decisions a expedier. `state.maxId` = plus grand id deja traite (null au premier passage : on ne
 * remonte que les decisions recentes). Renvoie { events, maxId } ; maxId n'avance qu'apres envoi reussi (cote appelant).
 */
function csShipSelect(decisions, state, nowMs) {
  const list = Array.isArray(decisions) ? decisions.filter((d) => csIsObj(d) && Number.isInteger(d.id)) : [];
  const first = !state || !Number.isInteger(state.maxId);
  const prev = first ? -1 : state.maxId;
  let maxId = first ? -1 : prev;
  const events = [];
  for (const d of list.sort((a, b) => a.id - b.id)) {
    if (d.id > maxId) maxId = d.id;
    if (d.id <= prev) continue;
    if (first) {
      const created = Date.parse(d.created_at);
      if (!Number.isFinite(created) || nowMs - created > BACKFILL_MS) continue;
    }
    const ev = csShipEvent(d, nowMs);
    if (ev) events.push(ev);
  }
  return { events: events.slice(0, MAX_BODY_EVENTS * 10), maxId: maxId < 0 ? (first ? null : prev) : maxId };
}

/** Corps NDJSON pour POST /v1/events du shipper, decoupe en paquets bornes. */
function csShipBodies(events) {
  const out = [];
  for (let i = 0; i < events.length; i += MAX_BODY_EVENTS) out.push(events.slice(i, i + MAX_BODY_EVENTS).map((e) => JSON.stringify(e)).join('\n') + '\n');
  return out;
}

module.exports = { csShipEvent, csShipSelect, csShipBodies, BACKFILL_MS };
