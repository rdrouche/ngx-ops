'use strict';
/**
 * Corrélation par IP à partir du log store (#62). Fonctions pures. DONNÉES PERSONNELLES : le résultat ne doit être
 * ni stocké par le Hub ni journalisé ; réservé à la permission indicators:view (administrateurs).
 *
 * Le log store renvoie, selon son mode IP : l'IP en clair, le /24 (« 203.0.113.0/24 ») ou une clé de pseudonyme
 * (32 hex). Seules les IP en clair peuvent être rapprochées des indicateurs des dashboards.
 */
const net = require('node:net');
const { INSTANCE_RE } = require('./model');

const SOURCES = ['access', 'waf', 'challenge', 'blocklist', 'crowdsec', 'analysis'];
const KIND_OF = { waf: 'waf', challenge: 'challenge', blocklist: 'blocklist', crowdsec: 'crowdsec', analysis: 'alert' }; // « access » n'est pas un signal de menace en soi
const PSEUDO_RE = /^[0-9a-f]{32}$/;
const CIDR24_RE = /^((?:\d{1,3}\.){3}0)\/24$/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.round(v) : 0);
const ms = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? t : null; };

/** Type de clé : ip | cidr | pseudonym | null (rejetée). */
function keyType(k) {
  if (typeof k !== 'string') return null;
  if (net.isIP(k)) return 'ip';
  const m = CIDR24_RE.exec(k);
  if (m && net.isIPv4(m[1])) return 'cidr';
  return PSEUDO_RE.test(k) ? 'pseudonym' : null;
}

/** Réponse brute de GET /v1/stats/ips → éléments assainis (clé invalide ou instance invalide ignorées). */
function shapeIps(raw) {
  const list = isObj(raw) && Array.isArray(raw.items) ? raw.items : [];
  const out = [];
  for (const x of list.slice(0, 500)) {
    if (!isObj(x)) continue;
    const type = keyType(x.key);
    if (!type) continue;
    const sources = (Array.isArray(x.sources) ? x.sources : []).filter((s) => SOURCES.includes(s));
    out.push({
      key: x.key, type, events: num(x.events), blocked: num(x.blocked), errors: num(x.errors), sites: num(x.sites),
      instance_count: num(x.instance_count), instances: (Array.isArray(x.instances) ? x.instances : []).map(String).filter((i) => INSTANCE_RE.test(i)).slice(0, 20),
      sources, first_seen: ms(x.first_seen), last_seen: ms(x.last_seen),
    });
  }
  return out;
}

/** Fusionne plusieurs listes (requêtes « ≥ N instances » et « ≥ 3 sources ») : une clé = un élément, cumul des max. */
function union(lists) {
  const by = new Map();
  for (const l of lists) for (const x of l) if (!by.has(x.key)) by.set(x.key, x);
  return [...by.values()];
}

/**
 * Rapproche les IP du log store des indicateurs des dashboards (même forme que features/modules/correlate.js).
 * Campagne probable : ≥ 2 instances (dashboards ou log store) ou ≥ 3 types de signaux (union des deux sources).
 */
function merge(dashboardItems, lsItems, { limit = 500 } = {}) {
  const dash = new Map((Array.isArray(dashboardItems) ? dashboardItems : []).map((d) => [d.ip, d]));
  const out = []; const used = new Set();
  for (const l of lsItems) {
    const kinds = new Set(l.sources.map((s) => KIND_OF[s]).filter(Boolean));
    const d = l.type === 'ip' ? dash.get(l.key) : null;
    if (d) { used.add(d.ip); d.kinds.forEach((k) => kinds.add(k)); }
    const instances = d ? d.instances : [];
    out.push({
      ip: l.key, scope: l.type, kinds: [...kinds], score: Math.max(d ? d.score : 0, kinds.size), instances,
      logstore: { instance_count: l.instance_count, instances: l.instances, events: l.events, blocked: l.blocked, errors: l.errors, sites: l.sites, sources: l.sources, first_seen: l.first_seen, last_seen: l.last_seen },
      campaign: instances.length >= 2 || l.instance_count >= 2 || kinds.size >= 3,
      campaign_rules: d && Array.isArray(d.campaign_rules) ? d.campaign_rules : [],
    });
  }
  for (const d of dash.values()) if (!used.has(d.ip)) out.push({ ...d, scope: 'ip', logstore: null, campaign_rules: Array.isArray(d.campaign_rules) ? d.campaign_rules : [] });
  out.sort((a, b) => Number(b.campaign) - Number(a.campaign) || (b.logstore ? b.logstore.instance_count : 0) - (a.logstore ? a.logstore.instance_count : 0)
    || b.instances.length - a.instances.length || b.kinds.length - a.kinds.length || b.score - a.score);
  return out.slice(0, limit);
}

module.exports = { keyType, shapeIps, union, merge, SOURCES };
