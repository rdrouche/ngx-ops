'use strict';
/**
 * Corrélation par IP entre instances (recommandation du contrat §2.9) : clé = IP ; une IP vue par ≥ 2 instances
 * ou par ≥ 3 « kinds » distincts → campagne probable. Le score du dashboard (nombre de types de sources) est conservé tel quel.
 */
const net = require('node:net');

function correlate(rows, { maxAgeMs, now = Date.now(), limit = 500 }) {
  const byIp = new Map();
  for (const r of rows) {
    if (now - r.fetched_at > maxAgeMs) continue; // instance muette : données périmées ignorées
    let list;
    try { list = JSON.parse(r.payload).data.indicators; } catch { continue; }
    if (!Array.isArray(list)) continue;
    for (const ind of list) {
      if (!ind || typeof ind.ip !== 'string' || !net.isIP(ind.ip)) continue;
      const kinds = Array.isArray(ind.kinds) ? ind.kinds.filter((k) => typeof k === 'string').slice(0, 12) : [];
      let e = byIp.get(ind.ip);
      if (!e) { e = { ip: ind.ip, kinds: new Set(), instances: [], score: 0, rules: new Set() }; byIp.set(ind.ip, e); }
      for (const s of Array.isArray(ind.sources) ? ind.sources : []) {
        if (s && s.kind === 'campaign' && typeof s.type === 'string' && e.rules.size < 10) e.rules.add(s.type.slice(0, 80)); // règles de campagne d'analyse (#83)
      }
      kinds.forEach((k) => e.kinds.add(k));
      e.score = Math.max(e.score, Number(ind.score) || kinds.length);
      e.instances.push({ id: r.instance_id, name: r.name, score: Number(ind.score) || kinds.length, kinds, sources: (Array.isArray(ind.sources) ? ind.sources : []).slice(0, 12), seen_at: r.fetched_at });
    }
  }
  const out = [...byIp.values()].map((e) => ({
    ip: e.ip, score: e.score, kinds: [...e.kinds], instances: e.instances, campaign_rules: [...e.rules],
    campaign: e.instances.length >= 2 || e.kinds.size >= 3,
  }));
  out.sort((a, b) => Number(b.campaign) - Number(a.campaign) || b.instances.length - a.instances.length || b.kinds.length - a.kinds.length || b.score - a.score);
  return out.slice(0, limit);
}

module.exports = { correlate };
