'use strict';
/**
 * A periodic operational summary — traffic, bot/human split, top countries,
 * CrowdSec activity, WAF activity, upcoming certificate expiries — composed
 * from data this project already computes elsewhere. No new log parsing, no
 * new aggregation engine: this is assembly of existing pieces (the
 * analyzer's traffic/bot aggregates, CrowdSec's decision list, the WAF event
 * store, the certificate lister), sent by email and shown in the dashboard.
 *
 * A CrowdSec Decision, per its own published schema, carries no creation
 * timestamp — only `duration` (a Go duration string) and `until` (an expiry
 * date). There is no honest way to ask "how many bans are new since the last
 * digest" from that shape alone, so this reports a snapshot instead — how
 * many are active right now, broken down by origin — rather than fabricate
 * a "new since X" figure the API cannot actually support.
 */

const certsLib = require('./certs');

// Injectable, defaulting to no-ops that report "unavailable" rather than
// throwing — a digest should degrade gracefully (a missing analyzer or
// unconfigured CrowdSec shows as absent in the digest, not a hard failure),
// the same tolerance this project already applies everywhere else data
// crosses a network boundary.
const deps = {
  analyzerApi: null,
  crowdsecGet: null,
  crowdsecConfigured: () => false,
  listExistingCerts: certsLib.listExistingCerts,
  // features/blocklists.js's getHitStats(), injected — returns
  // { available, hitLogging, totalUniqueIps?, totalHits, uniqueHitIps,
  //   topIps, bySource }. null when unset (mirrors every other dep here).
  getBlocklistStats: null,
};

function configure(overrides) { Object.assign(deps, overrides); }

async function generateDigest(periodHours = 24) {
  const to = Date.now();
  const from = to - periodHours * 3_600_000;

  const digest = {
    generatedAt: to,
    periodHours,
    traffic: null,
    bots: null,
    topCountries: [],
    crowdsec: { configured: false },
    waf: { configured: false },
    blocklists: { enable: false },
    certs: { expiringSoon: [] },
    previous: null,
    errors: [],
  };

  if (deps.analyzerApi) {
    // Promise.allSettled, not Promise.all: these three calls are independent
    // — a timeout on one (bots) must not discard the other two that already
    // succeeded. Promise.all rejects the whole batch the instant any single
    // promise rejects, which silently wiped out traffic and topCountries
    // here even when only the bots call had actually failed.
    const [botsRes, countriesRes, vhostsRes, vhostsPrevRes] = await Promise.allSettled([
      deps.analyzerApi(`/api/traffic/bots?hours=${periodHours}`),
      deps.analyzerApi(`/api/traffic/countries?hours=${periodHours}`),
      deps.analyzerApi(`/api/traffic/vhosts?hours=${periodHours}`),
      // v12.75.0 — période précédente = (2P) − (P) : l'analyseur ne sait
      // répondre qu'à « les N dernières heures », la soustraction donne la
      // période juste avant sans nouvelle agrégation.
      deps.analyzerApi(`/api/traffic/vhosts?hours=${periodHours * 2}`),
    ]);

    if (botsRes.status === 'fulfilled' && botsRes.value?.data) {
      const data = botsRes.value.data;
      digest.bots = {
        total: data.total || 0,
        human: data.human || 0,
        bots:  data.bots || 0,
        byCategory: data.byCategory || [],
      };
    } else if (botsRes.status === 'rejected') {
      digest.errors.push(`traffic (bots): ${botsRes.reason?.message || botsRes.reason}`);
    }

    if (countriesRes.status === 'fulfilled' && Array.isArray(countriesRes.value?.data?.countries)) {
      digest.topCountries = countriesRes.value.data.countries
        .slice().sort((a, b) => (b.requests || 0) - (a.requests || 0)).slice(0, 5);
    } else if (countriesRes.status === 'rejected') {
      digest.errors.push(`traffic (countries): ${countriesRes.reason?.message || countriesRes.reason}`);
    }

    if (vhostsRes.status === 'fulfilled' && Array.isArray(vhostsRes.value?.data?.vhosts)) {
      const vhosts = vhostsRes.value.data.vhosts;
      digest.traffic = {
        totalRequests: vhosts.reduce((s, v) => s + (v.requests || 0), 0),
        totalBytes:    vhosts.reduce((s, v) => s + (v.bytes || 0), 0),
        totalErrors:   vhosts.reduce((s, v) => s + (v.errors || 0), 0),
        byVhost: vhosts.slice().sort((a, b) => (b.requests || 0) - (a.requests || 0)),
      };
      if (vhostsPrevRes.status === 'fulfilled' && Array.isArray(vhostsPrevRes.value?.data?.vhosts)) {
        const sum = (k) => vhostsPrevRes.value.data.vhosts.reduce((a, v) => a + (v[k] || 0), 0);
        const prev = {
          totalRequests: Math.max(0, sum('requests') - digest.traffic.totalRequests),
          totalBytes:    Math.max(0, sum('bytes')    - digest.traffic.totalBytes),
          totalErrors:   Math.max(0, sum('errors')   - digest.traffic.totalErrors),
        };
        // Pas de comparaison honnête si l'historique ne couvre pas 2P (prev == 0).
        if (prev.totalRequests > 0) digest.previous = prev;
      }
    } else if (vhostsRes.status === 'rejected') {
      digest.errors.push(`traffic (vhosts): ${vhostsRes.reason?.message || vhostsRes.reason}`);
    }

    try {
      const wafRes = await deps.analyzerApi(`/api/waf/events?since=${from}&blocked=1&limit=1`);
      if (wafRes?.data) {
        digest.waf = { configured: true, blockedCount: wafRes.data.total || 0 };
      }
    } catch (e) { digest.errors.push(`waf: ${e.message}`); }
  }

  if (deps.crowdsecConfigured()) {
    // Fix (audit finding MISC-07): `activeTotal`/`byOrigin` used to be set
    // ONLY inside the try block below — a CrowdSec that is "configured" per
    // crowdsecConfigured() (e.g. only a Prometheus scrape target set, no
    // reachable LAPI) makes the /v1/decisions call fail, the catch records
    // the error but leaves both fields undefined, and formatDigest() below
    // unconditionally calls `.toLocaleString()` on activeTotal whenever
    // `configured` is true — an uncaught exception there aborted the WHOLE
    // digest, silently, for every period, not just the CrowdSec section.
    // Defaults set here up front mean a failed fetch degrades to "0 active
    // decisions" (visible, alongside the logged error) rather than crashing
    // digest generation entirely.
    digest.crowdsec.configured = true;
    digest.crowdsec.activeTotal = 0;
    digest.crowdsec.byOrigin = {};
    try {
      const decisions = await deps.crowdsecGet('/v1/decisions?limit=500');
      const list = Array.isArray(decisions) ? decisions : [];
      digest.crowdsec.activeTotal = list.length;
      const byOrigin = {};
      for (const d of list) {
        const origin = d.origin || 'unknown';
        byOrigin[origin] = (byOrigin[origin] || 0) + 1;
      }
      digest.crowdsec.byOrigin = byOrigin;
    } catch (e) { digest.errors.push(`crowdsec: ${e.message}`); }
  }

  if (deps.getBlocklistStats) {
    try { digest.blocklists = await deps.getBlocklistStats({ hours: periodHours }); }
    catch (e) { digest.errors.push(`blocklists: ${e.message}`); }
  }

  try {
    const certs = deps.listExistingCerts();
    digest.certs.expiringSoon = certs
      .filter(c => c.daysLeft != null && c.daysLeft <= 30 && c.daysLeft >= 0)
      .map(c => ({ name: c.name, daysLeft: c.daysLeft, notAfter: c.notAfter }))
      .sort((a, b) => a.daysLeft - b.daysLeft);
  } catch (e) { digest.errors.push(`certs: ${e.message}`); }

  return digest;
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

const nf = (n) => (n || 0).toLocaleString('fr-FR');

/** Nom lisible d'un code pays ISO ; « ?? » (adresses non résolues) → « Non résolu ». */
function countryName(code, lang = 'fr') {
  if (!code || code === '??' || !/^[A-Za-z]{2}$/.test(code)) return lang === 'fr' ? 'Non résolu' : 'Unresolved';
  try { return new Intl.DisplayNames([lang], { type: 'region' }).of(code.toUpperCase()) || code; } catch { return code; }
}
function flagEmoji(code) {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return '🌐';
  return String.fromCodePoint(...code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)));
}
function periodLabel(h) { return h >= 168 && h % 168 === 0 ? `${h / 168} semaine(s)` : h % 24 === 0 && h > 24 ? `${h / 24} jours` : `${h}h`; }
function pctDelta(cur, prev) { return prev > 0 ? Math.round(100 * (cur - prev) / prev) : null; }
const trend = (d) => d == null ? '' : (d > 0 ? `▲ +${d}%` : d < 0 ? `▼ ${d}%` : '= 0%');

/**
 * Points d'attention : ce que l'opérateur doit lire en premier. Chaque point
 * est {level: 'ok'|'warn'|'crit', text}. Calculés uniquement à partir des
 * données déjà présentes dans le digest.
 */
function highlights(d) {
  const out = [];
  if (d.traffic) {
    const rate = d.traffic.totalRequests ? 100 * d.traffic.totalErrors / d.traffic.totalRequests : 0;
    if (rate >= 10) out.push({ level: 'crit', text: `Taux d'erreurs élevé : ${rate.toFixed(1)} % des requêtes` });
    else if (rate >= 3) out.push({ level: 'warn', text: `Taux d'erreurs à surveiller : ${rate.toFixed(1)} %` });
    const dv = d.previous ? pctDelta(d.traffic.totalRequests, d.previous.totalRequests) : null;
    if (dv != null && Math.abs(dv) >= 50) out.push({ level: 'warn', text: `Trafic ${dv > 0 ? 'en forte hausse' : 'en forte baisse'} (${trend(dv)}) par rapport à la période précédente` });
  }
  if (d.bots && d.bots.total && d.bots.bots / d.bots.total >= 0.6) out.push({ level: 'warn', text: `Majorité de robots : ${Math.round(100 * d.bots.bots / d.bots.total)} % des visiteurs` });
  for (const c of d.certs.expiringSoon) out.push({ level: c.daysLeft <= 7 ? 'crit' : 'warn', text: `Certificat ${c.name} : expire dans ${c.daysLeft} jour(s)` });
  if (d.waf.configured && d.waf.blockedCount > 0) out.push({ level: 'ok', text: `${nf(d.waf.blockedCount)} requête(s) bloquée(s) par le WAF` });
  if (!out.some(h => h.level !== 'ok')) out.unshift({ level: 'ok', text: 'Rien d\'anormal à signaler sur la période.' });
  return out;
}

/** Plain-text rendering for email (partie texte du mail multipart). */
function formatDigestText(d) {
  const lines = [];
  lines.push(`NGX Ops — Résumé des ${periodLabel(d.periodHours)}`);
  lines.push(`Généré le ${new Date(d.generatedAt).toLocaleString('fr-FR')}`);
  lines.push('');
  lines.push('À RETENIR');
  for (const h of highlights(d)) lines.push(` ${h.level === 'crit' ? '[!!]' : h.level === 'warn' ? '[!]' : '[ok]'} ${h.text}`);
  lines.push('');

  if (d.traffic) {
    const dv = d.previous ? pctDelta(d.traffic.totalRequests, d.previous.totalRequests) : null;
    lines.push(`Trafic : ${nf(d.traffic.totalRequests)} requêtes${dv != null ? ` (${trend(dv)} vs période précédente)` : ''}, ${fmtBytes(d.traffic.totalBytes)}, ${nf(d.traffic.totalErrors)} erreurs`);
    for (const v of d.traffic.byVhost.slice(0, 5)) lines.push(`  ${v.vhost} — ${nf(v.requests)} req, ${fmtBytes(v.bytes)}, ${nf(v.errors)} err.`);
  } else {
    lines.push('Trafic : analyseur injoignable');
  }

  if (d.bots) {
    const pct = d.bots.total ? Math.round(100 * d.bots.bots / d.bots.total) : 0;
    lines.push(`Visiteurs : ${nf(d.bots.human)} humains, ${nf(d.bots.bots)} robots (${pct} %)`);
  }

  if (d.topCountries.length) {
    lines.push('');
    lines.push('Top pays :');
    for (const c of d.topCountries) lines.push(`  ${countryName(c.country)} — ${nf(c.requests)} requêtes`);
  }

  if (d.waf.configured) {
    lines.push('');
    lines.push(`WAF : ${nf(d.waf.blockedCount)} requêtes bloquées sur la période`);
  }

  if (d.crowdsec.configured) {
    lines.push('');
    lines.push(`CrowdSec : ${nf(d.crowdsec.activeTotal)} décision(s) active(s)`);
    for (const [origin, n] of Object.entries(d.crowdsec.byOrigin || {})) lines.push(`  ${origin} : ${n}`);
  }

  if (d.blocklists?.enable) {
    lines.push('');
    lines.push(`Blocklists IP : ${nf(d.blocklists.totalUniqueIps)} adresse(s) IP au total`);
    if (d.blocklists.available) {
      lines.push(`  ${nf(d.blocklists.totalHits)} hit(s) sur la période, ${nf(d.blocklists.uniqueHitIps)} IP distincte(s)`);
      for (const s of (d.blocklists.bySource || []).slice(0, 5)) lines.push(`  ${s.name} : ${nf(s.hits)} hit(s)`);
    } else if (d.blocklists.hitLogging && !d.blocklists.hitLogging.enable) {
      lines.push('  (journalisation des hits désactivée — voir hit_logging_* dans config/blocklists.yml)');
    } else {
      lines.push('  (statistiques de hits indisponibles — analyseur injoignable)');
    }
  }

  if (d.certs.expiringSoon.length) {
    lines.push('');
    lines.push('Certificats à renouveler bientôt :');
    for (const c of d.certs.expiringSoon) lines.push(`  ${c.name} — ${c.daysLeft} jour(s) restant(s)`);
  }

  if (d.errors.length) {
    lines.push('');
    lines.push('(Certaines sections n\'ont pas pu être générées : ' + d.errors.join('; ') + ')');
  }

  return lines.join('\n');
}

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * Rendu HTML du mail : tables + styles inline uniquement (Gmail/Outlook
 * ignorent <style> et les flex/grid), largeur 640 px, lisible sur mobile.
 * Toutes les valeurs passent par esc().
 */
function formatDigestHtml(d, { dashboardUrl = '' } = {}) {
  const C = { bg: '#f3f5f9', card: '#ffffff', text: '#1c2230', mute: '#6b7488', line: '#e6e9f0', brand: '#00b765', ok: '#14a05a', warn: '#c98200', crit: '#d6334a' };
  const card = (title, inner) => `<tr><td style="padding:0 24px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${C.card};border:1px solid ${C.line};border-radius:10px"><tr><td style="padding:16px 18px"><div style="font:700 12px/1 Arial,sans-serif;letter-spacing:.8px;text-transform:uppercase;color:${C.mute};margin-bottom:12px">${esc(title)}</div>${inner}</td></tr></table></td></tr>`;
  const kpi = (label, value, sub) => `<td align="center" style="padding:6px 4px;width:25%"><div style="font:700 20px/1.2 Arial,sans-serif;color:${C.text}">${esc(value)}</div><div style="font:11px/1.4 Arial,sans-serif;color:${C.mute}">${esc(label)}</div>${sub ? `<div style="font:11px/1.4 Arial,sans-serif;color:${sub.startsWith('▲') ? C.warn : sub.startsWith('▼') ? C.mute : C.mute}">${esc(sub)}</div>` : ''}</td>`;
  const row = (cells, head) => `<tr>${cells.map((c, i) => `<td style="padding:6px 4px;border-bottom:1px solid ${C.line};font:${head ? '700 11px' : '13px'}/1.4 Arial,sans-serif;color:${head ? C.mute : C.text};text-align:${i ? 'right' : 'left'}">${esc(c)}</td>`).join('')}</tr>`;
  const bar = (pct, color) => `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="background:${C.line};border-radius:4px;height:8px"><div style="width:${Math.max(2, Math.min(100, pct))}%;height:8px;background:${color};border-radius:4px"></div></td></tr></table>`;

  const parts = [];
  // À retenir
  const hl = highlights(d).map(h => `<tr><td style="padding:4px 0;font:14px/1.5 Arial,sans-serif;color:${C.text}"><span style="display:inline-block;width:10px;height:10px;border-radius:5px;background:${h.level === 'crit' ? C.crit : h.level === 'warn' ? C.warn : C.ok};margin-right:8px"></span>${esc(h.text)}</td></tr>`).join('');
  parts.push(card('À retenir', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${hl}</table>`));

  // KPI
  if (d.traffic) {
    const dv = d.previous ? trend(pctDelta(d.traffic.totalRequests, d.previous.totalRequests)) : '';
    const rate = d.traffic.totalRequests ? (100 * d.traffic.totalErrors / d.traffic.totalRequests).toFixed(1) + ' %' : '0 %';
    const bots = d.bots && d.bots.total ? Math.round(100 * d.bots.bots / d.bots.total) + ' %' : '—';
    parts.push(card('Trafic', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>${kpi('Requêtes', nf(d.traffic.totalRequests), dv)}${kpi('Données', fmtBytes(d.traffic.totalBytes))}${kpi('Erreurs', nf(d.traffic.totalErrors), rate)}${kpi('Robots', bots)}</tr></table>`
      + (d.traffic.byVhost.length ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:12px">${row(['Site', 'Requêtes', 'Données', 'Erreurs'], true)}${d.traffic.byVhost.slice(0, 8).map(v => row([v.vhost, nf(v.requests), fmtBytes(v.bytes), nf(v.errors)])).join('')}</table>` : '')));
  } else {
    parts.push(card('Trafic', `<div style="font:13px Arial,sans-serif;color:${C.mute}">Analyseur injoignable.</div>`));
  }

  // Pays
  if (d.topCountries.length) {
    const max = Math.max(...d.topCountries.map(c => c.requests || 0), 1);
    parts.push(card('Top pays', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${d.topCountries.map(c => `<tr><td style="padding:5px 0;font:13px Arial,sans-serif;color:${C.text};width:40%">${flagEmoji(c.country)} ${esc(countryName(c.country))}</td><td style="padding:5px 8px">${bar(100 * (c.requests || 0) / max, C.brand)}</td><td align="right" style="padding:5px 0;font:13px Arial,sans-serif;color:${C.mute};white-space:nowrap">${nf(c.requests)}</td></tr>`).join('')}</table>`));
  }

  // Sécurité
  const sec = [];
  if (d.waf.configured) sec.push(row(['WAF — requêtes bloquées', nf(d.waf.blockedCount)]));
  if (d.crowdsec.configured) {
    sec.push(row(['CrowdSec — décisions actives', nf(d.crowdsec.activeTotal)]));
    for (const [o, n] of Object.entries(d.crowdsec.byOrigin || {})) sec.push(row(['   ' + o, String(n)]));
  }
  if (d.blocklists?.enable) {
    sec.push(row(['Blocklists — IP listées', nf(d.blocklists.totalUniqueIps)]));
    if (d.blocklists.available) {
      sec.push(row(['Blocklists — hits', `${nf(d.blocklists.totalHits)} (${nf(d.blocklists.uniqueHitIps)} IP)`]));
      for (const s of (d.blocklists.bySource || []).slice(0, 5)) sec.push(row(['   ' + s.name, nf(s.hits)]));
    }
  }
  if (sec.length) parts.push(card('Sécurité', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${sec.join('')}</table>`));

  // Certificats
  if (d.certs.expiringSoon.length) {
    parts.push(card('Certificats à renouveler', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${d.certs.expiringSoon.map(c => row([c.name, `${c.daysLeft} j`])).join('')}</table>`));
  }

  if (d.errors.length) parts.push(card('Sections indisponibles', `<div style="font:12px/1.5 Arial,sans-serif;color:${C.mute}">${esc(d.errors.join(' · '))}</div>`));

  const link = dashboardUrl ? `<a href="${esc(dashboardUrl)}" style="color:${C.brand};text-decoration:none;font-weight:700">Ouvrir le dashboard →</a>` : '';
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NGX Ops — Résumé</title></head>
<body style="margin:0;padding:0;background:${C.bg}"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${C.bg}"><tr><td align="center" style="padding:20px 8px">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px">
<tr><td style="padding:0 24px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0f1218;border-radius:10px"><tr><td style="padding:20px 22px"><div style="font:800 20px Arial,sans-serif;color:#ffffff;letter-spacing:-.3px">NGX <span style="color:#00e87a">Ops</span></div><div style="font:14px/1.5 Arial,sans-serif;color:#aab2c5;margin-top:4px">Résumé des ${esc(periodLabel(d.periodHours))} · ${esc(new Date(d.generatedAt).toLocaleString('fr-FR'))}</div></td></tr></table></td></tr>
${parts.join('\n')}
<tr><td align="center" style="padding:8px 24px 0;font:12px/1.6 Arial,sans-serif;color:${C.mute}">${link}<div>Envoyé automatiquement par NGX Ops.</div></td></tr>
</table></td></tr></table></body></html>`;
}

module.exports = { generateDigest, formatDigestText, formatDigestHtml, highlights, countryName, configure };
