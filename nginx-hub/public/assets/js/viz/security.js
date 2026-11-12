// Onglet Sécurité : état des protections, indicateurs, alertes, listes de blocage, challenge, WAF (ticket #67).
import { h } from '../dom.js';
import { fmt, compact, dateTime } from '../util.js';
import { t } from '../i18n.js';
import { smartTable } from '../smart.js';
import { securityModel } from './model.js';
import { card, tile, status, hbars, donut, funnel, columns, empty } from './widgets.js';

const SEV_CLS = { critical: 'err', high: 'err', medium: 'warn', low: 'c1', info: 'c4' };
const SEV_LABEL = () => ({ critical: t('Critique'), high: t('Élevée'), medium: t('Moyenne'), low: t('Faible'), info: t('Info') });
const SRC_CLS = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6'];
const TYPE_LABEL = () => ({ scan: t('Scan'), flood: t('Flood') });

export function securityView(data) {
  const m = securityModel(data);
  const k = m.kpis;
  const ruleName = new Map(m.rules.map((r) => [r.key, r.name]));
  const typeLabel = TYPE_LABEL();

  const comp = Object.fromEntries(m.components.map((c) => [c.id, c]));
  const strip = h('div', { class: 'vz-strip' },
    status(t('Listes de blocage'), comp.blocklists.state, comp.blocklists.state === 'off' ? '' : t('{n} sources', { n: comp.blocklists.count }) + (comp.blocklists.errors ? ` · ${t('{n} en erreur', { n: comp.blocklists.errors })}` : '')),
    status('Challenge', comp.challenge.state, [comp.challenge.engine, comp.challenge.paused ? t('en pause') : ''].filter(Boolean).join(' · ')),
    status('WAF', comp.waf.state, [comp.waf.engine, comp.waf.rulesLoaded ? t('{n} règles', { n: comp.waf.rulesLoaded }) : '', comp.waf.paranoia ? `PL${comp.waf.paranoia}` : ''].filter(Boolean).join(' · ')),
    status('CrowdSec', comp.crowdsec.state, comp.crowdsec.state === 'off' ? t('non configuré') : t('{n} décisions', { n: comp.crowdsec.decisions })));

  const tiles = h('div', { class: 'kpis' },
    k.blockedIps !== null ? tile(t('IP bloquées (uniques)'), fmt(k.blockedIps), t('{n} entrées en liste blanche', { n: m.whitelist })) : null,
    k.hits !== null ? tile(t('Hits des listes'), fmt(k.hits), t('{n} IP distinctes', { n: fmt(k.hitIps ?? 0) })) : null,
    k.alerts !== null ? tile(t('Alertes'), fmt(k.alerts), t('{n} non acquittées', { n: fmt(k.unacked ?? 0) }), k.unacked ? 'err' : 'ok') : null,
    k.wafRequests !== null ? tile(t('WAF — requêtes (24 h)'), compact(k.wafRequests), t('{n} détections · {i} IP', { n: fmt(k.wafHits ?? 0), i: fmt(k.wafIps ?? 0) }), k.wafHits ? 'warn' : 'ok') : null,
    k.challengeStarted ? tile(t('Challenge résolus'), k.solveRate !== null ? `${k.solveRate} %` : '—', t('{s} sur {n} démarrés', { s: fmt(k.challengeSolved), n: fmt(k.challengeStarted) }), k.solveRate !== null && k.solveRate < 50 ? 'warn' : 'ok') : null);

  const alertTypes = m.alertsByType.map((a, i) => ({ label: ruleName.get(a.key) || typeLabel[a.key] || a.key, value: a.value, cls: SRC_CLS[i % SRC_CLS.length] }));
  const sev = SEV_LABEL();
  const alertsCard = card(t('Alertes'), m.alertsByType.length || m.alertsBySeverity.length
    ? h('div', { class: 'vz-split' },
      h('div', null, h('h3', { class: 'vz-h3' }, t('Par type')), hbars(alertTypes)),
      h('div', null, h('h3', { class: 'vz-h3' }, t('Par sévérité')), donut(m.alertsBySeverity.map((a) => ({ label: sev[a.key] || a.key, value: a.value, cls: SEV_CLS[a.key] || 'c1' })), { center: compact(k.alerts ?? 0), sub: t('alertes') })))
    : empty(t('Aucune alerte.')), { badge: k.unacked ? t('{n} à traiter', { n: fmt(k.unacked) }) : null });

  const hitsCard = card(t('Hits des listes de blocage'), m.hitsBySource.length
    ? h('div', { class: 'vz-split' },
      h('div', null, h('h3', { class: 'vz-h3' }, t('Par source')), donut(m.hitsBySource.map((s, i) => ({ label: s.key, value: s.value, cls: SRC_CLS[i % SRC_CLS.length] })), { center: compact(k.hits ?? 0), sub: t('hits') })),
      h('div', null, h('h3', { class: 'vz-h3' }, t('IP les plus touchées')), hbars(m.topHitIps.map((i) => ({ label: i.key, value: i.value })), { mono: true, limit: 8 })))
    : empty());

  const ch = m.challenge;
  const challengeCard = card('Challenge', ch.steps.some(([, v]) => v > 0)
    ? h('div', { class: 'vz-stack' },
      funnel([
        { label: t('Pages servies'), value: ch.steps[0][1], cls: 'c1' }, { label: t('Démarrés'), value: ch.steps[1][1], cls: 'c3' },
        { label: t('Résolus'), value: ch.steps[2][1], cls: 'ok' }, { label: t('Échoués'), value: ch.steps[3][1], cls: 'err' },
      ]),
      ch.series.length ? h('div', null, h('h3', { class: 'vz-h3' }, t('Activité par heure')), columns(ch.series.map((p) => ({ ...p, abandoned: Math.max(0, p.started - p.solved - p.failed) })), [{ key: 'solved', label: t('Résolus'), cls: 'ok' }, { key: 'failed', label: t('Échoués'), cls: 'err' }, { key: 'abandoned', label: t('Abandonnés'), cls: 'c3' }])) : null)
    : empty(), { note: ch.windowHours ? t('{h} dernières heures', { h: ch.windowHours }) : null });

  const srcCard = card(t('Sources de blocage'), m.sources.length
    ? hbars(m.sources.map((s, i) => ({ label: s.name, value: s.count, cls: s.error ? 'err' : s.enable ? SRC_CLS[i % SRC_CLS.length] : 'off', sub: s.error ? t('erreur') : !s.enable ? t('désactivée') : s.type || '' })))
    : empty(), { badge: m.sources.length });

  const rulesCard = m.rules.some((r) => r.detected > 0) ? card(t('Règles d’analyse déclenchées'), hbars(m.rules.filter((r) => r.detected > 0).map((r) => ({ label: r.name, value: r.detected, cls: r.remediation === 'block' ? 'c5' : 'c1', sub: r.remediation !== 'none' ? r.remediation : '' })))) : null;

  const wafCard = card('WAF', m.waf.rules.length || m.waf.ips.length
    ? h('div', { class: 'vz-split' },
      h('div', null, h('h3', { class: 'vz-h3' }, t('Règles')), hbars(m.waf.rules.map((r) => ({ label: String(r.id ?? r.rule ?? r.name ?? '?'), value: Number(r.count ?? r.hits ?? 0) })), { limit: 8 })),
      h('div', null, h('h3', { class: 'vz-h3' }, 'IP'), hbars(m.waf.ips.map((r) => ({ label: String(r.ip ?? '?'), value: Number(r.count ?? r.hits ?? 0) })), { mono: true, limit: 8 })))
    : empty(t('Aucune détection WAF sur la période.')));

  const bansCard = card(t('Bannissements actifs'), m.bans.length ? smartTable(m.bans, { name: 'bans', maxCols: 8 }) : empty(t('Aucun bannissement actif.')),
    { badge: m.bans.length, note: m.offenders.length ? t('{n} contrevenants suivis', { n: m.offenders.length }) : null });
  const offenders = m.offenders.length ? card(t('Contrevenants suivis'), h('div', { class: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'IP'), h('th', { class: 'r' }, t('Tentatives')), h('th', null, t('Hôte')), h('th', null, t('Dernière vue')))),
    h('tbody', null, m.offenders.slice(0, 10).map((o) => h('tr', null, h('td', { class: 'mono' }, String(o.ip)), h('td', { class: 'r num' }, fmt(o.attempts)), h('td', null, String(o.host || '—')), h('td', { class: 'nowrap' }, o.lastSeen ? dateTime(o.lastSeen * 1000) : '—'))))))) : null;

  return h('div', { class: 'stack vz-root' }, strip, tiles, h('div', { class: 'vz-grid' }, alertsCard, hitsCard, challengeCard, srcCard, rulesCard, wafCard, bansCard, offenders));
}
