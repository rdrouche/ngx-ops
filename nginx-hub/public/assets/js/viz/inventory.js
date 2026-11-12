// Onglet Inventaire : nginx, certificats, hôtes virtuels, conteneurs (ticket #67).
import { h } from '../dom.js';
import { fmt, ago } from '../util.js';
import { t } from '../i18n.js';
import { inventoryModel } from './model.js';
import { card, tile, status, hbars, donut, lifebar, empty } from './widgets.js';

const KIND_LABEL = () => ({ docker: t('Conteneur'), upstream: t('Upstream'), static: t('Statique'), other: t('Autre') });
const certTone = (c) => (c.expired ? 'err' : c.warning || (c.daysLeft !== null && c.daysLeft < 30) ? 'warn' : 'ok');

export function inventoryView(data) {
  const m = inventoryModel(data);
  const v = m.vhosts;
  const ng = m.nginx;
  const cs = m.certSummary;

  const strip = h('div', { class: 'vz-strip' },
    ng ? status('nginx', ng.running ? 'ok' : 'err', [ng.version, ng.tls].filter(Boolean).join(' · ')) : null,
    ...m.containers.map((c) => status(c.name, c.running ? 'ok' : 'err', c.started ? ago(Date.parse(c.started)) : c.status || '')),
    m.agents.total ? status(t('Agents'), m.agents.online === m.agents.total ? 'ok' : 'warn', `${m.agents.online} / ${m.agents.total}`) : null);

  const tiles = h('div', { class: 'kpis' },
    v.files ? tile(t('Virtual hosts'), fmt(v.files), t('{n} blocs server', { n: v.blocks })) : null,
    v.blocks ? tile('HTTPS', `${Math.round((v.ssl / v.blocks) * 100)} %`, t('{n} redirections HTTP→HTTPS', { n: v.redirects })) : null,
    cs ? tile(t('Certificats'), fmt(cs.total), t('{e} expirés · {w} à renouveler', { e: cs.expired ?? 0, w: cs.warning ?? 0 }), cs.expired ? 'err' : cs.warning ? 'warn' : 'ok') : null,
    v.blocks ? tile(t('Supervisés'), fmt(v.monitored), t('sur {n} blocs', { n: v.blocks }), v.monitored ? '' : 'warn') : null,
    ng && ng.conn ? tile(t('Connexions actives'), fmt(ng.conn.active), t('{r} en lecture · {w} en écriture', { r: ng.conn.reading, w: ng.conn.writing })) : null);

  const certs = card(t('Certificats'), m.certs.length
    ? h('div', { class: 'cert-list' }, m.certs.map((c) => h('div', { class: 'cert-row' },
      h('span', { class: 'cert-n', title: c.file }, c.name, c.sans > 1 ? h('small', null, t('{n} noms', { n: c.sans })) : null),
      lifebar(c.daysLeft, c.totalDays, certTone(c)),
      h('span', { class: `cert-d num t-${certTone(c)}` }, c.expired ? t('expiré') : c.daysLeft === null ? '—' : t('{n} j', { n: fmt(c.daysLeft) })))))
    : empty(), { badge: m.certs.length, note: t('triés par échéance') });

  const kinds = KIND_LABEL();
  const hosts = card(t('Hôtes virtuels'), v.blocks
    ? h('div', { class: 'vz-split' },
      h('div', null, h('h3', { class: 'vz-h3' }, t('Protocole')), donut([{ label: 'HTTPS', value: v.ssl, cls: 'ok' }, { label: t('HTTP → HTTPS'), value: v.redirects, cls: 'c1' }, { label: t('HTTP seul'), value: Math.max(0, v.blocks - v.ssl - v.redirects), cls: 'warn' }], { center: String(v.blocks), sub: t('blocs') })),
      h('div', null, h('h3', { class: 'vz-h3' }, t('Destinations')), v.kinds.length ? hbars(v.kinds.map((k, i) => ({ label: kinds[k.key] || k.key, value: k.value, cls: ['c1', 'c3', 'c4', 'c6'][i % 4] }))) : empty()))
    : empty(), { badge: v.files });

  const conn = ng && ng.conn ? card(t('Connexions nginx'), hbars([
    { label: t('Actives'), value: ng.conn.active, cls: 'c1' }, { label: t('En attente'), value: ng.conn.waiting, cls: 'c3' },
    { label: t('Lecture'), value: ng.conn.reading, cls: 'c2' }, { label: t('Écriture'), value: ng.conn.writing, cls: 'c4' }]),
  { note: ng.conn.requests ? t('{n} requêtes depuis le démarrage', { n: fmt(ng.conn.requests) }) : null }) : null;

  return h('div', { class: 'stack vz-root' }, strip, tiles, h('div', { class: 'vz-grid' }, certs, hosts, conn));
}
