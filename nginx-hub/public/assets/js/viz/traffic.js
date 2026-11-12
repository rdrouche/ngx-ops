// Onglet Trafic : volumes, erreurs, humains/bots, vhosts et pays (ticket #67).
import { h } from '../dom.js';
import { fmt, compact, bytes } from '../util.js';
import { t } from '../i18n.js';
import { trafficModel, topN } from './model.js';
import { card, tile, hbars, donut, stack, columns, empty } from './widgets.js';

const CAT_CLS = { human: 'c2', good: 'c1', ai: 'c4', bad: 'err', unknown: 'off' };
const CAT_LABEL = () => ({ human: t('Humains'), good: t('Bots légitimes'), ai: t('IA'), bad: t('Bots malveillants'), unknown: t('Inconnus') });
const rate = (e, r) => (r > 0 ? `${((e / r) * 100).toFixed(1)} %` : '');
const country = (c) => (c === '??' ? t('Inconnu') : c);

export function trafficView(data) {
  const m = trafficModel(data);
  const k = m.kpis;
  const cat = CAT_LABEL();

  const tiles = h('div', { class: 'kpis' },
    k.requests ? tile(t('Requêtes'), compact(k.requests), t('{n} vhosts', { n: k.vhosts })) : null,
    k.requests ? tile(t('Erreurs'), fmt(k.errors), rate(k.errors, k.requests), k.errorRate > 10 ? 'err' : k.errorRate > 3 ? 'warn' : 'ok') : null,
    k.bytes ? tile(t('Volume sortant'), bytes(k.bytes), '') : null,
    k.humanRate !== null ? tile(t('Trafic humain'), `${k.humanRate} %`, t('{n} bots', { n: fmt(k.bots ?? 0) }), k.humanRate < 50 ? 'warn' : '') : null,
    k.countries ? tile(t('Pays'), fmt(k.countries), t('distincts')) : null);

  const hourly = m.hourly.length ? card(t('Requêtes par heure'), columns(m.hourly, [{ key: 'errors', label: t('Erreurs'), cls: 'err' }, { key: 'requests', label: t('Requêtes'), cls: 'c1' }]))
    : card(t('Requêtes par heure'), empty(t('Aucune série horaire sur la période : l\'analyseur n\'a pas encore de données ou la période est trop courte.')));

  const clients = card(t('Qui visite ?'), m.categories.length
    ? donut(m.categories.map((c) => ({ label: cat[c.key] || c.key, value: c.value, cls: CAT_CLS[c.key] || 'c6' })), { center: compact(m.categories.reduce((a, c) => a + c.value, 0)), sub: t('requêtes') })
    : empty());

  const vh = card(t('Virtual hosts'), m.vhosts.length
    ? hbars(m.vhosts.slice(0, 10).map((v) => ({ label: v.name, value: v.requests, sub: v.errors ? `${fmt(v.errors)} ${t('err.')}` : '', cls: v.requests && v.errors / v.requests > 0.2 ? 'warn' : 'c1' })), { format: compact })
    : empty(), { badge: m.vhosts.length });

  const withClients = m.vhosts.filter((v) => v.human !== null && v.requests > 0).slice(0, 6);
  const mix = withClients.length ? card(t('Humains / bots par vhost'), h('div', { class: 'vz-stack' }, withClients.map((v) => h('div', null, h('div', { class: 'vz-cap' }, h('b', null, v.name), h('span', { class: 'muted' }, fmt(v.human + v.bots))),
    stack([{ label: t('Humains'), value: v.human, cls: 'c2' }, { label: t('Bots'), value: v.bots, cls: 'c5' }]))))) : null;

  const { top, rest, restCount } = topN(m.countries.map((c) => ({ ...c, value: c.requests })), 10);
  const geo = card(t('Pays'), m.countries.length
    ? hbars([...top.map((c) => ({ label: country(c.code), value: c.requests, sub: c.errors ? rate(c.errors, c.requests) : '', cls: c.requests && c.errors / c.requests > 0.5 ? 'warn' : 'c1' })), ...(restCount ? [{ label: t('{n} autres pays', { n: restCount }), value: rest, cls: 'off' }] : [])], { format: compact })
    : empty(), { badge: m.countries.length });
  const noisy = m.countries.filter((c) => c.requests >= 100 && c.errors / c.requests > 0.8).slice(0, 8);
  const noise = noisy.length ? card(t('Pays presque 100 % en erreur'), hbars(noisy.map((c) => ({ label: country(c.code), value: c.errors, sub: rate(c.errors, c.requests), cls: 'err' })), { format: compact }), { note: t('Scanners probables') }) : null;

  return h('div', { class: 'stack vz-root' }, tiles, h('div', { class: 'vz-grid' }, hourly, clients, vh, mix, geo, noise));
}
