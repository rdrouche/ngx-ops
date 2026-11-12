// Journaux (log store) : agrégats multi-instances en lecture seule (ticket #62). Aucune IP, aucun chemin, aucun log brut.
import { h, mount, icon } from '../dom.js';
import { get } from '../api.js';
import { fmt, compact, bytes, ago, toast } from '../util.js';
import { t } from '../i18n.js';
import { card, tile, hbars, donut, columns, empty } from './../viz/widgets.js';

const PERIODS = [[24, '24 h'], [72, '3 j'], [168, '7 j'], [336, '14 j'], [744, '31 j']];
const ERR = () => ({ auth_failed: t('jeton refusé'), timeout: t('délai dépassé'), connection: t('connexion impossible'), tls: t('certificat invalide'), dns: t('nom introuvable'), blocked_url: t('adresse non autorisée'), private_address: t('adresse privée non autorisée'), too_large: t('réponse trop volumineuse'), rate_limited: t('limite atteinte') });
const PROBLEM = () => ({ url_missing: t('URL du log store absente (logstore.url).'), url_invalid: t('URL du log store invalide ou non autorisée par la politique réseau.'), token_missing: t('Jeton de lecture absent ou invalide (HUB_LOGSTORE_TOKEN).') });
const errText = (c) => ERR()[c] || (/^http_\d+$/.test(c) ? `HTTP ${c.slice(5)}` : t('erreur'));
const COUNTRY = (c) => (c === '??' || c === '' ? t('Inconnu') : c);

function body(d) {
  if (!d.enabled) return card(t('Journaux'), empty(t('Le log store n’est pas configuré.')));
  const v = d.visits; const sec = d.security; const k = d.totals;
  const blocked = sec ? sec.blocked.reduce((a, b) => a + b.count, 0) : 0;
  const tiles = h('div', { class: 'kpis' },
    k ? tile(t('Requêtes'), compact(k.requests), t('{h} h', { h: d.hours })) : null,
    k ? tile(t('Erreurs 4xx'), fmt(k.s4xx), k.requests ? `${((k.s4xx / k.requests) * 100).toFixed(1)} %` : '', k.requests && k.s4xx / k.requests > 0.1 ? 'warn' : undefined) : null,
    k ? tile(t('Erreurs 5xx'), fmt(k.s5xx), k.requests ? `${((k.s5xx / k.requests) * 100).toFixed(1)} %` : '', k.s5xx ? 'err' : 'ok') : null,
    k ? tile(t('Volume'), bytes(k.bytes), '') : null,
    sec ? tile(t('Blocages'), fmt(blocked), '', blocked ? 'warn' : undefined) : null,
    sec ? tile(t('Scanners détectés'), fmt(sec.scanners), t('IP distinctes (non exposées)')) : null);

  const series = [{ key: 's5xx', label: '5xx', cls: 'err' }, { key: 's4xx', label: '4xx', cls: 'warn' }, { key: 's3xx', label: '3xx', cls: 'c1' }, { key: 's2xx', label: '2xx', cls: 'ok' }];
  const hist = card(t('Requêtes par code de statut'), v && v.points.length ? columns(v.points, series, { step: v.bucket === 'day' ? 86400e3 : 3600e3 }) : empty());
  const classes = sec ? card(t('Codes de statut'), donut([{ label: '2xx', value: sec.status_classes.s2xx, cls: 'ok' }, { label: '3xx', value: sec.status_classes.s3xx, cls: 'c1' }, { label: '4xx', value: sec.status_classes.s4xx, cls: 'warn' }, { label: '5xx', value: sec.status_classes.s5xx, cls: 'err' }], { center: compact(Object.values(sec.status_classes).reduce((a, b) => a + b, 0)), sub: t('requêtes') })) : null;
  const top = (dim, title, label = (x) => x) => (d.tops[dim] && d.tops[dim].length ? card(title, hbars(d.tops[dim].map((x) => ({ label: label(x.key), value: x.count })), { limit: 8 })) : null);
  const blk = sec && sec.blocked.length ? card(t('Blocages par source'), hbars(sec.blocked.map((b) => ({ label: `${b.source} · ${b.action}`, value: b.count, cls: 'err' })), { limit: 8 })) : null;
  const inst = d.instances && d.instances.length ? card(t('Instances connues du log store'), h('div', { class: 'tbl-wrap' }, h('table', null,
    h('thead', null, h('tr', null, [t('Instance'), t('Événements'), t('Dernier envoi')].map((x, i) => h('th', { scope: 'col', class: i === 1 ? 'r' : null }, x)))),
    h('tbody', null, d.instances.map((i) => h('tr', null, h('td', null, h('b', null, i.name || i.id), i.name ? h('div', { class: 'muted mono' }, i.id) : null), h('td', { class: 'r num' }, fmt(i.events_total)), h('td', { class: 'nowrap muted' }, i.last_seen ? ago(i.last_seen) : '—')))))), { badge: d.instances.length }) : null;

  const s = d.store;
  const db = s ? card(t('Base de données du log store'), s.detail
    ? h('div', { class: 'mini' }, [
      [t('Version'), s.version || '—'],
      ['TimescaleDB', s.timescale ? t('oui') : t('non (PostgreSQL simple)')],
      [t('Taille de la base'), bytes(s.db_size_bytes)],
      [t('Dernier envoi reçu'), s.last_ingest ? ago(s.last_ingest) : '—'],
      [t('Rétention des journaux bruts'), s.retention_days ? `${s.retention_days} ${t('jours')}` : '—'],
      [t('Mode des adresses IP'), ({ clear: t('en clair'), pseudonymized: t('pseudonymisées'), truncated: t('tronquées') })[s.ip_mode] || '—'],
    ].map(([l, v]) => h('div', null, h('span', { class: 'd' }, l), h('b', null, v))))
    : empty(t('Le détail de la base exige un jeton de lecture global (sans instance).'))) : null;

  const errs = Object.entries(d.errors || {});
  const banner = errs.length ? h('div', { class: 'banner' }, icon('warn', 20), h('div', { class: 't' }, h('b', null, t('Données partielles')), h('span', null, errs.map(([n, c]) => `${n} : ${errText(c)}`).join(' · ')))) : null;
  return h('div', { class: 'stack vz-root' }, banner, tiles, h('div', { class: 'vz-grid' }, hist, classes, top('site', t('Sites les plus sollicités')), top('country', t('Pays'), COUNTRY), top('rule', t('Règles déclenchées')), blk, top('bot_class', t('Types de clients')), top('source', t('Sources d’événements')), db, inst));
}

export function logstoreView(root) {
  const st = { hours: 24, instance: '' };
  const toolbar = h('div'); const out = h('div', { class: 'stack' });
  let instances = [];
  const drawBar = () => mount(toolbar, h('div', { class: 'toolbar' },
    h('label', { class: 'check' }, t('Période'), ' ', h('select', { class: 'select', 'aria-label': t('Période'), onChange: (e) => { st.hours = Number(e.target.value); load(); } }, PERIODS.map(([hrs, l]) => h('option', { value: String(hrs), selected: hrs === st.hours }, t(l))))),
    h('label', { class: 'check' }, t('Instance'), ' ', h('select', { class: 'select', 'aria-label': t('Instance'), onChange: (e) => { st.instance = e.target.value; load(); } },
      h('option', { value: '' }, t('Toutes')), instances.map((i) => h('option', { value: i.id, selected: i.id === st.instance }, i.name || i.id)))),
    h('span', { class: 'muted grow' }, t('Agrégats en lecture seule : aucune adresse IP, aucun chemin ni journal brut.'))));
  async function load() {
    try {
      const d = await get(`/logstore/overview?hours=${st.hours}${st.instance ? `&instance=${encodeURIComponent(st.instance)}` : ''}`);
      if (d.instances && !instances.length) { instances = d.instances; }
      drawBar(); mount(out, body(d));
    } catch (e) { if (e.code !== 'unauthenticated') toast(e.message); }
  }
  mount(root, h('div', { class: 'page-h' }, h('div', null, h('h1', null, t('Journaux')), h('p', null, t('Visites, sécurité et blocages de toutes les instances (log store).')))), toolbar, out);
  drawBar(); load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 60_000);
  return () => clearInterval(timer);
}
