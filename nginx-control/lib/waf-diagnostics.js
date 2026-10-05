'use strict';
/**
 * WAF emule — conseils de configuration (page « Conseils », GET /api/waf/diagnostics).
 *
 * Module PUR : il recoit l'etat deja lu (statut du conteneur WAF, vhosts, reglages,
 * extraits de configuration nginx) et renvoie une liste de conseils structures
 *   { id, level: 'info'|'warn'|'ok', titleKey, detailKey, vars, [snippet, file] }
 * Aucun texte en dur : le front traduit `titleKey`/`detailKey` (wafemu.diag.<id>.title|detail)
 * avec `vars`. Seuls `snippet` (code nginx a copier) et `file` (nom de fichier suggere) sont
 * du contenu technique non traduisible.
 */
const { extractBlocks } = require('./vhost-targets');

// Snippet EXACT du contrat (WAF-CONTRACT.md) : fichier separe, jamais le log principal,
// pour ne pas perturber GoAccess ni l'analyseur.
const WAF_JSON_SNIPPET =
  'log_format waf_json escape=json \'{"t":"$time_iso8601","vhost":"$host","ip":"$remote_addr","m":"$request_method","u":"$request_uri","p":"$server_protocol","s":$status,"ua":"$http_user_agent","ref":"$http_referer","ct":"$content_type","cl":"$content_length","xff":"$http_x_forwarded_for","acc":"$http_accept","al":"$http_accept_language","ae":"$http_accept_encoding","org":"$http_origin","xrw":"$http_x_requested_with"}\';\n' +
  'access_log /var/log/nginx/waf.wafemu.log waf_json;';
const WAF_JSON_FILE = 'waf-emu-log.conf';

const stripComments = (s) => String(s || '').replace(/^\s*#.*$/gm, '').replace(/\s#[^\n]*$/gm, '');
const SERVER_RE = () => /(?<![A-Za-z0-9_$.-])server\s*\{/g;

function parseAccessLogs(text) {
  const out = [];
  for (const m of stripComments(text).matchAll(/(?:^|[;{}\s])access_log\s+([^;]+);/g)) {
    const toks = m[1].trim().split(/\s+/);
    if (toks[0] === 'off') { out.push({ off: true }); continue; }
    const cond = (toks.find(t => /^if=/.test(t)) || '').slice(3);
    const rest = toks.slice(1).filter(t => !/^(if|buffer|flush|gzip)(=|$)/.test(t));
    out.push({ off: false, path: toks[0], format: rest[0] || 'combined', cond });
  }
  return out;
}

/**
 * @param {Array<{name:string, content:string}>} files   fichiers nginx (conf.d + sites)
 * @returns {{ formats:string[], global:object[], vhosts:object[], wafJsonDefined:boolean, wafJsonLogged:boolean, notStaticFilter:boolean }}
 */
function scanNginxLogging(files) {
  const formats = new Set();
  const global = [];
  const vhosts = [];
  for (const f of files || []) {
    const content = String(f.content || '');
    for (const m of stripComments(content).matchAll(/(?:^|[;{}\s])log_format\s+(\S+)/g)) formats.add(m[1]);
    let outside = content;
    for (const { match, body } of extractBlocks(content, SERVER_RE())) {
      outside = outside.replace(match[0] + body + '}', '');
      const names = ((stripComments(body).match(/server_name\s+([^;]+);/) || [])[1] || '').trim().split(/\s+/).filter(Boolean);
      const logs = parseAccessLogs(body);
      for (const name of names) {
        if (name === '_') continue;
        vhosts.push({ name, file: f.name, accessLogOff: logs.some(l => l.off) && !logs.some(l => !l.off), logs: logs.filter(l => !l.off) });
      }
    }
    for (const l of parseAccessLogs(outside)) global.push({ ...l, file: f.name });
  }
  const all = [...global, ...vhosts.flatMap(v => v.logs)];
  return {
    formats: [...formats],
    global, vhosts,
    wafJsonDefined: formats.has('waf_json'),
    wafJsonLogged: all.some(l => !l.off && l.format === 'waf_json'),
    notStaticFilter: all.some(l => !l.off && /\$is_not_static/.test(l.cond || '')),
  };
}

const lvl = (id, level, vars, extra) => ({ id, level, titleKey: `wafemu.diag.${id}.title`, detailKey: `wafemu.diag.${id}.detail`, vars: vars || {}, ...(extra || {}) });

/**
 * @param {object} i
 * @param {object|null} i.status        /api/status du WAF (null = injoignable)
 * @param {object[]}    i.vhosts        lignes de /api/waf/vhosts (avec seen:boolean)
 * @param {object|null} i.settings      reglages du WAF
 * @param {object}      i.nginx         resultat de scanNginxLogging()
 * @param {{blocklistEnabled:boolean, challengeEnabled:boolean, hasWafSource:boolean}} i.lists
 */
function buildDiagnostics({ status, vhosts = [], settings = null, nginx = null, lists = {} } = {}) {
  const out = [];
  if (!status) return [lvl('unreachable', 'warn')];
  const logs = status.logs || {};
  const formats = logs.formats || {};
  const ng = nginx || { global: [], vhosts: [], formats: [] };

  if (status.engine && status.engine.ready === false) out.push(lvl('engine_error', 'warn', { error: String((status.engine && status.engine.error) || '') }));

  const crs = status.crs || {};
  if (crs.downloading) out.push(lvl('crs_downloading', 'info', { version: crs.version || '' }));
  else if (crs.lastError) out.push(lvl('crs_error', 'warn', { error: String(crs.lastError), version: crs.version || '' }));
  else if (!crs.installed) out.push(lvl('crs_missing', 'warn', { version: crs.version || '' }));
  else out.push(lvl('crs_ok', 'ok', { version: crs.version || '', rules: crs.rulesLoaded || 0 }));

  if (Array.isArray(crs.filesIgnored) && crs.filesIgnored.length) {
    out.push(lvl('rules_ignored', 'warn', { count: crs.filesIgnored.length, files: crs.filesIgnored.map(f => f.file).slice(0, 5).join(', ') }));
  }

  // Format de log : sans prefixe vhost, la selection par vhost est impossible (sauf un fichier par vhost).
  if ((formats.combined || 0) > 0) out.push(lvl('log_combined_no_vhost', 'warn', { files: formats.combined }));
  if ((formats.waf_json || 0) > 0) out.push(lvl('waf_json_active', 'ok', { files: formats.waf_json }));
  else if (ng.wafJsonLogged || ng.wafJsonDefined) out.push(lvl('waf_json_not_read', 'warn', { file: 'waf.wafemu.log' }));
  else out.push(lvl('waf_json_missing', 'info', {}, { snippet: WAF_JSON_SNIPPET, file: WAF_JSON_FILE }));

  if (ng.notStaticFilter) out.push(lvl('static_not_logged', 'info'));

  // Vhosts nginx sans log / sans trafic.
  const logOff = ng.vhosts.filter(v => v.accessLogOff).map(v => v.name);
  if (logOff.length) out.push(lvl('vhost_log_off', 'warn', { count: logOff.length, names: [...new Set(logOff)].slice(0, 8).join(', ') }));
  const noTraffic = vhosts.filter(v => v.seen === false && !logOff.includes(v.name)).map(v => v.name);
  if (noTraffic.length) out.push(lvl('vhost_no_traffic', 'info', { count: noTraffic.length, names: noTraffic.slice(0, 8).join(', ') }));

  // Regles « non fiables » desactivees par le systeme.
  const unreliable = status.unreliableRules || {};
  const nUnreliable = new Set(Object.values(unreliable).flat()).size;
  if (nUnreliable > 0) out.push(lvl('rules_unreliable', 'info', { count: nUnreliable, combined: (unreliable.combined || []).length, wafJson: (unreliable.waf_json || []).length }));

  // Lignes perdues : trois causes distinctes, trois messages (v12.70.2). Compat : `dropped` seul = ancien conteneur.
  const qd = logs.queueDropped || 0, unparsed = logs.unparsed || 0, notReady = logs.notReady || 0;
  const legacy = logs.unparsed === undefined && logs.queueDropped === undefined ? (logs.dropped || 0) : 0;
  if (qd > 0 || legacy > 0) out.push(lvl('saturation', 'warn', { dropped: qd || legacy }));
  if (unparsed > 0) {
    const samples = Array.isArray(logs.unparsedSamples) ? logs.unparsedSamples.slice(0, 5) : [];
    out.push(lvl('unparsed', 'info', { count: unparsed }, samples.length ? { snippet: samples.join('\n') } : {}));
  }
  if (notReady > 0) out.push(lvl('engine_not_ready', 'info', { count: notReady }));
  // Journaux combined ET waf_json suivis ensemble : doublons ecartes automatiquement.
  if ((formats.waf_json || 0) > 0 && ((formats.combined || 0) + (formats.vhost || 0)) > 0) {
    out.push(lvl('dedup_active', 'ok', { count: logs.duplicatesSkipped || 0 }));
  }

  // Remediation : listes et challenge doivent suivre.
  if (settings) {
    const remediating = settings.mode === 'remediate' || Object.values(settings.vhosts || {}).some(v => v && v.mode === 'remediate');
    if (remediating) {
      if (!lists.blocklistEnabled) out.push(lvl('blocklist_disabled', 'warn'));
      else if (!lists.hasWafSource) out.push(lvl('no_waf_source', 'warn'));
      const th = settings.thresholds || {};
      if (th.challenge && !lists.challengeEnabled) out.push(lvl('challenge_disabled', 'warn', { threshold: th.challenge }));
    }
  }
  return out;
}

module.exports = { scanNginxLogging, buildDiagnostics, parseAccessLogs, WAF_JSON_SNIPPET, WAF_JSON_FILE };
