'use strict';
// v12.72.0 — Aide contextuelle (modal) pour Blocklists / Diagnostic / Monitoring.
// Textes dans les fichiers de langue : help.<page>.title, help.<page>.<id>.t|.b
// Pour ajouter une page : ajouter une entree dans PAGE_HELP + cles i18n + bouton pageHelpOpen('<page>').

const PH_BLOCKLISTS_YAML = [
  'blocklists:',
  '  - name: spamhaus-drop',
  '    type: url',
  '    url: https://www.spamhaus.org/drop/drop.txt',
  '    action: deny_403        # deny_403 | drop_444 | challenge',
  '  - name: waf-block',
  '    type: waf               # IP issues du WAF emule',
  '    action: challenge',
  'whitelist:',
  '  - 203.0.113.10',
].join('\n');

const PH_BLOCKLISTS_VHOST = [
  'server {',
  '    listen 443 ssl;',
  '    server_name app.example.com;',
  '',
  '    include snippets/blocklist-enforce.conf;   # deny / drop (opt-in par vhost)',
  '    include snippets/challenge-gate.conf;      # APRES enforce, si challenge_enable: true',
  '',
  '    location / { proxy_pass http://backend; }',
  '}',
].join('\n');

const PH_DIAG_VHOST = [
  'server {',
  '    listen 80;',
  '    server_name app.example.com;',
  '    return 301 https://$host$request_uri;',
  '}',
  'server {',
  '    listen 443 ssl;',
  '    server_name app.example.com;',
  '    server_tokens off;',
  '    add_header Strict-Transport-Security "max-age=31536000" always;',
  '    location / { proxy_pass http://backend; }',
  '}',
].join('\n');

const PH_MONITORING_VHOST = [
  'server {',
  '    server_name app.example.com;',
  '    # nginx-control-monitoring: on',
  '    # nginx-control-monitoring-interval: 60s',
  '    # nginx-control-monitoring-valid-http-code: 200,301,302',
  '    # nginx-control-monitoring-ignore-location: on',
  '    location / { proxy_pass http://backend; }',
  '}',
].join('\n');

const PH_DIAG_OPTOUT = [
  '# Fichier entier (avant le premier server{}) :',
  '# nginx-control-diagnostic: off',
  '',
  'server {',
  '    server_name legacy.example.com;',
  '    # Ce bloc seulement :',
  '    # nginx-control-diagnostic-vhost: off',
  '    return 301 https://app.example.com$request_uri;',
  '}',
].join('\n');

const PAGE_HELP = {
  blocklists: [['what', null], ['config', PH_BLOCKLISTS_YAML], ['nginx', PH_BLOCKLISTS_VHOST], ['challenge', null], ['check', null]],
  diagnostic: [['what', null], ['tabs', null], ['vhost', PH_DIAG_VHOST], ['badges', null], ['fix', null], ['optout', PH_DIAG_OPTOUT]],
  monitoring: [['what', null], ['enable', PH_MONITORING_VHOST], ['status', null], ['history', null]],
};

function phEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function pageHelpOpen(page) {
  const sections = PAGE_HELP[page];
  if (!sections) return;
  document.getElementById('page-help-title').textContent = t('help.' + page + '.title');
  const body = document.getElementById('page-help-body');
  body.textContent = '';
  sections.forEach(([id, code]) => {
    const h = phEl('div', t('help.' + page + '.' + id + '.t'), 'ctitle');
    h.style.cssText = 'margin:14px 0 4px;font-size:12px';
    body.appendChild(h);
    t('help.' + page + '.' + id + '.b').split('\n').forEach(par => {
      const p = phEl('div', par); p.style.margin = '0 0 4px';
      body.appendChild(p);
    });
    if (code) {
      const pre = phEl('pre', code);
      pre.style.cssText = 'margin:6px 0;padding:10px;background:var(--bg);border-radius:var(--r);color:var(--text2);overflow:auto';
      body.appendChild(pre);
    }
  });
  document.getElementById('page-help-overlay').style.display = 'flex';
}
function pageHelpClose() { document.getElementById('page-help-overlay').style.display = 'none'; }
