'use strict';
// Chemins hote detectes (#103) : fonctions pures, sur les deux compose du ticket.
const assert = require('assert');
const HP = require('../lib/host-paths');

let fail = 0;
function check(name, fn) { try { fn(); console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

const bind = (container, host, rw = true) => ({ Type: 'bind', Source: host, Destination: container, RW: rw });
const oldBody = { Config: { Labels: { 'com.docker.compose.project': 'nginx-rproxy', 'com.docker.compose.project.working_dir': '/containers/nginx-rproxy' } },
  Mounts: [bind('/nginx/logs', '/containers/nginx-rproxy/logs', false), bind('/nginx/certs', '/containers/nginx-rproxy/certs', false),
    bind('/nginx/goaccess', '/containers/nginx-rproxy/goaccess'), bind('/geoip', '/containers/nginx-rproxy/geoip_data', false),
    bind('/config', '/containers/nginx-rproxy/nginx-dashboard/config'), { Type: 'volume', Name: 'git-work', Source: '/var/lib/docker/volumes/x/_data', Destination: '/git-work', RW: true }] };
const newBody = { Config: { Labels: { 'com.docker.compose.project.working_dir': '/containers/ngx-ops' } },
  Mounts: [bind('/nginx/logs', '/containers/ngx-ops/nginx/logs', false), bind('/certificats', '/containers/ngx-ops/certificats'),
    bind('/nginx/goaccess', '/containers/ngx-ops/config/nginx-dashboard/goaccess'), bind('/geoip', '/containers/ngx-ops/geoip_data'),
    bind('/config', '/containers/ngx-ops/config/nginx-dashboard/config')] };
const env = { DIR_LOGS: '/nginx/logs', DIR_CERTS: '/nginx/certs', DIR_GOACCESS: '/nginx/goaccess', DIR_GEOIP: '/geoip', DIR_SSL: '/nginx/ssl', DIR_BACKUPS: '/nginx/backups', CONFIG_DIR: '/config' };

check('normalize : bind -> chemin hote, volume nomme sans chemin, projet compose', () => {
  const n = HP.normalize(oldBody);
  assert.strictEqual(n.project.dir, '/containers/nginx-rproxy');
  assert.strictEqual(n.mounts.find((m) => m.container === '/git-work').host, null);
  assert.strictEqual(n.mounts.find((m) => m.container === '/git-work').name, 'git-work');
  assert.strictEqual(n.mounts.find((m) => m.container === '/nginx/logs').rw, false);
});
check('ancien compose : logs / geoip / goaccess retrouves', () => {
  const s = HP.suggestions(HP.normalize(oldBody).mounts, env);
  assert.strictEqual(s.logs.host, '/containers/nginx-rproxy/logs');
  assert.strictEqual(s.geoip.host, '/containers/nginx-rproxy/geoip_data');
  assert.strictEqual(s.goaccess.host, '/containers/nginx-rproxy/goaccess');
  assert.strictEqual(s.webroot.host, '/containers/nginx-rproxy/webroot'); assert.strictEqual(s.webroot.derived, true);
});
check('nouveau compose : certs via /certificats/certbot, webroot deduit du voisin de logs', () => {
  const s = HP.suggestions(HP.normalize(newBody).mounts, env);
  assert.strictEqual(s.logs.host, '/containers/ngx-ops/nginx/logs');
  assert.strictEqual(s.certs.host, '/containers/ngx-ops/certificats/certbot');
  assert.strictEqual(s.webroot.host, '/containers/ngx-ops/nginx/webroot');
  assert.strictEqual(s.config.host, '/containers/ngx-ops/config/nginx-dashboard/config');
});
check('hostFor : sous-dossier, montage le plus specifique, non monte -> null', () => {
  const m = HP.normalize(newBody).mounts;
  assert.strictEqual(HP.hostFor(m, '/nginx/logs/site.log'), '/containers/ngx-ops/nginx/logs/site.log');
  assert.strictEqual(HP.hostFor(m, '/nginx/logsX'), null);
  assert.strictEqual(HP.hostFor(m, '/ailleurs'), null);
  assert.strictEqual(HP.hostFor([{ container: '/a', host: '/h/a' }, { container: '/a/b', host: '/h/b' }], '/a/b/c'), '/h/b/c');
});
check('sans montage : aucune suggestion inventee', () => {
  assert.deepStrictEqual(HP.suggestions([], env), {});
  const n = HP.normalize(null); assert.deepStrictEqual(n.mounts, []); assert.strictEqual(n.project, null);
});

console.log('\n' + (fail ? fail + ' FAIL' : 'tous les tests passent'));
process.exit(fail ? 1 : 0);
