'use strict';
/** v12.71.1 — AGENT_DEFAULT_IMAGE (ARG/ENV du Dockerfile) pris en compte par le kit de deploiement des agents. */
const assert = require('assert');
const fs = require('fs'), os = require('os'), path = require('path');
const { execFileSync } = require('child_process');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adi-'));
fs.writeFileSync(path.join(dir, 'users.yml'), 'users: []\n');
const probe = (env) => JSON.parse(execFileSync('node', ['-e', `
  const c = require('./lib/config'); const B = require('./lib/agent-bundle');
  const v = B.validateOptions({ name: 'agent-1', dashboardUrl: 'https://dash.example.org' });
  const compose = v.ok ? B.buildCompose(v.value) : '';
  const envf = v.ok ? B.buildEnv(v.value, 'tok') : '';
  console.log(JSON.stringify({ cfg: c.AGENT_DEFAULT_IMAGE, def: B.DEFAULTS.image, ok: v.ok, err: v.error, image: v.ok && v.value.image, tag: v.ok && v.value.tag, tagCfg: c.AGENT_DEFAULT_TAG,
    compose: compose.split('\\n').find(l => l.includes('image:')), env: envf.split('\\n').find(l => l.startsWith('AGENT_IMAGE=')) }));
`], { cwd: path.join(__dirname, '..'), env: { PATH: process.env.PATH, USERS_FILE: path.join(dir, 'users.yml'), ...env } }).toString().trim().split('\n').pop());

const FALLBACK = 'forge.rdr-it.com/dockerfiles/nginx-control-agent';
console.log('\nAGENT_DEFAULT_IMAGE');
check('sans variable : defaut historique inchange', () => { const r = probe({}); assert.strictEqual(r.cfg, FALLBACK); assert.strictEqual(r.image, FALLBACK); });
check('variable vide (compose ${AGENT_DEFAULT_IMAGE:-}) : defaut', () => assert.strictEqual(probe({ AGENT_DEFAULT_IMAGE: '' }).cfg, FALLBACK));
check('image privee : reprise dans les options, le .env et le compose.yml', () => {
  const r = probe({ AGENT_DEFAULT_IMAGE: 'registry.example.com/team/ngx-agent' });
  assert.strictEqual(r.cfg, 'registry.example.com/team/ngx-agent'); assert.strictEqual(r.def, r.cfg); assert.strictEqual(r.image, r.cfg);
  assert.ok(r.compose.includes('registry.example.com/team/ngx-agent'), r.compose);
  assert.strictEqual(r.env, 'AGENT_IMAGE=registry.example.com/team/ngx-agent');
});
check('nom:tag accepté : le tag devient le tag par défaut du kit (avant : rejeté en silence)', () => {
  const r = probe({ AGENT_DEFAULT_IMAGE: 'forge.example.fr/dockerfiles/agent:1.2' });
  assert.strictEqual(r.cfg, 'forge.example.fr/dockerfiles/agent'); assert.strictEqual(r.tag, '1.2'); assert.strictEqual(r.tagCfg, '1.2');
  assert.strictEqual(probe({ AGENT_DEFAULT_IMAGE: 'forge.example.fr/dockerfiles/agent' }).tag, 'latest');
});
check('valeur invalide (espaces, guillemets, $) : repli sur le defaut, jamais ecrite dans un .env', () => {
  for (const bad of ['a b', 'x"y', 'img$(id)', 'img:tag with space', 'img:ta$g']) assert.strictEqual(probe({ AGENT_DEFAULT_IMAGE: bad }).cfg, FALLBACK, bad);
});
fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
