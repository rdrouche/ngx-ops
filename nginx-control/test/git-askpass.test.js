'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const git = require('../lib/git');
const script = require('path').join(__dirname, '..', 'tools', 'git-askpass.sh');

const ask = (prompt, env) => spawnSync('sh', [script, prompt], { env: { PATH: process.env.PATH, ...env } });

test('gitEnv : jeton HTTPS → GIT_ASKPASS limité à l hôte du dépôt', () => {
  const env = git.gitEnv({ repoUrl: 'https://forge.example.fr/a/b.git', token: 'tok123' });
  assert.equal(env.NGX_GIT_HOST, 'forge.example.fr');
  assert.equal(env.NGX_GIT_TOKEN, 'tok123');
  assert.match(env.GIT_ASKPASS, /git-askpass\.sh$/);
  assert.equal(env.GIT_TERMINAL_PROMPT, '0');
  assert.equal(git.gitEnv({ repoUrl: 'https://forge.example.fr/a/b.git', token: '' }).GIT_ASKPASS, process.env.GIT_ASKPASS);
  assert.equal(git.gitEnv({ repoUrl: 'git@forge.example.fr:a/b.git', token: 'x' }).NGX_GIT_TOKEN, undefined);
});

test('git-askpass.sh : jeton pour l hôte configuré, rien pour un autre domaine', () => {
  const env = { NGX_GIT_HOST: 'forge.example.fr', NGX_GIT_TOKEN: 'tok123' };
  assert.equal(ask("Username for 'https://forge.example.fr': ", env).stdout.toString(), 'tok123\n');
  assert.equal(ask("Password for 'https://tok123@forge.example.fr': ", env).stdout.toString(), '\n');
  const other = ask("Username for 'https://evil.example.org': ", env);
  assert.notEqual(other.status, 0); assert.equal(other.stdout.toString(), '');
});
