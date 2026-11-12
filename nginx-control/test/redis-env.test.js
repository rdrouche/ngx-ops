'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('redis-env : rien sans REDIS_URL, valeurs propres sinon', () => {
  const save = { ...process.env };
  try {
    delete process.env.REDIS_URL; delete process.env.REDIS_PASSWORD; delete process.env.REDIS_PREFIX;
    const e = require('../lib/redis-env');
    assert.deepEqual(e.analyzerEnv(), []);
    assert.deepEqual(e.challengeEnv(), []);
    process.env.REDIS_URL = 'redis://redis:6379/0';
    process.env.REDIS_PASSWORD = 'p\nINJECT=1';
    process.env.REDIS_PREFIX = 'a b;c';
    assert.deepEqual(e.analyzerEnv(), ['REDIS_URL=redis://redis:6379/0', 'REDIS_PASSWORD=pINJECT=1', 'REDIS_PREFIX=abc']);
    assert.deepEqual(e.challengeEnv(), ['NC_REDIS_URL=redis://redis:6379/0', 'NC_REDIS_PASSWORD=pINJECT=1', 'NC_REDIS_PREFIX=abc']);
    process.env.REDIS_URL = 'http://nope';
    assert.deepEqual(e.analyzerEnv(), []);
  } finally { for (const k of ['REDIS_URL', 'REDIS_PASSWORD', 'REDIS_PREFIX']) { if (save[k] === undefined) delete process.env[k]; else process.env[k] = save[k]; } }
});
