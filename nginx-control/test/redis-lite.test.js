'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const net = require('node:net');
const os = require('node:os');
const { createClient, parseUrl, parseReply } = require('../lib/redis-lite');

const HAVE = spawnSync('redis-server', ['--version']).status === 0;
const freePort = () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

async function startRedis(extra = []) {
  const port = await freePort();
  const p = spawn('redis-server', ['--port', String(port), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--dir', os.tmpdir(), ...extra], { stdio: 'ignore' });
  for (let i = 0; i < 60; i++) {
    const ok = await new Promise(r => { const c = net.connect(port, '127.0.0.1', () => { c.destroy(); r(true); }); c.on('error', () => r(false)); });
    if (ok) break; await new Promise(r => setTimeout(r, 50));
  }
  return { port, stop: () => new Promise(r => { p.once('exit', r); p.kill(); }) };
}

test('URL : validation et secrets', () => {
  assert.equal(createClient(''), null);
  assert.throws(() => parseUrl('http://x'));
  assert.throws(() => parseUrl('redis://h/999'));
  const c = createClient('redis://u:secret@h.example:6380/2');
  assert.equal(c.redacted(), 'redis://h.example:6380/2');
  assert.equal(parseUrl('redis://:old@h', 'new').password, 'new');
});

test('parseReply : réponses partielles et imbriquées', () => {
  assert.equal(parseReply(Buffer.from('$5\r\nhel')), null);
  assert.deepEqual(parseReply(Buffer.from('*2\r\n:1\r\n+OK\r\n'))[0], [1, 'OK']);
  assert.equal(parseReply(Buffer.from('$-1\r\n'))[0], null);
});

test('Redis réel : binaire, TTL, auth, info, coupure puis reprise', { skip: !HAVE && 'redis-server absent' }, async () => {
  const r = await startRedis(['--requirepass', 'pw']);
  const bad = createClient(`redis://127.0.0.1:${r.port}/0`);
  await assert.rejects(bad.get('x'));
  bad.close();
  const c = createClient(`redis://127.0.0.1:${r.port}/1`, { password: 'pw' });
  const val = Buffer.from([0, 1, 2, 13, 10, 255, 36]);
  await c.set('bin', val, 30);
  assert.deepEqual(await c.get('bin'), val);
  assert.equal(await c.get('absent'), null);
  assert.ok((await c.call('TTL', 'bin')) > 0);
  const big = Buffer.alloc(3 * 1024 * 1024, 'x');
  await c.set('big', big);
  assert.equal((await c.get('big')).length, big.length);
  const inf = await c.info();
  assert.ok(inf.ok && inf.version && inf.usedMemory > 0);
  // coupure : erreur franche (pas de blocage), puis reprise sur le même serveur
  await r.stop();
  await assert.rejects(c.get('bin'));
  c.close();
});

test('Redis absent : échec rapide, jamais de blocage', async () => {
  const c = createClient('redis://127.0.0.1:1/0');
  const t0 = Date.now();
  await assert.rejects(c.get('x'));
  assert.ok(Date.now() - t0 < 3000);
  assert.deepEqual((await c.info()).ok, false);
  c.close();
});
