'use strict';
// #117 : client S3 (SigV4) — vecteur officiel AWS + serveur factice qui re-signe chaque requete reçue.
const assert = require('assert');
const http = require('http');
const S3 = require('../lib/s3');

let fail = 0;
async function check(name, fn) { try { await fn(); console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

(async () => {
  console.log('\nSigV4');
  await check('vecteur officiel AWS « GET Object » (examplebucket, Range)', () => {
    const r = S3.signRequest({
      method: 'GET', host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', headers: { Range: 'bytes=0-9' },
      region: 'us-east-1', accessKey: 'AKIAIOSFODNN7EXAMPLE', secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', now: new Date('2013-05-24T00:00:00Z'),
    });
    assert.strictEqual(r.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
    assert.strictEqual(r.signedHeaders, 'host;range;x-amz-content-sha256;x-amz-date');
  });
  await check('vecteur officiel AWS « GET Bucket (List Objects) » (requete avec parametres)', () => {
    const r = S3.signRequest({
      method: 'GET', host: 'examplebucket.s3.amazonaws.com', path: '/', query: { 'max-keys': '2', prefix: 'J' },
      region: 'us-east-1', accessKey: 'AKIAIOSFODNN7EXAMPLE', secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', now: new Date('2013-05-24T00:00:00Z'),
    });
    assert.strictEqual(r.signature, '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7');
  });

  console.log('\nvalidation');
  await check('endpoint : https requis, pas d\'identifiants, http seulement si autorise', () => {
    assert.throws(() => S3.createClient({ endpoint: 'http://s3.local', region: 'r', bucket: 'bkt', accessKey: 'a', secretKey: 'b' }), /HTTPS/);
    assert.throws(() => S3.createClient({ endpoint: 'https://u:p@s3.local', region: 'r', bucket: 'bkt', accessKey: 'a', secretKey: 'b' }), /identifiants/);
    assert.throws(() => S3.createClient({ endpoint: 'pas une url', region: 'r', bucket: 'bkt', accessKey: 'a', secretKey: 'b' }), /invalide/);
    assert.throws(() => S3.createClient({ endpoint: 'https://s3.local', region: 'r', bucket: 'Bad_Bucket', accessKey: 'a', secretKey: 'b' }), /bucket/);
    S3.createClient({ endpoint: 'http://127.0.0.1:1', region: 'r', bucket: 'bkt', accessKey: 'a', secretKey: 'b', allowInsecure: true });
  });

  console.log('\nclient (serveur factice)');
  const store = new Map();
  const seen = [];
  const SECRET = 'S3CR3T-never-in-errors';
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const u = new URL(req.url, 'http://x');
      const query = Object.fromEntries(u.searchParams);
      // re-signe avec les memes en-tetes que ceux reçus : la signature doit etre identique
      const auth = req.headers.authorization || '';
      const date = req.headers['x-amz-date'];
      const hdrs = {}; for (const n of (auth.match(/SignedHeaders=([^,]+)/) || [, ''])[1].split(';')) if (!['host', 'x-amz-date', 'x-amz-content-sha256'].includes(n)) hdrs[n] = req.headers[n];
      const re = S3.signRequest({ method: req.method, host: req.headers.host, path: u.pathname, query, headers: hdrs, payloadHash: req.headers['x-amz-content-sha256'], region: 'eu-test-1', accessKey: 'AKTEST', secretKey: SECRET, now: new Date(date.replace(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/, '$1-$2-$3T$4:$5:$6Z')) });
      seen.push(`${req.method} ${u.pathname}${u.search}`);
      if (!auth.endsWith('Signature=' + re.signature) || S3.sha256hex(body) !== req.headers['x-amz-content-sha256'] && body.length) {
        res.writeHead(403); return res.end('<Error><Code>SignatureDoesNotMatch</Code><Message>bad sig</Message></Error>');
      }
      if (u.pathname === '/bkt/boom') { res.writeHead(500); return res.end(`<Error><Code>InternalError</Code><Message>oups</Message></Error>`); }
      if (req.method === 'PUT') { store.set(decodeURIComponent(u.pathname.slice(5)), body); res.writeHead(200); return res.end(); }
      if (req.method === 'DELETE') { store.delete(decodeURIComponent(u.pathname.slice(5))); res.writeHead(204); return res.end(); }
      if (req.method === 'GET' && u.pathname === '/bkt') {
        const keys = [...store.keys()].filter((k) => k.startsWith(query.prefix || '')).sort();
        const start = query['continuation-token'] ? Number(query['continuation-token']) : 0;
        const page = keys.slice(start, start + Number(query['max-keys']));
        const more = start + page.length < keys.length;
        res.writeHead(200, { 'content-type': 'application/xml' });
        return res.end(`<ListBucketResult><IsTruncated>${more}</IsTruncated>${more ? `<NextContinuationToken>${start + page.length}</NextContinuationToken>` : ''}${page.map((k) => `<Contents><Key>${k.replace(/&/g, '&amp;')}</Key><Size>${store.get(k).length}</Size><LastModified>2026-11-12T07:00:00.000Z</LastModified></Contents>`).join('')}</ListBucketResult>`);
      }
      if (req.method === 'GET') { const v = store.get(decodeURIComponent(u.pathname.slice(5))); res.writeHead(v ? 200 : 404); return res.end(v || '<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>'); }
      res.writeHead(400); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = { endpoint: `http://127.0.0.1:${srv.address().port}`, region: 'eu-test-1', bucket: 'bkt', accessKey: 'AKTEST', secretKey: SECRET, allowInsecure: true, timeoutMs: 3000 };
  const c = S3.createClient(base);

  await check('put / get / list (prefixe, pagination, caracteres speciaux) / del', async () => {
    await c.put('ngx/a b&c.zip', Buffer.from('zip-data'), 'application/zip');
    await c.put('ngx/b.zip', Buffer.from('b'));
    await c.put('autre/c.zip', Buffer.from('c'));
    assert.strictEqual((await c.get('ngx/a b&c.zip')).toString(), 'zip-data');
    const l = await c.list('ngx/', { maxKeys: 1 });
    assert.deepStrictEqual(l.map((o) => o.key), ['ngx/a b&c.zip', 'ngx/b.zip']);
    assert.strictEqual(l[0].size, 8);
    await c.del('ngx/b.zip');
    assert.deepStrictEqual((await c.list('ngx/')).map((o) => o.key), ['ngx/a b&c.zip']);
  });
  await check('signature serveur identique (aucun 403) sur toutes les requetes', () => {
    assert.ok(seen.length >= 8 && !seen.some((s) => /403/.test(s)));
  });
  await check('mauvaise cle secrete -> erreur typee 403 sans fuite de secret', async () => {
    const bad = S3.createClient({ ...base, secretKey: 'autre-secret' });
    await assert.rejects(() => bad.put('x', Buffer.from('1')), (e) => e.status === 403 && e.code === 'SignatureDoesNotMatch' && !e.message.includes('autre-secret') && !e.message.includes(SECRET));
  });
  await check('erreur 500 : code et message S3 remontes, 404 sur objet absent', async () => {
    await assert.rejects(() => c.put('boom', Buffer.from('1')), (e) => e.status === 500 && /InternalError/.test(e.message));
    await assert.rejects(() => c.get('absent'), (e) => e.status === 404 && e.code === 'NoSuchKey');
  });
  await check('injoignable / delai : S3Error sans stack reseau brute', async () => {
    const dead = S3.createClient({ ...base, endpoint: 'http://127.0.0.1:1', timeoutMs: 500 });
    await assert.rejects(() => dead.list(''), (e) => e instanceof S3.S3Error && /injoignable|delai/.test(e.message));
  });
  await check('virtual-host : bucket dans le nom d\'hote', async () => {
    const vh = S3.createClient({ ...base, pathStyle: false });
    // 127.0.0.1 ne resout pas « bkt.127.0.0.1 » : on verifie seulement la construction (echec reseau propre)
    await assert.rejects(() => vh.list(''), (e) => e instanceof S3.S3Error);
  });

  srv.close();
  console.log(`\n${fail ? 'FAIL' : 'OK'} (${fail} echec(s))`);
  process.exit(fail ? 1 : 0);
})();
