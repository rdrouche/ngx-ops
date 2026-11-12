'use strict';
const assert = require('assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
const A = require('../lib/asset-version');
let pass = 0, fail = 0;
function check(n, f) { try { f(); pass++; console.log('  PASS  ' + n); } catch (e) { fail++; console.log('  FAIL  ' + n + '\n  ' + e.message); } }

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'av-'));
fs.writeFileSync(path.join(tmp, 'a.js'), 'x');
const v1 = A.computeVersion([tmp]);
check('empreinte stable, 10 caracteres hexa', () => { assert.match(v1, /^[a-f0-9]{10}$/); assert.strictEqual(A.computeVersion([tmp]), v1); });
fs.writeFileSync(path.join(tmp, 'a.js'), 'xyz');
check('l empreinte change quand un fichier change', () => assert.notStrictEqual(A.computeVersion([tmp]), v1));
check('dossier absent : pas d erreur', () => assert.match(A.computeVersion([path.join(tmp, 'nope')]), /^[a-f0-9]{10}$/));
check('URLs /assets versionnees, autres liens intacts, deja versionnees ignorees', () => {
  const h = '<link href="/assets/style.css" rel="stylesheet"><script src="/assets/js/app.js"></script><img src="/assets/logo.svg"><a href="/other.js"></a><script src="/assets/x.js?v=1"></script>';
  const o = A.versionAssetUrls(h, 'abcdef1234');
  assert.ok(o.includes('/assets/style.css?v=abcdef1234"') && o.includes('/assets/js/app.js?v=abcdef1234"') && o.includes('/assets/logo.svg?v=abcdef1234"'));
  assert.ok(o.includes('href="/other.js"') && o.includes('/assets/x.js?v=1"'));
});
check('version invalide : HTML inchange (pas d injection)', () => { const h = '<script src="/assets/a.js"></script>'; assert.strictEqual(A.versionAssetUrls(h, '"><x'), h); });
check('ETag et If-None-Match', () => {
  const e = A.etagOf(Buffer.from('abc'));
  assert.ok(A.notModified(e, e) && A.notModified('W/' + e, e) && A.notModified('"x", ' + e, e));
  assert.ok(!A.notModified('"autre"', e) && !A.notModified(undefined, e));
  assert.notStrictEqual(A.etagOf(Buffer.from('abd')), e);
});
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
