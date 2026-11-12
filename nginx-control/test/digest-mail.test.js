'use strict';
/** Digest v12.75.0 : contenu, HTML du mail, multipart SMTP, plus de « ?? ». */
const assert = require('assert'), net = require('net');
const digest = require('../lib/digest');
const notify = require('../lib/notify');
let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const base = () => ({ generatedAt: Date.now(), periodHours: 24,
  traffic: { totalRequests: 1000, totalBytes: 5e6, totalErrors: 150, byVhost: [{ vhost: '<b>a.com</b>', requests: 1000, bytes: 5e6, errors: 150 }] },
  previous: { totalRequests: 400, totalBytes: 1, totalErrors: 1 }, bots: { total: 100, human: 30, bots: 70 },
  topCountries: [{ country: 'FR', requests: 800 }, { country: '??', requests: 20 }],
  crowdsec: { configured: false }, waf: { configured: true, blockedCount: 12 }, blocklists: { enable: false },
  certs: { expiringSoon: [{ name: 'x.com', daysLeft: 5 }] }, errors: [] });

(async () => {
  await check('plus de « ?? » : pays nommé / non résolu', () => {
    assert.strictEqual(digest.countryName('FR'), 'France');
    assert.strictEqual(digest.countryName('??'), 'Non résolu');
    assert.strictEqual(digest.countryName(null), 'Non résolu');
    const t = digest.formatDigestText(base()); assert.ok(!t.includes('??')); assert.ok(t.includes('France'));
  });
  await check('points d\'attention : erreurs, hausse, robots, certificat', () => {
    const h = digest.highlights(base()).map(x => x.level + ':' + x.text).join('|');
    assert.ok(/crit:Taux d'erreurs élevé/.test(h)); assert.ok(/forte hausse/.test(h)); assert.ok(/robots/.test(h)); assert.ok(/crit:Certificat x\.com/.test(h));
  });
  await check('rien à signaler quand tout va bien', () => {
    const d = base(); d.traffic.totalErrors = 0; d.previous = null; d.bots = { total: 10, human: 9, bots: 1 }; d.certs.expiringSoon = [];
    assert.ok(digest.highlights(d).some(x => /Rien d'anormal/.test(x.text)));
  });
  await check('HTML : échappe les valeurs, tables inline, pas de script', () => {
    const h = digest.formatDigestHtml(base());
    assert.ok(h.includes('&lt;b&gt;a.com&lt;/b&gt;')); assert.ok(!h.includes('<b>a.com')); assert.ok(!/<script/i.test(h));
    assert.ok(h.includes('France')); assert.ok(h.includes('Non résolu'));
  });
  await check('HTML : section sans données (analyseur KO) ne plante pas', () => {
    const d = base(); d.traffic = null; d.bots = null; d.topCountries = []; d.waf = { configured: false }; d.certs.expiringSoon = [];
    assert.ok(digest.formatDigestHtml(d).includes('Analyseur injoignable'));
    assert.ok(digest.formatDigestText(d).includes('analyseur injoignable'));
  });
  await check('SMTP : mail multipart/alternative (texte + HTML) bien formé', async () => {
    let data = '';
    const srv = net.createServer((s) => {
      let state = 'cmd';
      s.write('220 test\r\n');
      s.on('data', (b) => {
        const t = b.toString();
        if (state === 'data') { data += t; if (data.endsWith('\r\n.\r\n')) { state = 'cmd'; s.write('250 ok\r\n'); } return; }
        for (const l of t.split('\r\n').filter(Boolean)) {
          if (/^EHLO/.test(l)) s.write('250 hi\r\n');
          else if (/^(MAIL|RCPT)/.test(l)) s.write('250 ok\r\n');
          else if (/^DATA/.test(l)) { state = 'data'; s.write('354 go\r\n'); }
          else if (/^QUIT/.test(l)) { s.write('221 bye\r\n'); s.end(); }
        }
      });
    });
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    const port = srv.address().port;
    const res = await notify.sendMail(['a@b.c'], 'Résumé é', 'texte brut', { enable: true, host: '127.0.0.1', port, security: 'none', from: 'x@y.z' }, { html: '<p>Bonjour é</p>\n.point seul' });
    srv.close();
    assert.ok(res.ok, JSON.stringify(res));
    assert.ok(/Content-Type: multipart\/alternative; boundary=/.test(data));
    const parts = [...data.matchAll(/Content-Transfer-Encoding: base64\r\n\r\n([A-Za-z0-9+\/=\r\n]+?)\r\n--/g)].map(m => Buffer.from(m[1].replace(/\r\n/g, ''), 'base64').toString('utf8'));
    assert.strictEqual(parts[0], 'texte brut'); assert.ok(parts[1].includes('Bonjour é') && parts[1].includes('.point seul'));
  });
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
