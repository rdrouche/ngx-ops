'use strict';
// #93 : lien « fiche IP » vers Intelligence — réglage par navigateur, IP validée, jamais d'injection.
const assert = require('assert');
const fs = require('fs'); const path = require('path'); const vm = require('vm');
let pass = 0, fail = 0;
function check(n, f) { try { f(); pass++; console.log('  PASS  ' + n); } catch (e) { fail++; console.log('  FAIL  ' + n + '\n  ' + e.message); } }

function load(stored) {
  const store = { ngx_ip_links: stored };
  const mk = () => ({ attrs: {}, listeners: {}, set href(v) { this.attrs.href = v; }, get href() { return this.attrs.href; }, addEventListener() {} });
  const win = { location: { reload() {} } };
  const ctx = { window: win, localStorage: { getItem: (k) => store[k] ?? null, setItem: (k, v) => { store[k] = v; } }, location: win.location,
    document: { createElement: mk, addEventListener() {}, getElementById: () => null }, encodeURIComponent, t: (k) => k };
  ctx.window = Object.assign(win, ctx); vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/assets/js/ip-link.js'), 'utf8'), ctx);
  return { ip: win.NgxIp, store };
}

const off = load(undefined).ip;
check('désactivé par défaut : aucune pastille', () => { assert.strictEqual(off.enabled(), false); assert.strictEqual(off.badge('203.0.113.9'), null); assert.strictEqual(off.badgeHtml('203.0.113.9'), ''); });
const on = load('intel').ip;
check('activé : lien Intelligence, nouvel onglet, noopener', () => {
  const a = on.badge('203.0.113.9');
  assert.strictEqual(a.attrs.href, 'https://intelligence.ngx-ops.net/ip/203.0.113.9');
  assert.strictEqual(a.target, '_blank'); assert.ok(/noopener/.test(a.rel) && /noreferrer/.test(a.rel));
  assert.ok(on.badgeHtml('2001:db8::1').includes('/ip/2001%3Adb8%3A%3A1'));
});
check('seules les vraies IP produisent un lien (pas de réseau, pseudonyme, ni injection)', () => {
  for (const bad of ['', null, undefined, '203.0.113.0/24', 'a'.repeat(32), '<script>', '1.2.3.4"><img>', '../x', 'abc', '1.2.3']) {
    assert.strictEqual(on.badge(bad), null, String(bad)); assert.strictEqual(on.badgeHtml(bad), '', String(bad));
  }
});
check('toggle : bascule le réglage mémorisé', () => {
  const { ip, store } = load(undefined); ip.toggle(); assert.strictEqual(store.ngx_ip_links, 'intel'); ip.toggle(); assert.strictEqual(store.ngx_ip_links, 'plain');
});
console.log(`\n${pass} pass, ${fail} fail`); process.exit(fail ? 1 : 0);
