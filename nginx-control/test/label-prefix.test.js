'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('../lib/docker-autoconfig');

test('ngx-ops.* ≡ nginx-control.* (migration) ; ngx-ops. l emporte en cas de doublon', () => {
  const a = d.parseContainerLabels({ 'nginx-control.enable': 'true', 'nginx-control.vhost.server_name': 'a.example.com', 'nginx-control.network': 'n' });
  const b = d.parseContainerLabels({ 'ngx-ops.enable': 'true', 'ngx-ops.vhost.server_name': 'a.example.com', 'ngx-ops.network': 'n' });
  assert.deepEqual(b, a);
  const mixed = d.parseContainerLabels({ 'nginx-control.enable': 'true', 'ngx-ops.vhost.server_name': 'new.example.com', 'nginx-control.vhost.server_name': 'old.example.com' });
  assert.equal(mixed.serverNameRaw, 'new.example.com');
  assert.equal(d.parseContainerLabels({ 'ngx-ops.enable': 'false' }), null);
  assert.equal(d.parseContainerLabels({}), null);
});
