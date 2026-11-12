'use strict';
// #80 : détection de l'ancienne image Node de l'analyseur (avertissement, jamais de blocage).
const test = require('node:test');
const assert = require('node:assert/strict');
const { imageBase, isLegacyNodeImage } = require('../lib/analyzer-image');

test('imageBase : sans registre, tag ni empreinte', () => {
  assert.equal(imageBase('forge.rdr-it.com/dockerfiles/nginx-analyzer:latest'), 'nginx-analyzer');
  assert.equal(imageBase('registry.example.com:5000/a/b/Analyzer-Agent-Go:1.2.3'), 'analyzer-agent-go');
  assert.equal(imageBase('nginx-analyzer@sha256:abcdef'), 'nginx-analyzer');
  assert.equal(imageBase(''), '');
  assert.equal(imageBase(undefined), '');
});

test('images Node historiques détectées', () => {
  assert.equal(isLegacyNodeImage('forge.rdr-it.com/dockerfiles/nginx-analyzer:latest'), true);
  assert.equal(isLegacyNodeImage('forge.rdr-it.com/ngx-ops/ngx-ops/analyzer-agent:1.0.0'), true);
  assert.equal(isLegacyNodeImage('nginx-analyzer'), true);
  assert.equal(isLegacyNodeImage('registry.example.com/mon-fork/nginx-analyzer:latest'), true);
});

test('images Go et inconnues : pas d\'avertissement', () => {
  assert.equal(isLegacyNodeImage('forge.rdr-it.com/ngx-ops/ngx-ops/analyzer-agent-go:latest'), false);
  assert.equal(isLegacyNodeImage('forge.rdr-it.com/x/nginx-analyzer-go:12.52.0'), false);
  assert.equal(isLegacyNodeImage('registry.example.com/maison/mon-analyseur:1'), false);
  assert.equal(isLegacyNodeImage('nginx-analyzer.example.com/x/y:1'), false);
  assert.equal(isLegacyNodeImage(null), false);
});
