'use strict';
/**
 * Mini-parseur YAML (sous-ensemble) — suffisant pour config/hub.yml, sans dépendance.
 * Supporte : mappings imbriqués (indentation par espaces), listes "- x", listes inline [a, b],
 * scalaires (chaîne, nombre, booléen, null), chaînes quotées, commentaires "#".
 * Mappings inline { a: 1, b: [x, y] } (imbriquables). Ne supporte PAS : ancres, tags, multi-lignes (| >), clés complexes.
 */

function stripComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { if (ch === q && line[i - 1] !== '\\') q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

function scalar(raw) {
  const s = raw.trim();
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) return Number.parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return Number.parseFloat(s);
  if ((s.startsWith('"') && s.endsWith('"') && s.length >= 2)) {
    return s.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) return s.slice(1, -1).replace(/''/g, "'");
  if (s.startsWith('{') && s.endsWith('}')) {
    const inner = s.slice(1, -1).trim();
    const obj = {};
    if (!inner) return obj;
    for (const part of splitInline(inner)) {
      const m = part.trim().match(/^([A-Za-z0-9_.\-"']+?)\s*:(?:\s+([\s\S]*))?$/);
      if (!m) throw new Error('YAML : mapping inline invalide « ' + part.trim().slice(0, 40) + ' »');
      const key = m[1].replace(/^["']|["']$/g, '');
      const v = scalar(m[2] === undefined ? '' : m[2]);
      if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') obj[key] = v;
    }
    return obj;
  }
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitInline(inner).map(scalar);
  }
  return s;
}

function splitInline(s) {
  const out = []; let cur = ''; let q = null; let depth = 0;
  for (const ch of s) {
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

function parseYaml(text) {
  const lines = [];
  for (const rawLine of String(text).replace(/\r\n?/g, '\n').split('\n')) {
    const noComment = stripComment(rawLine);
    if (!noComment.trim()) continue;
    if (/\t/.test(noComment.match(/^\s*/)[0])) throw new Error('YAML : tabulation interdite en indentation');
    lines.push({ indent: noComment.match(/^ */)[0].length, text: noComment.trim() });
  }
  let pos = 0;

  function parseBlock(indent) {
    if (pos >= lines.length) return null;
    if (lines[pos].text.startsWith('- ') || lines[pos].text === '-') return parseList(indent);
    return parseMap(indent);
  }

  function parseList(indent) {
    const arr = [];
    while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text.startsWith('- ') || lines[pos].text === '-')) {
      const rest = lines[pos].text.slice(1).trim();
      pos++;
      if (rest === '') {
        arr.push(pos < lines.length && lines[pos].indent > indent ? parseBlock(lines[pos].indent) : null);
      } else if (/^[A-Za-z0-9_.-]+:(\s|$)/.test(rest) && !rest.startsWith('"')) {
        // élément mapping "- cle: valeur" : on réinjecte comme ligne indentée
        lines.splice(pos, 0, { indent: indent + 2, text: rest });
        arr.push(parseMap(indent + 2));
      } else {
        arr.push(scalar(rest));
      }
    }
    return arr;
  }

  function parseMap(indent) {
    const obj = {};
    while (pos < lines.length && lines[pos].indent === indent) {
      const { text } = lines[pos];
      if (text.startsWith('- ')) break;
      const m = text.match(/^([A-Za-z0-9_.\-"']+?)\s*:(?:\s+(.*))?$/);
      if (!m) throw new Error('YAML : ligne invalide « ' + text.slice(0, 40) + ' »');
      const key = m[1].replace(/^["']|["']$/g, '');
      pos++;
      let value;
      if (m[2] === undefined || m[2] === '') {
        if (pos < lines.length && lines[pos].indent > indent) value = parseBlock(lines[pos].indent);
        else if (pos < lines.length && lines[pos].indent === indent && lines[pos].text.startsWith('- ')) value = parseList(indent);
        else value = null;
      } else {
        value = scalar(m[2]);
      }
      // clés dangereuses : valeur consommée puis ignorée (pollution de prototype)
      if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') obj[key] = value;
    }
    return obj;
  }

  if (!lines.length) return {};
  const result = parseBlock(lines[0].indent);
  if (pos < lines.length) throw new Error('YAML : indentation incohérente près de « ' + lines[pos].text.slice(0, 40) + ' »');
  return result;
}

module.exports = { parseYaml };
