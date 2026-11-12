'use strict';
/** Réception d'un flux vers un fichier temporaire : taille bornée, SHA-256 calculé au fil de l'eau, jamais en mémoire. */
const fs = require('node:fs');
const { Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { createHash } = require('node:crypto');

class TooLarge extends Error { constructor() { super('too_large'); this.code = 'too_large'; } }

async function receiveToFile(readable, tmp, { maxBytes }) {
  const hash = createHash('sha256');
  let size = 0;
  const meter = new Transform({
    transform(chunk, _enc, cb) {
      size += chunk.length;
      if (size > maxBytes) return cb(new TooLarge());
      hash.update(chunk); cb(null, chunk);
    },
  });
  try {
    await pipeline(readable, meter, fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 }));
  } catch (e) {
    await fs.promises.rm(tmp, { force: true });
    throw e;
  }
  return { sha256: hash.digest('hex'), size };
}

module.exports = { receiveToFile, TooLarge };
