'use strict';
/**
 * redis-lite — client Redis minimal (RESP2), sans dépendance.
 *
 * Redis est OPTIONNEL dans NGX Ops : ce module ne sert qu'à partager/conserver
 * des états volatils (instantanés, caches, ensembles). Principes :
 *   - URL vide  → `createClient('')` renvoie null : l'appelant garde son comportement actuel ;
 *   - jamais d'exception non gérée : `call()` renvoie une promesse rejetée (délai 1,5 s par
 *     défaut) ; l'appelant dégrade silencieusement ;
 *   - un seul socket, commandes envoyées dans l'ordre (pipelining naturel), reconnexion
 *     automatique avec attente croissante (0,5 s → 10 s) ;
 *   - le mot de passe vient d'une variable d'environnement dédiée et n'est jamais journalisé
 *     (utiliser `redacted()` pour afficher l'adresse).
 * Valeurs binaires acceptées (Buffer) — les réponses « bulk » sont rendues en Buffer.
 */
const net = require('net');
const tls = require('tls');

const MAX_BULK = 512 * 1024 * 1024;

function parseUrl(raw, passwordOverride) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { throw new Error('URL Redis invalide (attendu : redis://hôte[:port][/db])'); }
  if ((u.protocol !== 'redis:' && u.protocol !== 'rediss:') || !u.hostname) {
    throw new Error('URL Redis invalide (attendu : redis://hôte[:port][/db])');
  }
  const dbStr = u.pathname.replace(/^\//, '');
  const db = dbStr === '' ? 0 : Number(dbStr);
  if (!Number.isInteger(db) || db < 0 || db > 255) throw new Error('numéro de base Redis invalide');
  return {
    tls: u.protocol === 'rediss:',
    host: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port || 6379),
    username: u.username ? decodeURIComponent(u.username) : '',
    password: passwordOverride || (u.password ? decodeURIComponent(u.password) : ''),
    db,
  };
}

/** Analyse incrémentale RESP2 : renvoie [valeur, octetsConsommés] ou null si incomplet. */
function parseReply(buf, off = 0, depth = 0) {
  if (off >= buf.length) return null;
  if (depth > 4) throw new Error('réponse trop imbriquée');
  const eol = buf.indexOf('\r\n', off, 'latin1');
  if (eol < 0) return null;
  const type = String.fromCharCode(buf[off]);
  const line = buf.toString('latin1', off + 1, eol);
  const next = eol + 2;
  switch (type) {
    case '+': return [line, next];
    case '-': { const e = new Error(line); e.redis = true; return [e, next]; }
    case ':': return [Number(line), next];
    case '$': {
      const n = Number(line);
      if (!Number.isInteger(n) || n > MAX_BULK) throw new Error('taille de réponse invalide');
      if (n < 0) return [null, next];
      if (buf.length < next + n + 2) return null;
      return [Buffer.from(buf.subarray(next, next + n)), next + n + 2];
    }
    case '*': {
      const n = Number(line);
      if (!Number.isInteger(n) || n > 1 << 20) throw new Error('taille de tableau invalide');
      if (n < 0) return [null, next];
      const out = []; let p = next;
      for (let i = 0; i < n; i++) {
        const r = parseReply(buf, p, depth + 1);
        if (!r) return null;
        out.push(r[0]); p = r[1];
      }
      return [out, p];
    }
    default: throw new Error('type de réponse inconnu');
  }
}

function encode(args) {
  const parts = [Buffer.from(`*${args.length}\r\n`)];
  for (const a of args) {
    const b = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
    parts.push(Buffer.from(`$${b.length}\r\n`), b, Buffer.from('\r\n'));
  }
  return Buffer.concat(parts);
}

class RedisClient {
  constructor(url, { password = '', timeoutMs = 1500, connectTimeoutMs = 2000, log = () => {} } = {}) {
    this.opt = parseUrl(url, password);
    this.timeoutMs = timeoutMs;
    this.connectTimeoutMs = connectTimeoutMs;
    this.log = log;
    this.sock = null; this.ready = false; this.connecting = null;
    this.queue = []; // {resolve,reject,timer}
    this.rx = Buffer.alloc(0);
    this.backoff = 500; this.nextTry = 0;
    this.lastError = ''; this.lastOkAt = 0; this.closed = false;
  }

  redacted() { return `${this.opt.tls ? 'rediss' : 'redis'}://${this.opt.host}:${this.opt.port}/${this.opt.db}`; }
  get connected() { return this.ready; }

  _fail(err) {
    this.lastError = String(err && err.message || err);
    const q = this.queue; this.queue = [];
    for (const p of q) { clearTimeout(p.timer); p.reject(err instanceof Error ? err : new Error(String(err))); }
  }

  _teardown(err) {
    const s = this.sock; this.sock = null; this.ready = false; this.rx = Buffer.alloc(0);
    if (s) { s.removeAllListeners(); s.on('error', () => {}); s.destroy(); }
    this._fail(err || new Error('connexion Redis fermée'));
    this.backoff = Math.min(this.backoff * 2, 10_000);
    this.nextTry = Date.now() + this.backoff;
  }

  _onData(chunk) {
    this.rx = this.rx.length ? Buffer.concat([this.rx, chunk]) : chunk;
    for (;;) {
      let r;
      try { r = parseReply(this.rx); } catch (e) { this._teardown(e); return; }
      if (!r) return;
      this.rx = this.rx.subarray(r[1]);
      const p = this.queue.shift();
      if (!p) continue;
      clearTimeout(p.timer);
      if (r[0] instanceof Error) p.reject(r[0]); else p.resolve(r[0]);
    }
  }

  _connect() {
    if (this.ready) return Promise.resolve();
    if (this.connecting) return this.connecting;
    if (Date.now() < this.nextTry) return Promise.reject(new Error(this.lastError || 'Redis indisponible (nouvel essai bientôt)'));
    this.connecting = new Promise((resolve, reject) => {
      const o = this.opt;
      const sock = o.tls
        ? tls.connect({ host: o.host, port: o.port, servername: o.host, minVersion: 'TLSv1.2' })
        : net.connect({ host: o.host, port: o.port });
      this.sock = sock;
      sock.setNoDelay(true);
      const timer = setTimeout(() => sock.destroy(new Error('délai de connexion Redis dépassé')), this.connectTimeoutMs);
      const onConnect = async () => {
        clearTimeout(timer);
        sock.on('data', c => this._onData(c));
        this.ready = true; // les commandes d'initialisation passent par la file normale
        try {
          if (o.password) await this._send(o.username ? ['AUTH', o.username, o.password] : ['AUTH', o.password]);
          if (o.db) await this._send(['SELECT', o.db]);
          this.backoff = 500; this.lastError = ''; this.lastOkAt = Date.now();
          resolve();
        } catch (e) { this._teardown(e); reject(e); }
      };
      sock.once(o.tls ? 'secureConnect' : 'connect', onConnect);
      sock.on('error', e => { clearTimeout(timer); const was = this.ready; this._teardown(e); if (!was) reject(e); });
      sock.on('close', () => { clearTimeout(timer); if (this.sock === sock) this._teardown(new Error('connexion Redis fermée')); });
    }).finally(() => { this.connecting = null; });
    this.connecting.catch(() => {});
    return this.connecting;
  }

  _send(args) {
    return new Promise((resolve, reject) => {
      if (!this.sock || !this.ready) return reject(new Error('Redis non connecté'));
      const p = { resolve, reject, timer: setTimeout(() => {
        // Une réponse en retard décalerait la file : on repart sur une connexion neuve.
        this._teardown(new Error('délai de commande Redis dépassé'));
      }, this.timeoutMs) };
      this.queue.push(p);
      this.sock.write(encode(args));
    });
  }

  /** Exécute une commande ; rejette (sans bruit pour l'appelant prudent) si Redis est indisponible. */
  async call(...args) {
    if (this.closed) throw new Error('client Redis fermé');
    await this._connect();
    const r = await this._send(args);
    this.lastOkAt = Date.now();
    return r;
  }

  async get(key) { return this.call('GET', key); }
  async set(key, val, exSeconds) { return exSeconds ? this.call('SET', key, val, 'EX', Math.max(1, Math.floor(exSeconds))) : this.call('SET', key, val); }
  async del(...keys) { return this.call('DEL', ...keys); }
  async ping() { return String(await this.call('PING')); }

  /** Renvoie { ok, usedMemory, maxMemory, version, clients, error } sans jamais lever. */
  async info() {
    try {
      const t0 = Date.now();
      const raw = String(await this.call('INFO')); // sections par défaut (inclut memory, server, clients)
      const pick = k => { const m = raw.match(new RegExp('^' + k + ':(.*)\\r?$', 'm')); return m ? m[1].trim() : ''; };
      return { ok: true, latencyMs: Date.now() - t0, version: pick('redis_version'),
        usedMemory: Number(pick('used_memory')) || 0, maxMemory: Number(pick('maxmemory')) || 0,
        clients: Number(pick('connected_clients')) || 0, uptimeSeconds: Number(pick('uptime_in_seconds')) || 0 };
    } catch (e) { return { ok: false, error: String(e.message || e) }; }
  }

  close() {
    this.closed = true;
    const s = this.sock; this.sock = null; this.ready = false;
    if (s) { s.removeAllListeners(); s.on('error', () => {}); s.destroy(); }
    this._fail(new Error('client Redis fermé'));
  }
}

/** null si `url` est vide (Redis non configuré) ; lève si l'URL est invalide. */
function createClient(url, opts) {
  if (!url || !String(url).trim()) return null;
  return new RedisClient(url, opts);
}

module.exports = { createClient, RedisClient, parseUrl, parseReply, encode };
