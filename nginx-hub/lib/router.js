'use strict';
/**
 * Routeur minimal. Options de route :
 *   auth     : true (défaut) → session requise ; false → public
 *   states   : états de session acceptés (défaut ['active']) — utilisé par les routes de connexion/MFA
 *   perm     : permission requise (cf. lib/perms.js)
 *   csrf     : true par défaut pour les méthodes non sûres
 *   rate     : { key:'login', max, windowMs } limite par IP (+ clé)
 */
class Router {
  constructor() { this.routes = []; }

  add(method, pattern, opts, handler) {
    if (typeof opts === 'function') { handler = opts; opts = {}; }
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/:([A-Za-z_]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
    this.routes.push({ method, pattern, re, keys, opts: { auth: true, states: ['active'], ...opts }, handler });
  }

  get(p, o, h) { this.add('GET', p, o, h); }
  post(p, o, h) { this.add('POST', p, o, h); }
  patch(p, o, h) { this.add('PATCH', p, o, h); }
  delete(p, o, h) { this.add('DELETE', p, o, h); }

  /** @returns {{route, params}|{methodNotAllowed:true}|null} */
  match(method, pathname) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method && !(method === 'HEAD' && r.method === 'GET')) continue;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return { route: r, params };
    }
    return pathMatched ? { methodNotAllowed: true } : null;
  }

  list() { return this.routes.map((r) => `${r.method} ${r.pattern}`); }
}

module.exports = { Router };
