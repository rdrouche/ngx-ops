'use strict';
/**
 * Formulaires de configuration generiques (#102) + chemins hote detectes (#103).
 *  - GET  /api/config-forms?key=   schema + valeurs courantes (jamais de secret) + suggestions de chemins hote
 *  - PUT  /api/config-forms        valide (lib/config-forms.js) et met a jour le YAML ligne par ligne (0600, atomique)
 *  - GET  /api/system/paths        montages du dashboard : chemin conteneur -> chemin hote (diagnostic)
 * Administrateur uniquement. Les fichiers de `config-editor` FILES sans schema restent editables en brut.
 */
const fs = require('fs');
const path = require('path');
const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const events = require('../lib/events');
const hostPaths = require('../lib/host-paths');
const forms = require('../lib/config-forms');
const { SCHEMAS } = require('../lib/config-schemas');
const { FILES } = require('./config-editor');
const { challengeOverridesFromText } = require('../lib/challenge-settings');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

const own = (o, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(o, k);
const entryOf = (key) => FILES.find((f) => f.key === key);

function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** Schema expose au navigateur (sans expressions regulieres ni rien d'executable). */
const publicFields = (schema) => schema.fields.map((f) => ({
  key: f.key, type: f.type, ...(f.options ? { options: f.options } : {}),
  ...(f.min != null ? { min: f.min } : {}), ...(f.max != null ? { max: f.max } : {}), ...(f.suggest ? { suggest: f.suggest } : {}),
}));

function register(router) {
  router.get('/api/config-forms', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const key = url.searchParams.get('key');
    const entry = entryOf(key);
    if (!entry || !own(SCHEMAS, key)) return httpLib.badRequest(res, 'unknown key');
    const schema = SCHEMAS[key];
    if (schema.dedicated) return send(res, 200, { key, dedicated: schema.dedicated });
    if (schema.pending) return send(res, 200, { key, pending: true });
    const text = fs.existsSync(entry.file) ? fs.readFileSync(entry.file, 'utf8') : '';
    const det = await hostPaths.detect().catch(() => null);
    return send(res, 200, { key, label: entry.label, exists: fs.existsSync(entry.file), fields: publicFields(schema),
      ...forms.formView(schema, text), suggestions: det ? det.suggestions : {} });
  });

  router.put('/api/config-forms', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const entry = entryOf(body && body.key);
    if (!entry || !own(SCHEMAS, body.key)) return httpLib.badRequest(res, 'unknown key');
    const schema = SCHEMAS[body.key];
    if (!schema.fields) return httpLib.badRequest(res, 'no form for this file');
    const previous = fs.existsSync(entry.file) ? fs.readFileSync(entry.file, 'utf8') : '';
    const r = forms.applyForm(schema, body.values, previous);
    if (!r.ok) return send(res, 400, { error: 'invalid', errors: r.errors });
    if (r.text !== previous) writeAtomic(entry.file, r.text);
    events.logEvent('config_form_save', `${entry.label} (${entry.key}) config saved (form)`, session.username);
    // challenge.yml : les cles challenge_* ne s'appliquent a nginx qu'apres regeneration (page Challenge HTTP).
    const regenerate = schema.note === 'regenerate'
      && JSON.stringify(challengeOverridesFromText(previous)) !== JSON.stringify(challengeOverridesFromText(r.text));
    return send(res, 200, { ok: true, ...(regenerate ? { regenerateChallenge: true } : {}) });
  });

  router.get('/api/system/paths', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    return send(res, 200, await hostPaths.detect({ fresh: url.searchParams.get('fresh') === '1' }));
  });
}

module.exports = { register };
