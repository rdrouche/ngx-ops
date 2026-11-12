'use strict';
/**
 * Compte administrateur initial. Au premier démarrage (aucun compte en base), crée « admin » avec un mot de passe
 * aléatoire affiché UNE SEULE FOIS dans les logs du conteneur (docker compose logs hub). Changement obligatoire à la
 * première connexion (état de session « pwchange »). Désactivable : security.bootstrap_admin: false.
 * Mot de passe imposé possible via HUB_BOOTSTRAP_ADMIN_PASSWORD (12 caractères minimum), changement obligatoire aussi.
 */
const crypto = require('node:crypto');
const { checkPassword } = require('./users');

async function ensureBootstrapAdmin({ users, config, banner, log, env = process.env }) {
  if (!config.security.bootstrap_admin || (await users.count()) > 0) return null;
  const fixed = env.HUB_BOOTSTRAP_ADMIN_PASSWORD;
  if (fixed && checkPassword(fixed)) log.warn('HUB_BOOTSTRAP_ADMIN_PASSWORD ignoré : ' + checkPassword(fixed));
  const password = fixed && !checkPassword(fixed) ? fixed : crypto.randomBytes(15).toString('base64url');
  await users.create({ username: 'admin', password, role: 'admin', mustChange: true });
  const bar = '='.repeat(66);
  banner([
    '', bar,
    '  NGX OPS HUB - COMPTE ADMINISTRATEUR INITIAL',
    '',
    '  Identifiant  : admin',
    fixed && !checkPassword(fixed) ? '  Mot de passe : (celui de HUB_BOOTSTRAP_ADMIN_PASSWORD)' : `  Mot de passe : ${password}`,
    '',
    '  Affiche UNE SEULE FOIS. Changement du mot de passe obligatoire a la',
    '  premiere connexion, puis activation du MFA.',
    '  Perdu ? docker compose exec hub node bin/hub-admin.js set-password admin --must-change',
    bar, '',
  ].join('\n'));
  return { username: 'admin' };
}

module.exports = { ensureBootstrapAdmin };
