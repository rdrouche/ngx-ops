#!/usr/bin/env node
'use strict';
/**
 * CLI d'administration locale (comptes du Hub). Exemples :
 *   node bin/hub-admin.js generate-key [--hex]   (base64 par défaut ; --hex = 64 caractères hexadécimaux)
 *   node bin/hub-admin.js create-user alice --role admin
 *   node bin/hub-admin.js set-password alice [--must-change]
 *   node bin/hub-admin.js reset-mfa alice
 *   node bin/hub-admin.js list-users
 *   node bin/hub-admin.js disable-user alice | enable-user alice
 * Le mot de passe est demandé sans écho (ou lu sur stdin si non interactif) : jamais en argument.
 */
const path = require('node:path');
const readline = require('node:readline');
const { loadConfig } = require('../lib/config');
const { openStore } = require('../lib/store');
const { generateKey, loadMasterKey } = require('../lib/crypto');
const { createUsers } = require('../features/auth/users');

function ask(prompt, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: !!process.stdin.isTTY });
    if (hidden && process.stdin.isTTY) {
      rl._writeToOutput = (s) => { if (s.includes(prompt)) process.stdout.write(s); };
    }
    rl.question(prompt, (a) => { rl.close(); if (hidden && process.stdin.isTTY) process.stdout.write('\n'); resolve(a); });
  });
}

async function readPassword() {
  if (!process.stdin.isTTY) return (await ask('')).trim();
  const a = await ask('Mot de passe : ', { hidden: true });
  const b = await ask('Confirmation : ', { hidden: true });
  if (a !== b) throw new Error('les mots de passe diffèrent');
  return a;
}

function flag(args, name, d) { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : d; }

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === 'help') {
    process.stdout.write('Commandes : generate-key | create-user <nom> [--role admin|viewer] [--must-change] | set-password <nom> | reset-mfa <nom> | list-users | disable-user <nom> | enable-user <nom>\n');
    return;
  }
  if (cmd === 'generate-key') { process.stdout.write(generateKey(process.argv.includes('--hex') ? 'hex' : 'base64') + '\n'); return; }

  const config = loadConfig();
  let key; try { key = loadMasterKey(); } catch { key = Buffer.alloc(32); } // clé inutile hors MFA
  const db = await openStore(config);
  const users = createUsers(db, key);
  const need = async (n) => { const u = await users.getByName(n || ''); if (!u) throw new Error('utilisateur inconnu : ' + n); return u; };

  switch (cmd) {
    case 'create-user': {
      const id = await users.create({ username: args[0], password: await readPassword(), role: flag(args, 'role', 'viewer'), mustChange: args.includes('--must-change') });
      process.stdout.write(`Utilisateur créé (id ${id}). Le MFA sera à enrôler à la première connexion.\n`);
      break;
    }
    case 'set-password': {
      const u = await need(args[0]);
      await users.setPassword(u.id, await readPassword(), { mustChange: args.includes('--must-change') });
      await db.run('DELETE FROM sessions WHERE user_id = ?', [u.id]);
      process.stdout.write('Mot de passe changé, sessions révoquées.\n');
      break;
    }
    case 'reset-mfa': {
      const u = await need(args[0]); await users.resetMfa(u.id);
      await db.run('DELETE FROM sessions WHERE user_id = ?', [u.id]);
      process.stdout.write('MFA réinitialisé (ré-enrôlement à la prochaine connexion).\n');
      break;
    }
    case 'list-users':
      for (const u of await users.list()) process.stdout.write(`${u.username}\t${u.role}\tmfa=${u.mfa_enabled ? 'oui' : 'non'}\t${u.disabled ? 'désactivé' : 'actif'}\n`);
      break;
    case 'disable-user': { const u = await need(args[0]); await users.setDisabled(u.id, true); await db.run('DELETE FROM sessions WHERE user_id = ?', [u.id]); process.stdout.write('Compte désactivé.\n'); break; }
    case 'enable-user': { const u = await need(args[0]); await users.setDisabled(u.id, false); process.stdout.write('Compte réactivé.\n'); break; }
    default: throw new Error('commande inconnue : ' + cmd);
  }
  await db.close();
}

main().catch((e) => { process.stderr.write('Erreur : ' + e.message + '\n'); process.exit(1); });
