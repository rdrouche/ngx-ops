'use strict';
/** Rôles et permissions. Ajouter une permission = ajouter une constante + l'attribuer aux rôles concernés. */
const PERMS = Object.freeze({
  VIEW: 'hub:view',
  REFRESH: 'instances:refresh',
  INSTANCES_WRITE: 'instances:write',
  AUDIT_VIEW: 'audit:view',
  COLLECTOR_STATUS: 'collector:status',
  BACKUPS_VIEW: 'backups:view',
  BACKUPS_DOWNLOAD: 'backups:download', // les archives peuvent contenir des secrets (chiffrés ou non) : admin seulement
  BACKUPS_MANAGE: 'backups:manage',
  INDICATORS_VIEW: 'indicators:view', // adresses IP de visiteurs (données personnelles) : admin seulement
  MAINTENANCE: 'maintenance:manage', // état et lancement de la maintenance PostgreSQL : admin seulement
});

const ROLES = Object.freeze({
  viewer: [PERMS.VIEW, PERMS.REFRESH, PERMS.BACKUPS_VIEW],
  admin: [PERMS.VIEW, PERMS.REFRESH, PERMS.INSTANCES_WRITE, PERMS.AUDIT_VIEW, PERMS.COLLECTOR_STATUS,
    PERMS.BACKUPS_VIEW, PERMS.BACKUPS_DOWNLOAD, PERMS.BACKUPS_MANAGE, PERMS.INDICATORS_VIEW, PERMS.MAINTENANCE],
});

function hasPerm(session, perm) {
  if (!session || session.state !== 'active') return false;
  return (ROLES[session.role] || []).includes(perm);
}

module.exports = { PERMS, ROLES, hasPerm };
