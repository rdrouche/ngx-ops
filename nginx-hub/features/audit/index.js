'use strict';
/** Feature audit : consultation du journal d'actions (écriture assurée par ctx.audit dans les autres features). */
const { API_PREFIX } = require('../../lib/config');

module.exports = {
  name: 'audit',
  version: '1',
  register(ctx) {
    const sql = 'SELECT id, ts, actor, action, target, ip, detail FROM audit ORDER BY id DESC LIMIT ?';
    ctx.router.get(`${API_PREFIX}/audit`, { perm: ctx.perms.AUDIT_VIEW }, async ({ query }) => {
      const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 100, 1), 500);
      return { items: await ctx.db.all(sql, [limit]) };
    });
  },
};
