// Point d'entrée des vues graphiques : un module sans vue dédiée (ou dont le rendu échoue) retombe sur le rendu générique (smart.js).
import { securityView } from './security.js';
import { trafficView } from './traffic.js';
import { inventoryView } from './inventory.js';
import { opsView } from './ops.js';
import { reportsView } from './reports.js';

const VIEWS = { security: securityView, traffic: trafficView, inventory: inventoryView, ops: opsView, reports: reportsView };

export function dashboardFor(name, data) {
  const view = VIEWS[name];
  if (!view || !data || typeof data !== 'object') return null;
  try { return view(data); } catch (e) { console.error('vue graphique', name, e); return null; }
}
