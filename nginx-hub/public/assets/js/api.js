import { t } from './i18n.js';
// Client API /api/hub/v1 : cookies de session (HttpOnly) + jeton CSRF en en-tête pour les méthodes non sûres.
const BASE = '/api/hub/v1';
let csrf = '';

export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export function setCsrf(v) { csrf = v || ''; }

export async function api(method, path, body) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
  let res;
  try {
    res = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: 'same-origin', cache: 'no-store' });
  } catch { throw new ApiError(0, 'network', t('Hub injoignable')); }
  let json = null;
  try { json = await res.json(); } catch { /* corps vide */ }
  if (!res.ok) {
    const e = new ApiError(res.status, json?.error?.code || 'error', t(json?.error?.message || 'Erreur {s}', { s: res.status }));
    if (res.status === 401 && e.code === 'unauthenticated') window.dispatchEvent(new CustomEvent('hub:unauthenticated'));
    throw e;
  }
  if (json && json.csrf) csrf = json.csrf;
  return json;
}

export const get = (p) => api('GET', p);
export const post = (p, b) => api('POST', p, b ?? {});
export const patch = (p, b) => api('PATCH', p, b);
export const del = (p) => api('DELETE', p);
