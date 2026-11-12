'use strict';
/**
 * Détection de l'ancienne image Node de l'analyseur (#80). Le dashboard pilote désormais l'analyseur Go
 * (nginx-analyzer-go, image « analyzer-agent-go ») ; l'image Node n'est plus maintenue ni publiée. Une installation
 * dont `container_image` pointe encore dessus continue de tourner (même API) mais reçoit un avertissement.
 */

/** Dernier segment du nom d'image, sans registre, tag ni empreinte : « reg.io/a/b/nginx-analyzer:1.0 » → « nginx-analyzer ». */
function imageBase(image) {
  let s = String(image || '').trim().toLowerCase();
  const at = s.indexOf('@');
  if (at >= 0) s = s.slice(0, at);
  s = s.slice(s.lastIndexOf('/') + 1);
  const colon = s.indexOf(':');
  return colon >= 0 ? s.slice(0, colon) : s;
}

const LEGACY_NODE_NAMES = new Set(['nginx-analyzer', 'analyzer-agent']);

/** Vrai pour les images Node historiques ; faux pour le Go (`nginx-analyzer-go`, `analyzer-agent-go`) et toute image inconnue. */
function isLegacyNodeImage(image) { return LEGACY_NODE_NAMES.has(imageBase(image)); }

module.exports = { imageBase, isLegacyNodeImage };
