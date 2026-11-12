# Hub : ce que le Hub fait du contrat dashboard

Le **contrat** (routes, jetons, enveloppes, codes d'erreur, résumé, archive, garanties de confidentialité) est défini une seule fois dans [`../../Docs/contrat-hub-dashboard-v1.md`](../../Docs/contrat-hub-dashboard-v1.md). Ce fichier ne décrit que le comportement **côté Hub** et ne répète pas le contrat.

## Pull
- Résumé : le Hub **re-type et borne tout** (`features/collector/summary-schema.js`) : champ inconnu ignoré, champ absent = valeur neutre, `traffic_24h: null` → `available:false` (distinct d'un zéro). Aucune IP de visiteur, secret ou chemin disque n'est retenu : liste blanche.
- États de composants : `ok|degraded|down|disabled|unknown` + synonymes tolérés (`running/active/up → ok`, `error/failed/stopped → down`, `warn → degraded`, `off → disabled`).
- Modules et alertes (12.78.0) : rendu tolérant, 404 = module désactivé ou inconnu (masqué, pas une erreur), partie absente ≠ zéro, clés inconnues ignorées, 429 → réessai au cycle suivant. `indicators` : opt-in, admin ; 403 `expose_ips_disabled` si le dashboard n'expose pas les IP. Les IP de visiteurs ne sont jamais écrites dans les journaux.
- Le Hub n'écrit aucune configuration du dashboard (sélection de modules, `expose_ips`).

## Push — réception des sauvegardes
`POST {hub}/api/hub/v1/backups` : `Content-Length` obligatoire (pas de chunked), `X-Backup-Sha256` obligatoire (de l'archive telle qu'envoyée).
Réponses : `201 {"id","duplicate":false}` · `200 {"id","duplicate":true}` (même SHA-256 déjà reçu pour l'instance) · `401` jeton · `411/413/415` · `422` (`checksum_mismatch`, `bad_archive`) · `429`.

Le Hub : identifie l'instance par l'empreinte du jeton Bearer (`X-Instance-Id` n'est qu'informatif), vérifie le SHA-256 en flux (jamais en mémoire), contrôle la forme (`tar.gz` ou `NGXB1…` cohérent avec `X-Backup-Encrypted`), stocke sur disque adressé par SHA-256, déduplique, applique `min(X-Retention-Days, backups.retention_days)`, alerte si aucune sauvegarde depuis `alert_after_hours`.

## Archive
Le Hub **ne connaît pas la phrase de passe** : blob opaque, aucune métadonnée lue (en-têtes seulement). Archive non chiffrée : seul le manifeste est lu (premiers Ko décompressés, plafonnés) — **aucune extraction, aucune décompression complète**.

## Hors périmètre (phase 2)
Restauration : voir §10 du contrat.
