# API du log store (v1)

Toutes les réponses sont en JSON UTF-8, dates en UTC (RFC 3339). Authentification :
`Authorization: Bearer <jeton>`. Erreurs : `{"error":"code","detail":"précision facultative"}`.

| Route | Rôle | Description |
|---|---|---|
| `GET /v1/health` | aucun / read | `{"status":"ok"}` ; avec un jeton de lecture : version, TimescaleDB, taille, dernier envoi |
| `POST /v1/ingest` | write | lot NDJSON (une ligne = un `wire.Event`), `Content-Encoding: gzip` accepté, `Idempotency-Key` obligatoire (8–128 car. `[A-Za-z0-9._:-]`), `X-Instance-Name` facultatif |
| `GET /v1/events` | read | recherche, du plus récent au plus ancien, pagination par `cursor` |
| `GET /v1/ips/{ip}` | read | résumé + événements d'une IP (ou d'une clé de pseudonyme de 32 hex) ; fenêtre par défaut 7 j |
| `GET /v1/stats/visits` | read | série horaire/journalière (cumuls) ; `visitors` seulement sur la période encore en brut |
| `GET /v1/stats/top` | read | `dimension` = path, ua, country, site, rule, referer_host, bot_class, source, action, status, ip |
| `GET /v1/stats/ips` | read | corrélation par identité (IP, /24 ou pseudonyme) : `min_instances` (déf. 2), `min_sources` (déf. 1), `limit` (≤ 500) ; fenêtre ≤ 7 j ; renvoie instances, sources, événements, blocages, dernière vue |
| `GET /v1/stats/campaigns` | read | signatures (règle + chemin) vues depuis ≥ `min_ips` IP (défaut 3, `limit` ≤ 200), fenêtre ≤ 7 j, sans IP en sortie |
| `GET /v1/stats/security` | read | classes de statuts, blocages, scanners (`min_paths`), user-agents en erreur |
| `GET /v1/instances` | read | instances connues |
| `GET /v1/settings` | read | rétention, mode IP, TimescaleDB actif, clé configurée |
| `PUT /v1/settings` | admin | `retention_days` (7–30), `agg_retention_days` (30–800), `ip_mode` |
| `GET /v1/maintenance` | admin | état de la maintenance PostgreSQL : `checks` (`retention_effective`, `compression`, `retention_events`, `aggregate_events_1h/1d`, `retention_events_1h/1d` ; `status` ok / warn / fail / na / unknown), dernier passage (`last` : déclencheur, durée, tables, erreur), `running`, taille / lignes vivantes et mortes / derniers (auto)vacuum et analyze par table, compression TimescaleDB (chunks, octets avant/après) |
| `POST /v1/maintenance` | admin | lance tout de suite la maintenance (purge + `VACUUM (ANALYZE)`) ; `202` aussitôt, avancement via `GET` ; `409` si déjà en cours |
| `GET/POST /v1/tokens`, `DELETE /v1/tokens/{id}` | admin | gestion des jetons (le jeton n'est montré qu'à la création). `instance_id` : obligatoire pour `write` ; **optionnel pour `read`** : le jeton ne voit alors que cette instance (événements, fiche IP, stats, liste des instances ; `403` si une autre `instance` est demandée ou sur `/v1/stats/ips`, qui corrèle les instances). Sans `instance_id`, `read` voit tout (Hub, administration). |

## Ingestion
Codes : `200` lot traité (`accepted`, `duplicate`, `rejected[]` = lignes refusées avec raison courte) ;
`400` requête invalide ; `401`/`403` ; `413` lot, ligne ou corps trop gros ; `429` + `Retry-After` ;
`503` base indisponible (+ `Retry-After`). Un `Idempotency-Key` déjà vu pour l'instance renvoie
`duplicate:true` sans rien écrire : rejouer un lot est toujours sûr. L'instance vient du jeton,
jamais de l'événement.

Raisons de rejet d'une ligne : `bad_json`, `bad_ts`, `ts_in_future` (> 5 min), `too_old` (au-delà de la
rétention), `bad_source`, `bad_action`, `bad_method`, `bad_status`, `bad_bytes`, `bad_rt`,
`bad_country`, `bad_ip`, `extra_too_large` (> 4 Kio), `ip_mode_unavailable`.

## Filtres (`/v1/events`, `/v1/ips`, `/v1/stats/*`)
`from`, `to` (RFC 3339) ou `since` (durée au format Go : `15m`, `24h`, `168h` ; **pas de jours**, `7d` renvoie 400) ; fenêtre ≤ 31 j (défaut : 1 h pour `events`,
24 h pour les statistiques) ; `instance`, `site`, `source`, `action`, `status` (`404` ou `4xx`),
`rule` (égalité exacte), `ua`, `path` (contient, insensible à la casse), `ip` (transformée selon le mode courant : en mode
`truncated` elle est ramenée à son /24, en mode `pseudonymized` à sa clé), `limit` (≤ 500), `cursor`.
Une query string mal encodée est refusée (`400`), jamais ignorée.

Le changement de mode IP n'est pas rétroactif : l'historique antérieur reste dans l'ancien format
et n'est pas retrouvé par une recherche faite avec le nouveau mode.
