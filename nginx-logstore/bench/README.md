# Banc de charge et kit de mesure du log store (#60)

Deux outils indépendants, sans dépendance hors Docker/Node/awk.

| Outil | Où | Rôle |
|---|---|---|
| `run.sh` + `bench.mjs` + `docker-compose.bench.yml` | poste de dev (Docker, Node ≥ 18) | pile jetable (TimescaleDB + log store), ingestion synthétique, latence de 16 requêtes API, tailles et compression |
| `measure-prod.sh` + `measure.sql` | **hôte de production** | mesure en lecture seule du log store réel : volume/jour, débit, tailles, compression, ressources |

## Banc synthétique

    ./run.sh                                   # 2 M d'événements sur 14 jours, 4 connexions, lots de 2 000
    ./run.sh --events 10000000 --conc 8 --days 30
    docker compose -p lsbench -f docker-compose.bench.yml down -v   # nettoyage

Options de `bench.mjs` : `--events --batch --conc --days --instances --queries --skip-ingest --json`.
Les jetons créés sont révoqués en fin de banc. Les limites de débit sont relevées dans le compose du banc.

## Kit de production (POSIX sh : Alpine/busybox et Debian)

    ./measure-prod.sh <conteneur-db> [<conteneur-logstore> [<conteneur-shipper>]] > mesure-$(date +%Y%m%d).txt

Aucune écriture, aucun jeton, aucun accès réseau. Variables facultatives : `PGUSER`, `PGDATABASE` (défaut `logstore`).
Le fichier produit ne contient ni IP ni chemin : seulement des volumes, des durées et des tailles.

## Résultats de référence (poste WSL2 8 cœurs, 16 Go, TimescaleDB pg16, 2 M événements / 14 jours)

- Ingestion : **~38 000 événements/s**, lot de 2 000 : p50 166 ms, p95 254 ms, aucun rejet. Le trafic réel visé (quelques dizaines d'événements/s) laisse une marge de ×1000.
- Disque : 865 Mo avant compression (~430 octets/événement, index compris), 211 Mo après (~100 octets/événement), ratio de compression ×10.
- RAM : log store ~11 Mo, PostgreSQL ~1 Go (cache) après la charge.
- Requêtes (p50, données brutes → compressées) : `events` 4 ms ; `top` 60–250 ms ; `security` 24 h 110–180 ms ; `campaigns` 24 h 60–150 ms ; fiche IP 60–380 ms ;
  **`stats/visits` 7 j 3,6–4,6 s, 14 j 8–10,5 s (p95 12,6 s, timeout à 15 s)** ; **`stats/ips` 7 j 5,3–5,8 s** (p95 jusqu'à 9,7 s).
- Cause de `stats/visits` (vérifiée par `EXPLAIN ANALYZE`) : `count(DISTINCT COALESCE(ip_key, abbrev(ip)))` sur le brut, ~2,9 s pour 7 j / 1 M de lignes. Variante « dédoublonnage par hachage puis comptage » : 0,63 s (×4,6).
- Cause de `stats/ips` 7 j : agrégat unique avec 4 `DISTINCT` (6,8 s). Un premier étage sans `site` (ip, ip_key, instance, source) tombe à 2,1 s (×3,3) ; `count(DISTINCT site)` ne serait calculé que pour le top 100.
- Biais du banc : les données sont injectées avec des dates anciennes et la politique de rafraîchissement des agrégats ne remonte que de 3 jours ; les buckets plus vieux sont recalculés sur le brut (480 ms → 16 ms après `CALL refresh_continuous_aggregate`). En production, les données arrivent chronologiquement et sont matérialisées : ce coût n'existe pas.
- La compression ne change pas les requêtes lentes.
