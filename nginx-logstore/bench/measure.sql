-- Kit de mesure du log store (#60). Lecture seule.
-- Usage : docker exec -i <conteneur-db> psql -U logstore -d logstore < measure.sql   (ou via measure-prod.sh)
\echo '== Volume par jour (30 derniers jours) =='
SELECT date_trunc('day', ts) AS jour, count(*) AS evenements FROM events WHERE ts > now() - interval '30 days' GROUP BY 1 ORDER BY 1;
\echo '== Volume par instance et source =='
SELECT instance_id, source, count(*) AS evenements FROM events GROUP BY 1, 2 ORDER BY 3 DESC;
\echo '== Debit moyen et pic horaire (evenements/s, 7 jours) =='
WITH h AS (SELECT date_trunc('hour', ts) AS h, count(*) AS n FROM events WHERE ts > now() - interval '7 days' GROUP BY 1)
SELECT round(avg(n) / 3600.0, 2) AS moyen_ev_s, round(max(n) / 3600.0, 2) AS pic_horaire_ev_s FROM h;
\echo '== Tailles =='
SELECT 'events (hypertable)' AS objet, pg_size_pretty(hypertable_size('events')) AS total,
       pg_size_pretty(index_bytes) AS index, pg_size_pretty(table_bytes) AS table_seule
FROM hypertable_detailed_size('events');
SELECT relname, pg_size_pretty(pg_total_relation_size(oid)) AS total FROM pg_class
WHERE relname IN ('instances','ingest_batches','settings','api_tokens') AND relkind = 'r';
SELECT pg_size_pretty(pg_database_size(current_database())) AS base_totale;
\echo '== Octets par evenement (hypertable : donnees + index, compresse ou non) =='
SELECT round(hypertable_size('events')::numeric / NULLIF((SELECT count(*) FROM events), 0)) AS octets_par_evenement;
\echo '== TimescaleDB : chunks et compression =='
SELECT count(*) AS chunks, count(*) FILTER (WHERE is_compressed) AS compresses FROM timescaledb_information.chunks WHERE hypertable_name = 'events';
SELECT pg_size_pretty(sum(before_compression_total_bytes)) AS avant, pg_size_pretty(sum(after_compression_total_bytes)) AS apres,
       round(sum(before_compression_total_bytes)::numeric / NULLIF(sum(after_compression_total_bytes), 0), 1) AS ratio
FROM chunk_compression_stats('events');
\echo '== Agregats continus =='
SELECT view_name FROM timescaledb_information.continuous_aggregates;
\echo '== Plus ancien / plus recent =='
SELECT min(ts) AS plus_ancien, max(ts) AS plus_recent FROM events;
