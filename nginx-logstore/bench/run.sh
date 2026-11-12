#!/bin/sh
# Banc complet (#60), POSIX sh : pile jetable, ingestion, mesures, tailles. Usage : ./run.sh [options de bench.mjs]
set -eu
cd "$(dirname "$0")"
P="-p lsbench -f docker-compose.bench.yml"
ADMIN=bench-admin-token-0123456789abcdef0123456789abcdef
docker compose $P up -d --build
i=0; until curl -fs http://127.0.0.1:18443/v1/health >/dev/null; do i=$((i+1)); [ "$i" -gt 60 ] && { echo "log store injoignable" >&2; exit 1; }; sleep 2; done
node bench.mjs --url http://127.0.0.1:18443 --admin-token "$ADMIN" --json result.json "$@"
echo; echo "== Ressources conteneurs =="; docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' $(docker compose $P ps -q)
echo; echo "== Avant compression =="; docker compose $P exec -T db psql -U logstore -d logstore < measure.sql
echo; echo "== Compression forcée des chunks > 1 jour =="
docker compose $P exec -T db psql -U logstore -d logstore -c "SELECT count(compress_chunk(c, if_not_compressed => true)) FROM show_chunks('events', older_than => interval '1 day') c;"
docker compose $P exec -T db psql -U logstore -d logstore < measure.sql | sed -n '/Tailles/,/Agrégats/p'
echo; echo "Nettoyage : docker compose $P down -v"
