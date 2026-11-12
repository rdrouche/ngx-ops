#!/bin/sh
# Kit de mesure PRODUCTION du log store (#60). POSIX sh : tourne tel quel sous Alpine (busybox ash) et Debian (dash/bash).
# Dépendances : docker, curl (facultatif), awk. Lecture seule : aucune écriture en base, aucun jeton créé.
# Usage : ./measure-prod.sh <conteneur-db> [<conteneur-logstore> [<conteneur-shipper>]]
#   ex. : ./measure-prod.sh logstore-db logstore nginx-logship > mesure-$(date +%Y%m%d).txt
set -eu
DB=${1:?conteneur PostgreSQL/TimescaleDB requis}; LS=${2:-}; SH=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
echo "# Mesure log store — $(date -u '+%Y-%m-%dT%H:%M:%SZ') — $(uname -sr)"
echo "# Hôte : $(nproc 2>/dev/null || echo '?') cœurs, $(awk '/MemTotal/ {printf "%.1f Go", $2/1048576}' /proc/meminfo)"
echo; echo "## PostgreSQL / TimescaleDB"
docker exec "$DB" psql -U "${PGUSER:-logstore}" -d "${PGDATABASE:-logstore}" -c "SELECT version();" -c "SELECT extversion AS timescaledb FROM pg_extension WHERE extname='timescaledb';"
docker exec -i "$DB" psql -U "${PGUSER:-logstore}" -d "${PGDATABASE:-logstore}" < "$HERE/measure.sql"
echo; echo "## Ressources instantanées (docker stats)"
for c in "$DB" $LS $SH; do docker stats --no-stream --format '{{.Name}}  CPU {{.CPUPerc}}  RAM {{.MemUsage}}  Réseau {{.NetIO}}  Disque {{.BlockIO}}' "$c"; done
echo; echo "## Occupation disque du volume de données"
docker exec "$DB" df -h /var/lib/postgresql/data | tail -n 1
echo; echo "## Requêtes lentes (pg_stat_statements si activé)"
docker exec "$DB" psql -U "${PGUSER:-logstore}" -d "${PGDATABASE:-logstore}" -At -c "SELECT round(mean_exec_time::numeric,1)||' ms moy / '||calls||' appels : '||left(regexp_replace(query,'\s+',' ','g'),90) FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;" 2>/dev/null || echo "(pg_stat_statements non activé : sans importance)"
if [ -n "$LS" ]; then echo; echo "## Journal du log store (erreurs/avertissements, 24 h)"; docker logs --since 24h "$LS" 2>&1 | grep -ciE 'level=(error|warn)' | awk '{print $1 " lignes warn/error"}'; fi
if [ -n "$SH" ]; then echo; echo "## Journal du shipper (erreurs/avertissements, 24 h)"; docker logs --since 24h "$SH" 2>&1 | grep -ciE 'error|warn' | awk '{print $1 " lignes warn/error"}'; fi
