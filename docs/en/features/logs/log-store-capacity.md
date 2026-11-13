# Log store capacity and performance

These figures come from a synthetic load test. They give **orders of magnitude**: they depend on your hardware and your traffic. To measure your own installation, a read-only kit is provided (see below).

## Reference results

Measurements on a development machine (WSL2, 8 cores, 16 GB), TimescaleDB, **2 million events over 14 days**:

| Measure | Result |
| ------- | ------ |
| Ingestion | about 38,000 events per second (batches of 2,000, p95 of 254 ms, no rejection) |
| Target traffic | a few dozen events per second: a margin of about ×1000 |
| Disk before compression | about 430 bytes per event, indexes included |
| Disk after compression | about 100 bytes per event (×10 compression) |
| Memory | log store about 11 MB, PostgreSQL about 1 GB (cache) after the load |

Typical response times (median):

| Query | Duration |
| ----- | -------- |
| Event search | a few milliseconds |
| Tops, security over 24 h, campaigns over 24 h | 60 to 250 ms |
| IP sheet | 60 to 380 ms |
| Visit statistics over 7 days | 3.6 to 4.6 s |
| Visit statistics over 14 days | 8 to 10.5 s |
| Per-IP statistics over 7 days | 5.3 to 5.8 s |

!!! warning "Long statistics"
    Visit and per-IP statistics are the most expensive queries: they count distinct values on the raw data. The maximum query time is 15 seconds (`LOGSTORE_QUERY_TIMEOUT_SECONDS`); on a very large volume, prefer short periods.

Compression does not change the duration of slow queries.

## Estimate disk space

With about 100 bytes per event after compression, 50 events per second represent about 4.3 million events per day, i.e. about 1.9 GB per day before compression and 430 MB after. Raw logs are kept 7 to 30 days, rollups much longer but for a much smaller volume. This calculation is an estimate to confirm with a measurement on your traffic.

## Measure your installation

The log store's `bench/` folder contains two independent tools:

| Tool | Where to run it | Role |
| ---- | --------------- | ---- |
| `run.sh` | Development machine (Docker, Node 18 or later) | Disposable stack, synthetic ingestion, API query latency |
| `measure-prod.sh` | Production host | Read-only measurement: volume per day, throughput, sizes, compression, resources |

```bash
./measure-prod.sh <db-container> [<logstore-container> [<shipper-container>]] > measure-$(date +%Y%m%d).txt
```

The production kit writes nothing, uses no token and does not access the network. The file it produces contains no IP or path, only volumes, durations and sizes.
