# Log store: centralized log

The **log store** is an optional service that centralizes NGX Ops logs: Nginx access, decisions from the challenge, the emulated WAF, the blocklists and CrowdSec. It enables search, visit statistics, security analysis and per-IP history.

It consists of an API (Go) and a **PostgreSQL database with TimescaleDB**. It is standalone: neither the dashboard nor the Hub embeds it, they query it over HTTPS.

```
analyzer / shipper ──gzip batches, HTTPS, write token──► log store (API) ──► PostgreSQL + TimescaleDB
dashboard / Hub ───────────── read token ─────────────►        (the database port is never published)
```

Without a log store, nothing changes for the rest of the suite.

## Installation

The log store ships with an example `docker-compose` (API service and TimescaleDB database). Copy the example variables file, fill in the two required values, then start:

```bash
cp sample.env logstore.env
# fill in LOGSTORE_DB_PASSWORD and LOGSTORE_ADMIN_TOKEN (openssl rand -hex 32)
docker compose --env-file logstore.env -f docker-compose.example.yml up -d
curl -s localhost:8443/v1/health
```

The expected response is `{"status":"ok"}`. The admin token is only used to create access tokens: it is hashed at first start.

!!! warning "TLS"
    The log store requires TLS by default (`LOGSTORE_TLS_CERT` and `LOGSTORE_TLS_KEY`). `LOGSTORE_INSECURE_HTTP=true` is reserved for an internal Docker network or a trusted TLS reverse proxy.

## Tokens

There are two roles:

| Role | Usage | Scope |
| ---- | ----- | ----- |
| `write` | Send logs (the shipper) | Bound to **one instance** (`instance_id`) |
| `read` | Browse | With `instance_id`: a dashboard only sees its own logs. Without `instance_id`: global view, reserved for the Hub and administration |

Creating a token (example for a server `web1`):

```bash
curl -s -H "Authorization: Bearer $LOGSTORE_ADMIN_TOKEN" \
  -d '{"label":"web1","role":"write","instance_id":"web1"}' \
  localhost:8443/v1/tokens
```

The token is shown **only once**. It is stored hashed (SHA-256), compared in constant time, and can be revoked.

The `https://<log store>/ui/` interface lets you view, create and revoke tokens after entering the admin token (kept in memory in the tab, never stored). It is disabled with `LOGSTORE_UI=false`. If possible, restrict `/ui/` by IP address at the reverse proxy level.

## Personal data: IP mode

The mode is applied **at ingestion, on the log store side**: no producer can bypass it. It is not retroactive.

| Mode | Stored value | Search by IP |
| ---- | ------------ | ------------ |
| `clear` | The address | Yes |
| `truncated` | The /24 (IPv4) or /48 (IPv6) prefix | Yes, reduced to the prefix |
| `pseudonymized` | A truncated HMAC-SHA256 fingerprint, no address | Yes, thanks to the key |

In `pseudonymized` mode, `LOGSTORE_PSEUDO_KEY` (32 characters minimum) is required and the service refuses to start without it. Changing it breaks correlation between before and after.

No raw query string or full referer is stored: only a fingerprint and the host.

## Retention

| Setting | Range |
| ------- | ----- |
| Raw logs | 7 to 30 days |
| Rollups (hourly and daily aggregates) | 30 to 800 days |

The variables are only used for initialization. After that, retention and IP mode are changed on the fly with `PUT /v1/settings` (admin role).

## PostgreSQL maintenance

TimescaleDB purge, compression and retention are automatic. In addition, the service runs a `VACUUM (ANALYZE)` on the tables every `LOGSTORE_MAINTENANCE_HOURS` (24 h by default, first run about ten minutes after startup). `LOGSTORE_MAINTENANCE=false` turns this task off, PostgreSQL autovacuum remaining active.

The maintenance status (dead rows, compression, retention respected) is visible in the "PostgreSQL maintenance" section of the `/ui/` interface and via `GET /v1/maintenance`; `POST /v1/maintenance` runs it immediately.

## Main variables

| Variable | Role |
| -------- | ---- |
| `LOGSTORE_DB_PASSWORD` | PostgreSQL password (required) |
| `LOGSTORE_ADMIN_TOKEN` | Admin token, 32 characters minimum (required) |
| `LOGSTORE_IP_MODE` | Initial IP mode: `clear`, `truncated`, `pseudonymized` |
| `LOGSTORE_PSEUDO_KEY` | Pseudonymization key |
| `LOGSTORE_RETENTION_DAYS` | Initial raw log retention (7 to 30) |
| `LOGSTORE_TLS_CERT` / `LOGSTORE_TLS_KEY` | TLS certificate mounted in the container |
| `LOGSTORE_INSECURE_HTTP` | Plain HTTP, internal network only |
| `LOGSTORE_REQUIRE_TIMESCALE` | `true`: refuses to start without TimescaleDB |
| `LOGSTORE_UI` | `/ui/` interface (`true` by default) |
| `LOGSTORE_RATE_READ` / `LOGSTORE_RATE_WRITE` | Requests per second per token (20 / 10) |
| `LOGSTORE_MAX_BATCH_EVENTS` | Maximum batch size (5000) |
| `LOGSTORE_QUERY_TIMEOUT_SECONDS` | Maximum query time (15) |

Two separate PostgreSQL roles (read-only and write-only) are possible with `LOGSTORE_DATABASE_URL_READ` and `LOGSTORE_DATABASE_URL_WRITE`.

## Security

* TLS required by default, PostgreSQL port never published, non-root container with a read-only file system.
* Rate limiting per token and a brake on authentication failures.
* Bounded sizes everywhere (body, batch, line, decompressed size), parameterized SQL, search window of 31 days at most.
* Errors without internal detail; no token or password in the logs.

## Known limits

* Without TimescaleDB, the log store runs in "plain PostgreSQL" mode: no compression or long rollups. Reserved for development and testing.
* The number of distinct visitors is only available over the period still stored raw.
* Rollups are computed in UTC.

To send logs to the log store, see [Shipper and Logs page](shipper.md). For orders of magnitude of volume and performance, see [Capacity and performance](log-store-capacity.md).
