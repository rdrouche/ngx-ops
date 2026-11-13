# Shipper and Logs page

The **shipper** reads Nginx access logs and sends them to the [log store](log-store.md). It also provides a local HTTP input where the emulated WAF, the challenge and CrowdSec drop their decisions. It is the **only exit point** to the log store: only the shipper knows the remote URL and the write token.

```
Nginx access logs ──► shipper ──(HTTPS, write token, durable disk buffer)──► log store ◄── Logs page (read token)
blocklist-hits.log ─────►    ▲
emulated WAF, challenge ─(local HTTP, local token)─┘
```

The shipper is one of the three binaries of the `analyzer-agent-go` image, along with the analyzer and the emulated WAF.

## Getting started from the dashboard

1. **Log store**: deploy it, then create one `write` token per server (with its `instance_id`) and one `read` token for the dashboard.
2. **Variables** in the dashboard `.env` file: `LOGSTORE_READ_TOKEN`, `LOGSINK_TOKEN`, and optionally `SHIPPER_LOCAL_TOKEN` (`openssl rand -hex 24`).
3. **Configuration**: **Configure** button on the **Logs** page (administrator), or the `logstore.yml` file:

    ```yaml
    enable: true
    url: https://logs.example.com
    shipper_enable: true
    shipper_host_data_path: /srv/ngx/shipper
    instance: web1
    ```

    `shipper_host_data_path` is required: it is a **host** path holding the read positions and the disk buffer.
4. **Logs** page → **Start / recreate**: NGX Ops pulls the image, creates the `ngx-shipper` container (hardened, no published port) and shows its status.
5. To send the decisions of the emulated WAF and the challenge, set `shipper_url: http://ngx-shipper:9181` in their configuration files, then restart their containers.

Tokens are never sent back to the browser (only "set" or "missing"). In the form, an empty field keeps the current value. Environment variables win over the file.

!!! info "Without the dashboard"
    An `ngx-shipper` service can also be declared directly in the `docker-compose` (`logstore` profile) with `LOGSINK_URL`, `LOGSINK_TOKEN` and `SHIPPER_LOCAL_TOKEN`. Choose **either** method (same container name). The Logs page then still reads the log store, but the dashboard does not manage this container.

## Guarantees

* Each read is durably written to a disk buffer **before** the read position advances: a crash is recovered at startup.
* Sends are idempotent: a replay is deduplicated by the log store.
* No loss or duplicate on restart, rotation, truncation (`copytruncate`) or log store outage.
* A file seen for the first time is read from its **end**: history is not re-imported.

!!! warning "Log rotation"
    Tracking is not done by inode. A rotation by renaming to a name that no longer matches the pattern (`access.log`, `access.log.1`…) can lose the lines written since the last pass (one second at most). Prefer `copytruncate`, or a name that still matches the pattern.

Decisions emitted while the shipper is stopped are lost; this trade-off is accepted. Access logs, on the other hand, are caught up at restart.

## What is sent

* Nginx access logs (with User-Agent classification, and the country if `shipper_country` is enabled).
* Requests refused by the blocklists, read from `blocklist-hits.log`. The shipper retrieves the list name from the analyzer.
* CrowdSec local decisions (`shipper_crowdsec`), without the community list.
* Decisions from the emulated WAF and the challenge, received through the local input.

## Monitoring

The **Logs** page shows the shipper status. Without going through Docker logs:

* `GET /healthz` (no token) serves as a probe;
* `GET /status` (header `Authorization: Bearer <SHIPPER_LOCAL_TOKEN>`) gives the tracked files, positions, lines read or skipped, rotations, buffer, sends and problems. It contains no secret.

## Shipper variables

| Variable | Default | Role |
| -------- | ------- | ---- |
| `LOGSINK_URL` | required | Log store URL |
| `LOGSINK_TOKEN` | required | The instance's `write` token |
| `LOGSINK_ALLOW_INSECURE` | `false` | Allows `http://` (internal Docker network only) |
| `LOGSINK_INSTANCE` | empty | Instance name |
| `LOGSINK_SPOOL_DIR` | `/data/spool` | Disk buffer (persistent volume) |
| `LOGSINK_SPOOL_MAX_MB` | `256` | Buffer cap; the oldest are dropped and counted |
| `LOGSINK_SPOOL_MAX_HOURS` | `24` | Maximum age in the buffer |
| `LOGSINK_BATCH_SIZE` | `500` | Batch size |
| `LOGSHIP_DIR` | `/nginx/logs` | Nginx logs folder (read-only) |
| `LOGSHIP_PATTERN` | `access.log` and its rotations | Tracked files |
| `LOGSHIP_POLL_MS` | `1000` | Read cadence |
| `LOGSHIP_BLOCKLIST` | `true` | Also tracks `blocklist-hits.log` |
| `LOGSHIP_STATE_FILE` | `/data/offsets.json` | Read positions |
| `LOGSHIP_LISTEN` | `127.0.0.1:9181` | Local API; in a container, `0.0.0.0:9181` on an internal network, never published |
| `LOGSHIP_LOCAL_TOKEN` | empty | Local API token (24 characters minimum); when empty, only `/healthz` is served |
| `LOGSHIP_BOTCLASS` | `true` | Adds the bot class |
| `LOGSHIP_COUNTRY` | `false` | Adds the country (GeoIP database) |

When the shipper is managed by the dashboard, these variables are filled in from `logstore.yml`.

## The Logs page

The dashboard **Logs** page queries the log store with the read token: search, visit statistics, security, per-IP history. It requires the log store to be enabled in `logstore.yml`. Search parameters are validated by allowlist and no redirect is followed.
