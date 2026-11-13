# NGX Ops Hub

The **Hub** gives a global, **read-only** view of several NGX Ops dashboards (one per server or site), without replacing them. It also centralizes their configuration [backups](backups.md).

It is a standalone Node.js container. It stores its data in SQLite (no extra dependency) or, optionally, in PostgreSQL.

```
browser ──HTTPS──► Nginx (TLS) ──► Hub ──HTTPS (pull, read-only)──► dashboard A / B / C
                                   │
                                   ├─ database: inventory, encrypted tokens, 30-day history
                                   └─ /data/backups: backup archives
```

The Hub **queries** the dashboards, never the other way around: a dashboard needs to know neither the address nor the existence of the Hub.

## Installation

```bash
cp config/hub.sample.yml config/hub.yml        # adapt public_base_url, allow_private_networks…
cp sample.env .env
cp docker-compose.example.yml docker-compose.yml
docker compose run --rm hub node bin/hub-admin.js generate-key   # paste the value in .env: HUB_SECRET_KEY=
docker compose up -d --build
docker compose logs hub      # password of the "admin" account, shown only once
```

On first start, the Hub creates the `admin` account with a random password written in the container logs. On first login:

1. password change is mandatory;
2. MFA enrollment by QR code (mandatory by default);
3. add a first instance.

!!! warning "Protect the first-start logs"
    The initial password only appears once, but if your Docker logs are collected elsewhere, purge or protect those from the first start.

Lost initial password: `docker compose exec hub node bin/hub-admin.js set-password admin --must-change`. To impose the initial password, use `HUB_BOOTSTRAP_ADMIN_PASSWORD`; `security.bootstrap_admin: false` disables automatic creation (then create an account with `create-user`).

!!! danger "Master key"
    `HUB_SECRET_KEY` (32 bytes, as 64 hexadecimal characters or base64) encrypts instance tokens and MFA secrets. **Back it up along with the `/data` volume**: without it, this data cannot be decrypted. It can also be provided by `HUB_SECRET_KEY_FILE` (Docker secret).

Put Nginx in front of the Hub (an example, `nginx/hub.conf.example`, is provided) before exposing it. The Hub port is bound to `127.0.0.1`.

## Connect a dashboard

1. In the Hub, **Add an instance** (name and HTTPS URL): the Hub shows a token and its SHA-256 fingerprint **only once**.
2. On the dashboard, set `HUB_TOKEN_SHA256=<fingerprint>` then restart. There is nothing else to install.
3. On the next cycle (60 seconds at most), the instance goes "Online".

**Token rotation**: *Edit* → *Renew the token*. Put both fingerprints, separated by a comma, on the dashboard side during the switchover.

How collection works: polling every 60 seconds (8 in parallel, 5-second timeout), instance "offline" after 3 consecutive failures, history kept 30 days.

## What the Hub shows

* **Overview and instances**: status of each dashboard and history.
* **Alerts**: global, with one tab per instance.
* **Virtual hosts**: all vhosts of all instances.
* **Module tabs** on an instance's page (traffic, security, monitoring, reports…), each with "Raw data" to see exactly what the dashboard sends. A missing module is simply hidden; a part in error is flagged, never counted as zero. Modules are set in the `modules:` block of `hub.yml`.
* **Indicators** (administrator): one row per IP with all the sources that know it.
* **Logs** and **Explorer** if the log store is connected (see below).

!!! info "Visitor IP addresses"
    These are personal data. They are only exposed if the dashboard has `expose_ips` **and** the Hub has `modules.indicators.enabled: true`. They are only visible to administrators and are never logged.

## Query the log store from the Hub

Disabled by default. To enable it, in `hub.yml`: `logstore.enabled: true` and `logstore.url: https://…`. The **global** `read` token (without `instance_id`) of the [log store](../features/logs/log-store.md) goes in `HUB_LOGSTORE_TOKEN` or `HUB_LOGSTORE_TOKEN_FILE`, never in `hub.yml`.

* **Logs** tab: visits by status code, security, blocks and tops (sites, countries, rules, client types, sources), from 24 hours to 31 days, per instance. No IP, path, User-Agent or raw log is relayed by this page.
* **IP correlation** (option `logstore.indicators.enabled`): merges the log store's per-IP activity into the Indicators. A probable campaign is an IP seen by at least 2 instances or by at least 3 signal types.
* **Explorer** (option `logstore.explorer.enabled`, in addition to the above): multi-instance raw log search, IP sheet, top attacks and sources, campaigns. It handles personal data: reserved for administrators, with rate limiting, **no storage at all** in the Hub. The log store's IP mode (clear, /24 or pseudonymized) is respected.

## Variables

Any missing key takes its default value. Environment variables win over `hub.yml`.

| Variable | `hub.yml` key | Role |
| -------- | ------------- | ---- |
| `HUB_SECRET_KEY` / `HUB_SECRET_KEY_FILE` | never in the YAML | Master key |
| `HUB_PUBLIC_BASE_URL` | `server.public_base_url` | Public URL, shown in backup upload URLs |
| `HUB_PORT`, `HUB_HOST`, `HUB_DATA_DIR`, `HUB_COOKIE_SECURE`, `HUB_LOG_LEVEL`, `HUB_CONFIG` | `server.*`, `log.level` | Server and logs |
| `HUB_BOOTSTRAP_ADMIN_PASSWORD` | — | Imposed initial password (12 characters minimum) |
| `HUB_LOGSTORE_ENABLED`, `HUB_LOGSTORE_URL` | `logstore.enabled`, `logstore.url` | Log store reading |
| `HUB_LOGSTORE_TOKEN` / `_FILE` | never in the YAML | Log store `read` token |
| `HUB_DB_DRIVER`, `HUB_DB_HOST`, `HUB_DB_PORT`, `HUB_DB_NAME`, `HUB_DB_USER` | `storage.*` | PostgreSQL |
| `HUB_DB_PASSWORD` / `_FILE` | never in the YAML | PostgreSQL password |

## Security

* The Hub only sends a `GET` to the dashboards, which only expose counters and states (no secret, no visitor IP).
* 256-bit instance tokens, encrypted (AES-256-GCM) in the database; the dashboard only keeps the SHA-256 fingerprint.
* Protection against requests to internal destinations (SSRF): HTTPS enforced, DNS validated at each connection, cloud metadata addresses always blocked, private networks allowed only with `allow_private_networks` or `allowed_cidrs`, no redirect followed, certificate always verified (internal authority with `extra_ca_file`).
* Authentication: hashed passwords, lockout after 5 failures (15 minutes), TOTP with anti-replay, `HttpOnly`, `Secure`, `SameSite=Strict` cookie, CSRF token, strict CSP.
* Audit log of logins, changes and rotations, kept 365 days.
* Non-root container, read-only file system, capabilities dropped.

To plan on the infrastructure side: restrict access to the Nginx vhost (VPN or allowed address list) and leave the Hub only outbound access to the dashboards.

## Language

An FR / EN selector in the header remembers the choice per browser; `ui.default_language` sets the default value.
