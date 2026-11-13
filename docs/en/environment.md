# Environment variables

This page describes the **dashboard** variables, then the essential variables of the other components. It follows the **System** page of the dashboard, reserved to administrators, which shows for each setting its current value, its default value and where to change it.

## General rules

- Variables go in the `.env` file next to the compose file. **No quotes** around values.
- For a given setting, the priority is: **environment variable**, then the **YAML file** in `config/` when it exists, then the default value. A value defined in `.env` therefore always wins.
- No secret is required to start. When they are missing, the dashboard generates the following secrets once and keeps them in `config/.generated-secrets.json`: `SESSION_SECRET`, `WAF_TOKEN`, `SHIPPER_LOCAL_TOKEN`, `NC_SECRET` and `INSTANCE_ID`.
- Secrets are shown in the **System** page as "configured" or "not configured", never in clear text.
- A variable marked **build** is set when the image is built (`build.args` in the compose) and can also be overridden at runtime.
- To generate a secret: `openssl rand -hex 32`.

## Dashboard

### General

| Variable | Default | Role |
|---|---|---|
| `PORT` | `3000` | Internal listening port. The published port is set in `ports:` of the compose |
| `NGINX_CONTAINER` | `nginx` | Name of the Nginx container to control (test, reload, statistics) |
| `NGINX_IMAGE` | detected | Image of the ephemeral container that tests a configuration before deployment |
| `NGINX_NETWORK` | `nginx-net` | Shared Docker network, used for the test container and DNS resolution |
| `NGINX_VTS_URL` | `http://nginx:8080/status.json` | Endpoint of the VTS module that provides per-vhost statistics |
| `NGINX_CONF_FILE` | `/etc/nginx/nginx.conf` | Path of `nginx.conf` in the Nginx container |
| `NOTIF_POLL_INTERVAL_SEC` | `5` | How often the browser polls notifications (minimum 2) |
| `INSTANCE_ID` | generated | Unique identifier of the installation (UUID), not a secret |
| `HTTP_USER_AGENT` | `NGXOps` | User-Agent of all outgoing requests, without a version number so it can be filtered |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket used to control Nginx and managed containers |

### Security and sessions

| Variable | Default | Role |
|---|---|---|
| `SESSION_SECRET` | generated | Session signing key |
| `SESSION_TTL_HOURS` | `8` | Session duration, renewed while the user is active |
| `SESSION_MAX_HOURS` | `24` | Maximum session duration, even when active |
| `LOGIN_MAX_ATTEMPTS` | `10` | Failed logins tolerated before a temporary lockout |
| `LOGIN_WINDOW_MIN` | `15` | Window for counting failures, in minutes |
| `LOGIN_LOCKOUT_MIN` | `15` | Lockout duration, in minutes |
| `API_TOKEN` | disabled | REST API token (`Authorization: Bearer`). It stays inactive if empty, if it starts with `changeme` or if it is shorter than 16 characters |
| `WEBHOOK_SECRET` | not configured | Signing secret for outgoing webhooks |
| `CORS_ORIGIN` | empty | Origin allowed cross-origin. Empty: same origin only, which is recommended |
| `TRUSTED_PROXIES` | private networks and loopback | Addresses allowed to set `X-Forwarded-For` |
| `HEALTH_PUBLIC` | `true` | Public `/health` route. `false` disables it |
| `MFA_RP_ID` | derived from `Host` | WebAuthn domain for security keys. Set it behind a proxy that rewrites `Host` |
| `MFA_ORIGIN` | derived | HTTPS origins allowed for WebAuthn, comma-separated |

The API and webhooks can also be set from the **System** page: the **Generate** button shows the value once and only keeps its fingerprint.

### Deployment and backups

| Variable | Default | Role |
|---|---|---|
| `ALLOW_EDIT` | `false` | Allows editing configuration files from the interface |
| `ALLOW_CREATE` | `false` | Allows creating files. No effect when Git is configured |
| `DEPLOY_SYNC_SSL` | `true` | Includes `ssl/` in the Git deployment. `certs/` is never synchronized |
| `GIT_REPO_URL` | empty | Reference repository. Empty: Git deployment disabled |
| `GIT_BRANCH` | `main` | Source branch |
| `GIT_BACKUP_BRANCH` | `backup` | Branch that receives the previous state before each deployment |
| `GIT_TOKEN` | empty | HTTPS token of the repository |
| `GIT_SSH_KEY` | empty | Path of the SSH key in the container, to mount as a volume |
| `GIT_USER_NAME`, `GIT_USER_EMAIL` | `Nginx Dashboard`, `dashboard@localhost` | Commit identity |
| `BACKUP_KEEP` | `20` | Number of local ZIP backups kept |
| `BACKUP_PASSPHRASE` | empty | Common fallback passphrase for encrypted archives |
| `HUB_BACKUP_PASSPHRASE` | empty | Passphrase of the backups sent to the Hub |
| `S3_BACKUP_PASSPHRASE` | empty | Passphrase of the archive sent to S3 |

A lost passphrase makes the encrypted archive unrecoverable: keep them outside the dashboard.

### Directories

The `DIR_*` variables tell where volumes are mounted **inside the dashboard container**. They must match the volumes of the compose.

| Variable | Default |
|---|---|
| `DIR_SITES` | `/nginx/sites` |
| `DIR_CONF` | `/nginx/conf` |
| `DIR_SNIPPETS` | `/nginx/snippets` |
| `DIR_STREAMS` | `/nginx/streams` |
| `DIR_SSL` | `/nginx/ssl` |
| `DIR_CERTS` | `/nginx/certs` |
| `DIR_LOGS` | `/nginx/logs` |
| `DIR_CACHE` | empty, which disables the cache purge button |
| `DIR_BACKUPS` | `/nginx/backups` |
| `DIR_GIT_WORK` | `/git-work` |
| `DIR_GOACCESS` | `/nginx/goaccess` |
| `DIR_GEOIP` | `/geoip` |

`HOST_LOGS` and `HOST_GOACCESS` are different: they are **absolute paths on the host**, used for the volumes of the containers the dashboard creates. Docker resolves these paths on the host side; a path that only exists inside the dashboard container would mount an empty folder.

### Integrations

| Variable | Default | Role |
|---|---|---|
| `CROWDSEC_PROMETHEUS_URL` | empty | Prometheus endpoint of the CrowdSec engine (recommended) |
| `CROWDSEC_LOCAL_ONLY` | `false` | Shows local decisions only |
| `CROWDSEC_URL`, `CROWDSEC_API_KEY` | empty | CrowdSec local API and bouncer key, read-only |
| `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD` | empty | Machine identity, required to ban, unban and manage allowlists |
| `GOACCESS_IMAGE` | `allinurl/goaccess:latest` | GoAccess image |
| `GOACCESS_LOG_FORMAT` | `COMBINED` | Log format read by GoAccess |
| `GOACCESS_REFRESH` | `30` | Report regeneration, in seconds |
| `GEOIP_CITY_DB`, `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB` | `/geoip/GeoLite2-*.mmdb` | Paths of the MaxMind databases |
| `GODNS_IP_CHECK` | `true` | Checks the public IP reported by GoDNS against several services |
| `GODNS_IP_CHECK_URLS` | ipify, icanhazip, ifconfig.me | Services queried for this check |
| `REDIS_URL` | empty | Address of the optional Redis, for example `redis://redis:6379/0` |
| `REDIS_PASSWORD` | empty | Redis password, required when Redis is used |
| `REDIS_PREFIX` | `INSTANCE_ID` or `ngx` | Prefix of Redis keys |

### Analysis, WAF, challenge and centralized logs

| Variable | Default | Role |
|---|---|---|
| `ANALYZER_DEFAULT_IMAGE` | suite analyzer image (**build**) | Default image of the analysis container |
| `WAF_DEFAULT_IMAGE` | `ANALYZER_DEFAULT_IMAGE` (**build**) | Emulated WAF image |
| `WAF_TOKEN` | generated | Secret shared with the emulated WAF |
| `CHALLENGE_DEFAULT_IMAGE` | suite challenge image (**build**) | Browser challenge image |
| `ANUBIS_DEFAULT_IMAGE` | `ghcr.io/techarohq/anubis:latest` (**build**) | Anubis engine image |
| `AGENT_DEFAULT_IMAGE` | suite agent image (**build**) | Image offered in the agent deployment kit |
| `NC_SECRET` | generated | Signing secret for challenge cookies |
| `NC_DIFFICULTY_BITS` | `16` | Proof-of-work difficulty (8 to 64) |
| `NC_COOKIE_HOURS` | `24` | Validity of the "verified browser" cookie, from 1 to 720 hours |
| `NC_GOODBOTS` | `true` | Lets through crawlers whose reverse DNS is confirmed |
| `NC_GOODBOTS_EXTRA` | empty | Extra crawlers: name, User-Agent regular expression and DNS suffix, separated by a vertical bar (detailed format in `sample.env`) |
| `NC_LANG` | `auto` | Language of the verification page: `auto`, `fr` or `en` |
| `SHIPPER_DEFAULT_IMAGE` | `ANALYZER_DEFAULT_IMAGE` | Shipper image |
| `SHIPPER_LOCAL_TOKEN` | generated | Local token shared between dashboard, shipper and WAF (24 characters minimum) |
| `LOGSINK_TOKEN` | empty | `write` token of this instance, used by the shipper |
| `LOGSTORE_READ_TOKEN` | empty | `read` token of the log store, used by the **Logs** page |
| `INTEL_API_URL` | empty (**build**) | Address of the Intelligence platform |
| `INTEL_TOKEN` | empty | Token for Intelligence identified mode |

The settings of these features (activation, limits, paths) are in the `config/` files: `analyzer.yml`, `waf.yml`, `challenge.yml`, `logstore.yml`, `intelligence.yml`. They can be changed from the matching dashboard pages.

### Retention and maintenance

| Variable | Default | Role |
|---|---|---|
| `EVENTS_RETENTION_DAYS` | `30` | Retention of the event log |
| `MONITOR_RETENTION_DAYS` | `30` | Retention of the monitoring history. An open incident is never purged |
| `NOTIF_CENTER_RETENTION_DAYS` | `90` | Retention of notifications |
| `DB_COMPACT_ON_START` | `auto` | SQLite compaction at startup: `auto`, `always` or `off` |
| `DB_COMPACT_MIN_FREE_MB` | `16` | Minimum free space that triggers compaction in `auto` mode |
| `DB_COMPACT_MIN_FREE_PCT` | `20` | Minimum share of free pages that triggers compaction in `auto` mode |

### Interface and menu

| Variable | Default | Role |
|---|---|---|
| `BRANDING_HEADER_TEXT` | empty | Text shown in the header (customer name, environment) |
| `BRANDING_DOC`, `BRANDING_DOC_LABEL` | empty, `Documentation` | Link to the documentation, at the bottom of the menu (**build**) |
| `BRANDING_SITE`, `BRANDING_SITE_LABEL` | empty | Link to a site (**build**) |
| `BRANDING_REPO`, `BRANDING_REPO_LABEL` | empty, `Source repository` | Link to the repository (**build**) |
| `BRANDING_KOFI`, `BRANDING_KOFI_LABEL` | empty, `Support on Ko-fi` | Support link. Empty: hidden (**build**) |
| `MENU_WAF`, `MENU_GODNS`, `MENU_API`, `MENU_WEBHOOKS`, `MENU_DOCKER_AUTOCONFIG`, `MENU_AGENTS`, `MENU_GOACCESS` | `auto` | Visibility of optional menus: `auto`, `show` or `hide` (GoDNS has no `auto` mode: `show` by default). Can also be set in `menu.yml` |

### Updates and synchronization

| Variable | Default | Role |
|---|---|---|
| `SYNC_REF_URL` | empty | Reference repository for snippet and configuration synchronization |
| `SYNC_REF_PATH_PREFIX` | empty | Subfolder of the reference repository, if `conf`, `sites`, `snippets` and `streams` are not at its root |
| `DASHBOARD_VERSION_URL`, `NGINX_VERSION_URL` | empty | Addresses queried to detect a new version. Empty: check disabled |
| `CHANGELOG_URL` | empty | Address of the changelog shown by the **Changelog** button |
| `ALERTING_URL`, `ALERTING_POLL_INTERVAL_MIN` | empty, `60` | Important messages delivered through a Markdown address, with a minimum interval of 5 minutes |

## Nginx

Variables read by the compose, in `.env`:

| Variable | Default | Role |
|---|---|---|
| `NGINX_TAG` | see `sample.env` | Nginx image tag |
| `NGINX_RESTART_POLICY` | `always` | Restart policy |
| `NGINX_WORKER_PROCESSES` | `auto` | Number of worker processes |
| `NGINX_WORKER_CONNECTIONS` | `768` | Connections per process |

## Hub

`.env` file of `nginx-hub/`. The rest of the configuration is in `config/hub.yml`.

| Variable | Role |
|---|---|
| `HUB_SECRET_KEY` | Master key that encrypts instance tokens. Generate it with `docker compose run --rm hub node bin/hub-admin.js generate-key`. Back it up with the data |
| `HUB_PORT` | Listening port, `8090` by default |
| `HUB_BOOTSTRAP_ADMIN_PASSWORD` | Initial password forced on the `admin` account (12 characters minimum, change required at first login). Without it, a random password is shown once in the logs |
| `HUB_LOG_LEVEL` | Logging level, `info` by default |
| `HUB_LOGSTORE_TOKEN`, `HUB_LOGSTORE_URL` | Global `read` token and address of the log store, for the **Logs** view |
| `HUB_DB_DRIVER`, `HUB_DB_HOST` | Use PostgreSQL instead of SQLite |

In production, prefer a Docker secret (`HUB_SECRET_KEY_FILE`, `HUB_LOGSTORE_TOKEN_FILE`) to a plain variable.

## Log store

| Variable | Default | Role |
|---|---|---|
| `LOGSTORE_DB_PASSWORD` | to define | PostgreSQL password |
| `LOGSTORE_ADMIN_TOKEN` | to define | Administration token (32 characters minimum) used to create `write` and `read` tokens |
| `LOGSTORE_IP_MODE` | `clear` | Initial IP address mode: `clear`, `pseudonymized` or `truncated` |
| `LOGSTORE_PSEUDO_KEY` | empty | Pseudonymization key, required in `pseudonymized` mode (32 characters minimum) |
| `LOGSTORE_RETENTION_DAYS` | `30` | Initial retention of raw logs, from 7 to 30 days |
| `LOGSTORE_TLS_CERT`, `LOGSTORE_TLS_KEY` | empty | TLS certificate mounted in the container |
| `LOGSTORE_INSECURE_HTTP` | `true` in the example | Plain HTTP, reserved to the internal network or behind a trusted TLS proxy |
| `LOGSTORE_LISTEN` | `:8443` | Listening address |
| `LOGSTORE_REQUIRE_TIMESCALE` | see `sample.env` | Refuses to start without TimescaleDB |
| `LOGSTORE_RATE_READ`, `LOGSTORE_RATE_WRITE` | `20`, `10` | Requests per second per token |
| `LOGSTORE_MAX_BODY_BYTES`, `LOGSTORE_MAX_BATCH_EVENTS` | `4194304`, `5000` | Batch limits |
| `LOGSTORE_QUERY_TIMEOUT_SECONDS` | `15` | Maximum duration of a query |
| `LOGSTORE_MAINTENANCE`, `LOGSTORE_MAINTENANCE_HOURS` | `true`, `24` | Scheduled database maintenance and its interval |
| `LOGSTORE_UI` | `true` | `/ui/` web interface for token management |

## Agent

`.env` file of the `nginx-agent/` folder, on the **remote server**. The dashboard can generate this file and the compose file from the remote hosts page.

| Variable | Default | Role |
|---|---|---|
| `DASHBOARD_URL` | to define | Dashboard address, reachable from the remote server |
| `AGENT_HOSTNAME` | container name | Name proposed at enrollment |
| `AGENT_FINGERPRINT` | empty | Free fingerprint shown to the operator at approval time |
| `POLL_INTERVAL` | `30s` | Interval between two manifest pushes |
| `TUNNEL_ENABLE` | `true` | Opens the tunnel connection when a vhost is in `tunnel` mode |
| `RELAY_HTTP_LISTEN`, `RELAY_HTTPS_LISTEN` | empty | Listening ports of relay mode. Empty: relay disabled |
| `RELAY_HTTP_ADVERTISE`, `RELAY_HTTPS_ADVERTISE` | empty | Full address (`http://ip:port`) Nginx will use to reach the relay |
| `RELAY_HTTPS_CERT`, `RELAY_HTTPS_KEY` | empty | Certificate of the HTTPS relay. Empty: self-signed certificate generated in memory |
| `RELAY_BACKEND_INSECURE_SKIP_VERIFY` | `false` | Accepts an HTTPS backend with a self-signed certificate |
| `TARGETS_FILE` | empty | JSON file describing several target dashboards |
| `INSECURE_SKIP_VERIFY` | `false` | Disables TLS verification of the dashboard. Never enable in production |

The details of direct, tunnel and relay modes are in [Remote agents: modes and options](features/docker-auto-config/agent-modes.md).
