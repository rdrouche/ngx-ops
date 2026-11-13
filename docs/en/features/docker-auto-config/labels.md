# `nginx-control.*` labels — full reference

This document lists **all** the Docker labels recognized by the two auto-configuration mechanisms, which share the same `nginx-control.*` prefix family but are **not the same code** and **do not understand exactly the same set of labels**:

| | **Local** auto-config | **Remote host** auto-config |
|---|---|---|
| Component | `nginx-dashboard/lib/docker-autoconfig.js` | `nginx-agent/labels.go` (separate Go binary, runs on the remote host) |
| Sees | containers on the **same host** as nginx, through the Docker socket | containers on **its own host** (different from nginx's) |
| Related doc | "Docker auto-config" section of the README | "Remote Docker hosts (agents)" section of the README |

---

## 1. Local auto-config (`nginx-control.*`)

### Base (simple HTTP vhost)

| Label | Required | Default | Description |
|---|---|---|---|
| `nginx-control.enable` | yes | — | `true` to publish this container. Without it, all other labels are ignored. |
| `nginx-control.network` | yes | — | Name of the Docker network **actually attached to the nginx container**. Without this label, nothing shows up, with no error message other than in the logs. |
| `nginx-control.vhost.server_name` | yes | — | One or more names, separated by a space or a comma. |
| `nginx-control.vhost.listen` | no | `80` (HTTP) or `443` (as soon as SSL is requested) | Listening port. An explicit label always wins over the default. |
| `nginx-control.vhost.location<NN>` | yes (at least one) | — | Location path. `NN` = `01`, `02`, ... |
| `nginx-control.vhost.location<NN>.proxy_pass` | yes (per location) | — | Target `http://host:port`. |
| `nginx-control.vhost.location<NN>.target` | no | — | **Alias** of `.proxy_pass` (same as the remote agent, see below). If both are set on the same location, **`.target` wins**. |

### SSL

| Label | Default | Description |
|---|---|---|
| `nginx-control.vhost.ssl_certificate` | `none` | `none` \| `snippet` \| `auto` \| `certbot_http` \| `certbot_dns`. |
| `nginx-control.vhost.ssl_certificate.snippet` | — | Required if `ssl_certificate=snippet`: name of an existing file in `snippets/`. |
| `nginx-control.vhost.http_to_https_auto` | `false` | `true` adds the 301 HTTP→HTTPS redirect, only once the certificate is actually resolved. |

`ssl_certificate=auto`: looks for an already issued Let's Encrypt certificate (exact or wildcard match); stays in plain HTTP if none matches, and switches automatically on the next cycle.

`ssl_certificate=certbot_http` / `certbot_dns`: like `auto`, but actively triggers a Certbot/Certbot-DNS issuance if no certificate exists yet, **provided that** Certbot/Certbot-DNS is configured and active (`config/certbot.yml` / `config/certbot-dns.yml`) — otherwise an explicit error (`ssl.error.code`/`ssl.error.message`, `ssl_error` status). A minimum delay between two attempts is applied (`certbot_retry_minutes`, default 15 min).

### snippets

| Label | Description |
|---|---|
| `nginx-control.vhost.server.snippet<NN>` | `include snippets/<file>;` at the server block level. |
| `nginx-control.vhost.location<NN>.snippet<MM>` | `include snippets/<file>;` at the level of a specific location. |

### monitoring / diagnostics / analysis

These labels write exactly the same magic comments as a hand-written vhost (`# nginx-control-monitoring: on`, etc.) — an automatically generated vhost is then managed like any other.

| Label | Default | Behavior |
|---|---|---|
| `nginx-control.vhost.monitor.enable` | `false` (**opt-in**) | Enables HTTP monitoring of the vhost. |
| `nginx-control.vhost.monitor.interval` | — | E.g. `60s`. |
| `nginx-control.vhost.monitor.valid_http_code` | — | E.g. `2xx, 3xx` or `200,301,302`. |
| `nginx-control.vhost.location<NN>.monitor.ignore` | `false` (monitored by default) | `true` excludes **this specific location** from monitoring while the vhost has it enabled. |
| `nginx-control.vhost.diagnostic.enable` | `true` (**opt-out**) | `false` disables diagnostics for this vhost. |
| `nginx-control.vhost.analyze.enable` | `true` (**opt-out**) | `false` disables log analysis for this vhost. |
| `nginx-control.vhost.analyze.ignore_rules` | — | E.g. `1, 2, 4` — IDs of rules to ignore. |

### Multi-container aggregation (`upstream_group`)

| Label | Description |
|---|---|
| `nginx-control.vhost.location<NN>.upstream_group` | Several containers (replicas) setting the **same** `server_name` normally conflict (neither is applied). By setting the **same** group name on the **same** location, they are aggregated into a single vhost with an `upstream {}` block. Also requires: same network, same port, same SSL config, same location paths — the slightest difference falls back to the normal conflict. |

---

## 2. Remote host auto-config (`nginx-control.*`, `nginx-agent`)

Same prefix and same spirit, but **it is not the same implementation**: no `nginx-control.network` (no shared Docker network is possible between two distinct hosts), and several labels exist **only** on the remote agent side.

| Label | Default | Description |
|---|---|---|
| `nginx-control.enable` | — | `true` to publish this container. |
| `nginx-control.vhost.server_name` | — | Vhost name(s). |
| `nginx-control.vhost.mode` | `direct` | `direct` \| `tunnel` \| `relay` — see "Routing modes" below. |
| `nginx-control.vhost.relay_scheme` | `http` | `http` \| `https` — **only used if `mode=relay`**: indicates through which relay port (HTTP or HTTPS) this vhost is reachable. |
| `nginx-control.vhost.listen` | depends on SSL, as locally | Listening port on the nginx side. |
| `nginx-control.vhost.ssl_certificate` | `none` | `none` \| `snippet` \| `auto` \| `certbot_http` \| `certbot_dns` — same semantics as locally. |
| `nginx-control.vhost.ssl_certificate.snippet` | — | As locally. |
| `nginx-control.vhost.http_to_https_auto` | — | As locally. |
| `nginx-control.vhost.server.snippet<NN>` | — | As locally. |
| `nginx-control.vhost.location<NN>` | — | Location path. |
| `nginx-control.vhost.location<NN>.target` | — | Target `scheme://host:port` **directly reachable from the agent's host** (never a Docker container name alone — no shared network with nginx in this mode). **Main** form here (unlike locally where `.proxy_pass` is historical). |
| `nginx-control.vhost.location<NN>.snippet<MM>` | — | As locally. |
| `nginx-control.vhost.location<NN>.monitor.enable` | `true` (**opt-out** per location) | ⚠️ **Name inverted compared to local**: here you disable a specific location with `monitor.enable=false` (equivalent of `location<NN>.monitor.ignore=true` locally) — same end effect, different label and polarity. |
| `nginx-control.monitor.enable` | `false` (**opt-in**, at the vhost level) | ⚠️ **Not under `.vhost.`** unlike local (`nginx-control.vhost.monitor.enable`). |
| `nginx-control.monitor.interval` | — | ⚠️ Not under `.vhost.` either. |
| `nginx-control.monitor.valid_http_code` | — | ⚠️ Same. |
| `nginx-control.diagnostic.enable` | `true` (**opt-out**) | ⚠️ Not under `.vhost.` either. |
| `nginx-control.vhost.analyze.enable` | `true` (**opt-out**) | Here under `.vhost.`, as locally. |
| `nginx-control.vhost.analyze.ignore_rules` | — | As locally. |
| `nginx-control.publish` | all targets (`all`) | Multi-master routing: `dmz,lan` limits this vhost to the named targets. No effect if a single target/master is used. |

### ⚠️ Divergences never to confuse between the two tables

1. **`.proxy_pass` vs `.target`**: both accept both forms (alias, `.target` takes priority) — the **only identical point** between the two schemes.
2. **`.vhost.` prefix for monitor/diagnostic**: present locally (`nginx-control.vhost.monitor.enable`), **absent** on the remote agent side (`nginx-control.monitor.enable`, without `.vhost.`). `analyze.*` stays under `.vhost.` on both sides.
3. **Per-location exclusion label**: local = `location<NN>.monitor.ignore` (`true` = excluded, default `false`); remote agent = `location<NN>.monitor.enable` (`false` = excluded, default `true`) — **different names, inverted polarity, but same end result** (a location not monitored while the rest of the vhost is).
4. **`nginx-control.network`**: required locally, **does not exist** on the remote agent side (no shared Docker network between two different hosts).
5. **`mode` / `relay_scheme` / `publish`**: **exist only** on the remote agent side — no local equivalent (local auto-config only knows one routing mode, since nginx and the containers already share the same host/network).
6. **`upstream_group`**: **exists only** locally — no documented equivalent on the remote agent side to date.

### Routing modes (remote agent only)

- **`direct`** (default): nginx connects directly to the `.target` — requires that the nginx host can reach the remote host on that port (VPN, private network, public IP...).
- **`tunnel`**: the agent opens an outbound WebSocket connection to the dashboard (`GET /api/agent/tunnel`) and stays connected; no inbound port needs to be opened on the remote host (useful behind a NAT without a public IP). Only one active tunnel connection per agent.
- **`relay`**: a single fixed port (or two, HTTP/HTTPS) exposed by the agent; routing between vhosts is done by `server_name` (longest prefix), with full HTTP streaming — a compromise between `direct` (one port per target) and `tunnel` (one JSON hop per request). `relay_scheme` then indicates which relay port (HTTP or HTTPS) serves this vhost.
