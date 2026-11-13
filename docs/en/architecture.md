# Suite architecture

NGX Ops is a suite of components organized around a classic Nginx. Only the **Nginx + dashboard** pair is required: all other components are optional, and each one can be used without the others.

## The components

| Component | Role | Where it runs |
|---|---|---|
| **Nginx** | The reverse proxy, with its native configuration (`conf.d`, `sites`, `snippets`, `streams`) | Main compose |
| **Dashboard** | Interface, REST API, webhooks, control of Nginx and associated containers | Main compose |
| **Analyzer** | Analyzes access logs, raises alerts, feeds the blocklists. Written in Go | Container created and managed by the dashboard |
| **Emulated WAF** | Replays logs through a rule engine, never blocking directly | Container managed by the dashboard |
| **Challenge** | Browser challenge (proof of work) for flagged IPs | Container managed by the dashboard |
| **Shipper** | Sends logs to the log store | Container managed by the dashboard |
| **Agent** | Controls a remote Nginx or Docker server from the dashboard | On each remote server |
| **Hub** | Global, read-only view of several dashboards; receives their backups | Dedicated compose |
| **Log store** | Log database (PostgreSQL and TimescaleDB) with its API | Dedicated compose |
| **Intelligence** | Central SaaS service that receives alerts, computes a reputation per IP and publishes lists | Hosted service |
| **Redis** | Keeps in-progress statistics across restarts | Main compose, `redis` profile |

The analyzer, the emulated WAF and the shipper are three programs of the same image. The challenge, certbot, the GeoIP update, error pages and GoAccess are created on demand by the dashboard through the Docker socket: they do not appear in the compose file.

## Overview

```text
                        ┌──────────── main server ──────────────────┐
 visitors ──80/443──▶   │  Nginx ◀── configuration files            │
                        │    │            ▲                          │
                        │    │ logs       │ write, test, reload      │
                        │    ▼            │                          │
                        │  Analyzer ──▶ Dashboard ──Docker socket──▶ managed containers
                        │  Emulated WAF    │   ▲                     │
                        │  Challenge       │   │                     │
                        │  Shipper         │   │                     │
                        └──────────────────┼───┼─────────────────────┘
                                           │   │
        Agent (remote host) ──manifest────▶│   │◀── Hub (read-only, polls the dashboard)
                                           │
              Shipper ──gzip batches, write token──▶ Log store ◀── read token ── Dashboard, Hub
                                           │
                    Dashboard ──alerts (option)──▶ Intelligence
```

## Who talks to whom

| Flow | Direction | Authentication |
|---|---|---|
| Dashboard → Nginx | Writes the configuration, runs `nginx -t` and reload, reads VTS statistics | Docker socket, internal network |
| Dashboard → managed containers | Create, stop, update image | Docker socket |
| Dashboard ↔ analyzer, WAF, challenge | Internal HTTP API | Internal token managed by the dashboard |
| Shipper → Log store | Compressed batches, replayable without duplicates | `write` token, TLS |
| Dashboard and Hub → Log store | Read, search, statistics | `read` token |
| Producers (WAF, challenge) → Shipper | Decisions sent over local HTTP | Shared local token |
| Agent → Dashboard | Periodic push of the remote host manifest | Token specific to each agent, HTTPS |
| Hub → Dashboard | The Hub **polls** the dashboard (pull); the reverse does not exist | `X-Hub-Token` token; the dashboard only keeps its SHA-256 fingerprint |
| Dashboard → Hub | Sends backups, only if this mode is enabled | `HUB_PUSH_TOKEN` |
| Dashboard → Intelligence | Sends analysis alerts, disabled by default | Anonymous mode, or identified mode with a token |

Secrets are never sent to the browser: the dashboard relays calls to the log store with the read token, on the server side.

## What happens when a component stops

| Stopped component | Consequence |
|---|---|
| Log store | The shipper keeps batches in a disk buffer (capped at 256 MB or 24 h) and resends them when the service returns, without duplicates |
| Shipper | Decisions emitted by the WAF and the challenge during the outage are lost; access log reading resumes where it stopped |
| Hub | No effect on dashboards |
| Intelligence | No effect on Nginx: each instance stays autonomous |
| Redis | In-progress statistics are lost when the analyzer or challenge restarts, as without Redis |
| Dashboard | Nginx keeps serving traffic with the last loaded configuration |

## Choosing what to deploy

| Need | Components |
|---|---|
| A reverse proxy with an interface | Nginx and dashboard |
| Detect and block abusive behavior | + analyzer, blocklists, challenge, emulated WAF (enabled from the dashboard) |
| Control remote servers | + agent on each server |
| Supervise several installations | + Hub |
| Keep and query logs over time | + log store (the shipper is managed by the dashboard) |
| Keep statistics after a restart | + Redis |

## One version for the whole suite

All components carry the same version number. See [Versions and updates](versions.md).
