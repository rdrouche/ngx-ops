# Remote agents: modes and options

This page details how the agent installed on a remote Docker host works. For installation and approval, see [Auto-configuration with Docker on a remote host](remote-host.md).

The agent reads the `nginx-control.*` labels of the containers on its host, builds a manifest and periodically pushes it to NGX Ops with a token. A label's target (`target`, or its alias `proxy_pass`) is an address **reachable from the host that serves it**, never a container name shared with Nginx.

A container without `nginx-control.enable=true`, without `server_name` or without at least one valid location is ignored. NGX Ops revalidates the entire manifest anyway.

## Choose a mode

| Mode | Nginx reaches… | Inbound connection on the remote host | Streaming |
| ---- | -------------- | ------------------------------------- | --------- |
| `direct` (default) | directly the target of each location | One port per service | Yes |
| `relay` | a fixed agent port | One or two fixed ports | Yes, WebSocket and SSE included |
| `tunnel` | NGX Ops, which relays through an outbound tunnel | None | No |

## Tunnel mode

If at least one vhost declares `mode: tunnel`, the agent opens an **outbound** WebSocket connection to NGX Ops (with the same token) and keeps it, with automatic reconnection. NGX Ops relays each vhost request through this tunnel; the agent routes it to the location's target by longest path prefix.

It suits hosts **with no inbound port**, behind a NAT for example.

Limits:

* one request at a time per connection, bodies fully buffered;
* no WebSocket or SSE through the tunnel (`relay` mode handles them);
* only one active tunnel connection per agent;
* `--insecure-skip-verify` disables TLS verification: reserved for tests.

## Relay mode

The remote host **can** receive connections, but you want to avoid opening one port per service. The agent opens **a fixed HTTP and/or HTTPS port** and routes to the right target by host name and path. The connection is direct, with full streaming: NGX Ops is no longer in the request path.

```yaml
labels:
  nginx-control.enable: "true"
  nginx-control.vhost.server_name: "app.example.com"
  nginx-control.vhost.mode: "relay"
  nginx-control.vhost.relay_scheme: "https"   # http or https: relay used by this vhost
  nginx-control.vhost.location01: "/"
  nginx-control.vhost.location01.target: "http://127.0.0.1:8080"
```

Agent side:

```bash
./nginx-control-agent --dashboard-url https://dashboard.example.com \
  --relay-http-listen :8080 --relay-http-advertise http://203.0.113.44:8080 \
  --relay-https-listen :8443 --relay-https-advertise https://203.0.113.44:8443
```

One of the two relays is enough if you do not need to tell them apart. Without `--relay-https-cert` and `--relay-https-key`, the HTTPS relay uses a self-signed certificate generated in memory; the generated vhost then adds `proxy_ssl_verify off;`. Providing a real certificate avoids this.

### `listen` and `advertise`

The two answer different questions:

* `--relay-*-listen`: on which interface and port does the agent open its socket? This is almost always generic (`:8080`).
* `--relay-*-advertise`: at which address must **Nginx** reach the agent? A **full** address, with the scheme (`http://10.20.0.5:8080`), never a bare port number, which the agent refuses at startup.

| Situation | `listen` | `advertise` |
| --------- | -------- | ----------- |
| Docker republishes the port under another number (`8080:19000`) | `:8080` | `http://vps.example.com:19000` |
| Several interfaces, only one reachable from Nginx | `:8080` | `http://10.20.0.5:8080` |
| A load balancer is in between | `:8080` | the load balancer's public address |
| Simple deployment, one public IP | `:8080` | `http://<this IP>:8080` |

### Schemes at each hop

The three hops choose their scheme independently: client → Nginx (usually HTTPS), Nginx → agent (`relay_scheme`), agent → service (the `target` scheme). For example, an HTTP relay to a service that requires HTTPS with a self-signed certificate:

```yaml
labels:
  nginx-control.vhost.mode: "relay"
  nginx-control.vhost.relay_scheme: "http"
  nginx-control.vhost.location01.target: "https://127.0.0.1:9443"
```

By default, the agent **verifies** the certificate of an `https://` service. For a self-signed certificate, enable `--relay-backend-insecure-skip-verify` (variable `RELAY_BACKEND_INSECURE_SKIP_VERIFY=true`). This setting only concerns the last hop, agent to service.

## Location snippets in relay and tunnel

Since path routing is done on the agent side, the generated Nginx vhost only has a `location /`. A location that carries at least one snippet (`nginx-control.vhost.locationNN.snippetMM`) additionally gets its own `location <path>` block, with the same `proxy_pass` and the same headers, followed by the `include snippets/...`. Snippets of a `/` location are added in `location /`. Locations without a snippet generate no block.

## Several NGX Ops (DMZ and LAN)

A single agent can publish to several independent NGX Ops, for example a front end in a DMZ and an internal dashboard. Each NGX Ops approves the agent separately and gives it its own token.

`--targets-file` (or `TARGETS_FILE`) replaces `--dashboard-url`, `--state-file` and `--token` with a JSON file:

```json
[
  { "name": "dmz", "dashboardUrl": "https://dmz.example.com",  "stateFile": "/data/dmz-state.json", "tokenFile": "/data/dmz-token" },
  { "name": "lan", "dashboardUrl": "https://lan.internal:3000", "stateFile": "/data/lan-state.json", "tokenFile": "/data/lan-token" }
]
```

Providing both forms at the same time is a startup error. By default, a container is published to **all** targets; to restrict it:

```text
nginx-control.publish=dmz,lan
```

The `relay` mode relays and their advertised address remain **shared** between all targets. If DMZ and LAN do not reach the agent at the same address, run two agent processes.

## Agent options

Each option exists as an environment variable (useful in a container); the command-line option takes precedence.

| Option | Role | Default |
| ------ | ---- | ------- |
| `--dashboard-url` | NGX Ops URL (except with `--targets-file`) | — |
| `--targets-file` | Several targets | empty |
| `--hostname` | Name proposed at enrollment | system host name |
| `--state-file` | Local file (identifier and token) | `./nginx-control-agent-state.json` |
| `--token` / `--token-file` | Direct token, or file re-read on each cycle | — |
| `--docker-socket` | Local Docker socket | `/var/run/docker.sock` |
| `--poll-interval` | Interval between two sends | `30s` |
| `--tunnel` | Enables the tunnel client if needed | `true` |
| `--relay-http-listen` / `--relay-http-advertise` | HTTP relay | disabled |
| `--relay-https-listen` / `--relay-https-advertise` | HTTPS relay | disabled |
| `--relay-https-cert` / `--relay-https-key` | HTTPS relay certificate | self-signed |
| `--relay-backend-insecure-skip-verify` | Do not verify an HTTPS service's certificate | `false` |

### Token: file or variable

* `TOKEN_FILE` (default choice): the token does not go through the environment and its rotation requires **no restart**.
* `TOKEN`: convenient with a secrets vault that injects variables, but visible to anything that reads the container environment; a change requires recreating the container. If both are set, `TOKEN` wins.

## Host metrics

On Linux, the agent attaches to each send the host's CPU and memory usage, uptime and network throughput, shown on the **Remote hosts** page. On another system, this information is simply omitted.
