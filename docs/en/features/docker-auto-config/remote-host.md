# Docker auto-configuration with labels on remote hosts

Docker auto-configuration can also be used with containers on **remote hosts**.

In this case, **NGX Ops** cannot directly access the remote host's Docker socket. A lightweight agent, written in Go, is therefore installed on each Docker host to communicate with **NGX Ops** and send it the information about the containers to publish.

This setup also lets you choose how Nginx communicates with the remote applications.

Three communication modes are available:

* **direct**: the default mode. Nginx connects directly to the target defined in the `target` label. The Nginx host must therefore be able to reach the remote host directly on the port used;
* **tunnel**: the agent opens an outbound WebSocket connection to **NGX Ops**. No inbound connection is needed on the remote host, which notably allows publishing containers located behind a NAT;
* **relay**: the agent exposes one or two fixed ports that let Nginx reach the different published VHosts. Routing is then done by `server_name`. This mode is a compromise between **direct** mode and **tunnel** mode.

For **relay** mode, the `relay_scheme` label indicates whether the VHost must use the HTTP or HTTPS relay.

## Enable the feature in NGX Ops

Go to **ADMINISTRATION → Configuration**, then select the **Remote Docker hosts (agent)** tab.

Add the following configuration then click **Save**:

```yaml
enable: true
offline_after_sec: 90
max_vhosts_per_agent: 50
tunnel_enable: false
certbot_retry_minutes: 15
```

Then refresh the **NGX Ops** interface with the **F5** key.

The **INTEGRATIONS → Remote hosts** menu is then available.

## Deploy the agent

On the remote Docker host, create a folder to store the agent's files.

Then create the `compose.yml` file:

```yaml
services:
  nginx-control-agent:
    image: forge.rdr-it.com/ngx-ops/ngx-ops/ngx-ops-agent:nightly
    container_name: nginx-control-agent
    restart: ${AGENT_RESTART_POLICY:-always}

    networks:
      - proxy-relay

    environment:
      - DASHBOARD_URL=${DASHBOARD_URL:-}
      - AGENT_HOSTNAME=${AGENT_HOSTNAME:-}
      - AGENT_FINGERPRINT=${AGENT_FINGERPRINT:-}
      - TOKEN_FILE=/data/token
      - STATE_FILE=/data/nginx-control-agent-state.json
      - DOCKER_SOCKET=/var/run/docker.sock
      - POLL_INTERVAL=${POLL_INTERVAL:-30s}
      - INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY:-false}
      - TUNNEL_ENABLE=${TUNNEL_ENABLE:-true}
      - RELAY_HTTP_LISTEN=${RELAY_HTTP_LISTEN:-}
      - RELAY_HTTP_ADVERTISE=${RELAY_HTTP_ADVERTISE:-}
      - RELAY_HTTPS_LISTEN=${RELAY_HTTPS_LISTEN:-}
      - RELAY_HTTPS_ADVERTISE=${RELAY_HTTPS_ADVERTISE:-}
      - RELAY_HTTPS_CERT=${RELAY_HTTPS_CERT:-}
      - RELAY_HTTPS_KEY=${RELAY_HTTPS_KEY:-}
      - RELAY_BACKEND_INSECURE_SKIP_VERIFY=${RELAY_BACKEND_INSECURE_SKIP_VERIFY:-false}
      - TARGETS_FILE=${TARGETS_FILE:-}

    ports:
      - "${RELAY_HTTP_HOST_PORT:-8080}:8080"
      - "${RELAY_HTTPS_HOST_PORT:-8443}:8443"

    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/data

networks:
  proxy-relay:
    name: proxy-relay
    driver: bridge
```

Then create the `.env` file:

```text
DASHBOARD_URL=http://ip-nginx-control:3000
AGENT_HOSTNAME=remote-host
AGENT_FINGERPRINT=remote-host

POLL_INTERVAL=30s
INSECURE_SKIP_VERIFY=false
TUNNEL_ENABLE=true
AGENT_RESTART_POLICY=always

RELAY_HTTP_LISTEN=8080
RELAY_HTTPS_LISTEN=8443

RELAY_HTTP_HOST_PORT=8080
RELAY_HTTPS_HOST_PORT=8443

RELAY_HTTP_ADVERTISE=http://ip-host-agent:8080
RELAY_HTTPS_ADVERTISE=http://ip-host-agent:8443

RELAY_HTTPS_CERT=
RELAY_HTTPS_KEY=

RELAY_BACKEND_INSECURE_SKIP_VERIFY=false

# TARGETS_FILE=
```

### First connection of the agent

Start the agent a first time:

```bash
docker compose up -d
```

The agent then appears in **NGX Ops** and must be approved.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-044-remote.png" width="800" />

Once the agent is approved, **NGX Ops** displays a token used to authenticate the agent.

> The token is only displayed once. Keep it before continuing the configuration.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-045-remote.png" width="800" />

On the remote host, then stop the agent:

```bash
docker compose down
```

In the `./data/` folder, create the `token` file and add the token provided by **NGX Ops**.

Then restart the agent:

```bash
docker compose up -d
```

The agent is now registered and appears **Online** in **NGX Ops**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-046-remote.png" width="800" />

## Auto-configuration examples

### Direct mode

In this mode, Nginx connects directly to the target defined in `target`.

The host running Nginx must therefore be able to reach the remote application directly.

```yaml
services:
  web3:
    image: nginx:alpine
    container_name: simple_nginx3
    ports:
      - "8889:80"
    restart: always
    networks:
      - proxy-relay
    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.mode=direct"
      - "nginx-control.vhost.server_name=test-03.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.target=http://ip-remote-host:8889"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  proxy-relay:
    external: true
```

### Relay mode

In this mode, Nginx goes through the agent.

```yaml
services:
  web2:
    image: nginx:alpine
    container_name: simple_nginx2
    restart: always
    networks:
      - proxy-relay
    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.mode=relay"
      - "nginx-control.vhost.server_name=test-02.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.target=http://web2:80"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  proxy-relay:
    external: true
```

Once the container is detected by the agent, the VHost appears in **INTEGRATIONS → Remote hosts**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-047-remote.png" width="800" />

The generated Nginx configuration can also be viewed from this interface.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-048-remote.png" width="800" />

VHosts are thus generated automatically from the Docker labels present on the remote host's containers.

For details on the modes, the relay and the agent options, see [Remote agents: modes and options](agent-modes.md).
