# Docker auto-configuration with labels

This feature is disabled by default.

To enable it, go to **ADMINISTRATION → Configuration**, then select the **Docker auto-config (labels)** tab.

In the configuration field, enter the following configuration, then click **Save**:

```yaml
enable: true
require_approval: true
poll_interval_sec: 15
events_enable: true
events_debounce_ms: 3000
certbot_retry_minutes: 15
allowed_server_name_patterns:
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-039-autodocker.png" width="800" />

Then reload the **NGX Ops** interface with the **F5** key so the new menu is available in the navigation.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-040-autodocker.png" width="800" />

## Create a Docker container

To test auto-configuration, create a Docker container that must be connected to the **same Docker network as Nginx**. This lets Nginx reach the container directly to forward requests to it.

For example, the following `compose.yml` file creates a simple Nginx container:

```yaml
services:
  web:
    image: nginx:alpine
    container_name: simple_nginx

    # ports:
    #   - "80:80"

    # volumes:
    #   - ./html:/usr/share/nginx/html:ro

    restart: always

    networks:
      - nginx-net

    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.server_name=test-01.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.proxy_pass=http://web:80"
      - "nginx-control.network=nginx-net"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  nginx-net:
    external: true
```

The labels let **NGX Ops** determine how to publish the container:

* `nginx-control.enable=true`: enables publishing of the container;
* `nginx-control.vhost.server_name`: sets the DNS name of the VHost;
* `nginx-control.vhost.location01`: sets the first `location`;
* `nginx-control.vhost.location01.proxy_pass`: sets the traffic destination;
* `nginx-control.network`: indicates the Docker network used to communicate with the container;
* `nginx-control.vhost.server.snippet01`: adds a snippet at the `server` level.

### Publication approval

Start the container.

After a few seconds, it should appear in NGX Ops **pending approval**.

Click **Approve** to allow its publication.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-041-autodocker.png" width="800" />

Once the container is approved, the VHost is generated automatically and becomes active.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-042-autodocker.png" width="800" />

The generated configuration can be viewed from **CONFIGURATION → Conf files**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-043-autodocker.png" width="800" />

This configuration is generated automatically from the container's Docker labels. You can therefore change the publication directly from the `compose.yml` file, then let **NGX Ops** detect the changes and update the Nginx configuration.
