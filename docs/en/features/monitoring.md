# Backend monitoring — `proxy_pass` targets

With **NGX Ops**, you can monitor the backends used by the `proxy_pass` directives of your VHosts.

Monitoring is disabled by default. It is enabled and configured directly in the VHost configuration files using specific comments.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-049-monitoring.png" width="800" />

## Enable monitoring

To enable monitoring of a VHost, add the following comments in the `server { ... }` block:

```nginx
# nginx-control-monitoring: on
# nginx-control-monitoring-interval: 60s
```

For example:

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Once the configuration is reloaded, the `proxy_pass` targets are monitored by **NGX Ops**.

Backend status tracking is available from **CONFIGURATION → Monitoring**.

## Disable monitoring on a location

By default, each `proxy_pass` present in a monitored VHost is taken into account.

In some cases, however, monitoring a specific location may be pointless. This is notably the case when a location is used to serve cached content.

To exclude a location from monitoring, add the comment:

```nginx
# nginx-control-monitoring-ignore-location: on
```

For example:

```nginx
server {
    ...

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s

    location /cache {
        # nginx-control-monitoring-ignore-location: on
    }
}
```

The `/cache` location is then not taken into account by monitoring.

## Configure valid HTTP codes

Depending on the architecture used, you may need to adapt the HTTP codes considered valid.

By default, a target is considered unavailable on timeout or **5XX** HTTP error.

Take the example of an application running in a Docker container and published by **Traefik** on a remote host.

If the application container is stopped, Traefik may return a **404** response. From an HTTP point of view, the backend therefore responds correctly, even though the application is no longer available.

You can then define the HTTP codes considered valid with:

```nginx
# nginx-control-monitoring-valid-http-code: 2xx, 3xx
```

For example:

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s
    # nginx-control-monitoring-valid-http-code: 2xx, 3xx

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

In this example, **2XX** and **3XX** responses are considered valid by monitoring.

This configuration adapts monitoring to the real behavior of your architecture, notably when the backend is itself placed behind another reverse proxy.
