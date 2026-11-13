# Health and optional Redis

## Dashboard health

Two routes let you supervise NGX Ops from an external tool.

| Route | Access | Content |
|---|---|---|
| `GET /health` | **Public**, no session | `{"status":"ok"}`, `"degraded"` or `"down"`. HTTP code 200 for `ok` and `degraded`, **503** for `down`. Cached for 5 seconds |
| `GET /api/health` | Session or token, metrics read permission | Status of each component |

`/api/health` returns a status for `dashboard`, `nginx`, `analyzer`, `waf`, `challenge`, `crowdsec`, `log_store`, `shipper` and `redis`, among `ok`, `degraded`, `down`, `disabled` and `unknown`. It gives no precise version, path, address or error message.

### How the global status is computed

- `down`: Nginx does not answer.
- `degraded`: an **enabled** component is down.
- A disabled component (`disabled`) or one whose state is unreadable (`unknown`) does not degrade the global status.

### Restrict access

The public route only reveals a single word, but NGX Ops adds no authentication to it. To turn it off: `HEALTH_PUBLIC=false` (the route then answers 404). To limit it to your monitoring, restrict it in the reverse proxy:

```nginx
location = /health {
    allow 10.0.0.0/8;          # internal monitoring
    allow 192.168.0.0/16;
    allow 203.0.113.10;        # external probe, replace with its address
    deny  all;
    proxy_pass http://nginx-dashboard:3000;
}
```

Behind another proxy or a CDN, the address seen by Nginx is the proxy's: use the `real_ip` module (see `cloudflare-real-ip.conf`) so that `allow` and `deny` apply to the real visitor address.

## Optional Redis

Redis is **never required**. Without `REDIS_URL`, everything works as before. When present, it keeps what is lost at each analyzer or challenge restart.

| Component | Kept in Redis | Effect |
|---|---|---|
| Analyzer | Traffic hours being aggregated (vhost, country), IP membership in blocklists and their mode | The baseline is no longer skewed by a truncated hour |
| Challenge | Hourly counters, failing IPs, ongoing automatic blocks, block history, anti-replay tokens | A restart no longer unblocks banned IPs |

### Setup

1. In `.env`, set the address and a long random password:

    ```bash
    REDIS_URL=redis://redis:6379/0
    REDIS_PASSWORD=<openssl rand -hex 32>
    ```

2. Start the service with its profile:

    ```bash
    docker compose --profile redis up -d
    ```

3. Recreate the analyzer and the challenge once, so they receive these variables.

The Redis status is shown in `GET /api/health` and the variables in the **System** page.

### Security

- Internal Docker network only: no port is published.
- Password required: the service refuses to start without it.
- The `FLUSHALL`, `FLUSHDB` and `DEBUG` commands are disabled.
- Memory capped by `REDIS_MAXMEMORY` (256 MB by default), with eviction of the oldest keys.
- No disk writes.
- Keys are prefixed by `REDIS_PREFIX`: distinguish them if several installations share the same Redis. They expire after 7 days.
