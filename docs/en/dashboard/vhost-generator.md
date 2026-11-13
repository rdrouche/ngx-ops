# Vhost generator and snippets

The generator on the **VHost Generator** page produces a complete reverse proxy configuration file from a form. **Nothing is written to disk**: you review the result, then place it in `sites/` (by hand or through [Git deployment](../features/git.md)).

## What you can set

| Option | Effect |
|---|---|
| Server names | One or more names in `server_name` |
| HTTPS | `listen 443 ssl` (or the chosen port), with the selected certificate |
| HTTP to HTTPS redirect | Adds a block on port 80 that answers `301` |
| HTTP/2 | Adds `http2 on;` |
| Access log | Automatic file named after the vhost, custom path, or no directive (for example if a snippet handles it) |
| Server and location snippets | One `include snippets/<file>;` line per chosen snippet |
| Maximum body size | `client_max_body_size` |
| Backend read timeout | `proxy_read_timeout`, 60 seconds by default |
| Free configuration | Lines added in the `server` block or in the `location` block |

## The backend

- **Classic URL**: `proxy_pass` to the entered address.
- **Docker container**: when "Docker container" is checked, the generator writes the container name, port and scheme in a variable, and adds the Docker DNS resolver. Nginx then finds the container address at each resolution, even after it is recreated.

```nginx
set $backend http://my-container:3000;
resolver 127.0.0.11 valid=30s;
```

## The certificate

The form offers three sources:

| Source | What the generator writes |
|---|---|
| `ssl-*.conf` snippets of the `snippets/` folder | `include snippets/ssl-xxx.conf;` |
| Certificates of the `ssl/` folder | `ssl_certificate` and `ssl_certificate_key` pre-filled. A pair without a key is flagged "missing key" |
| Let's Encrypt certificates of `certs/live/` | The Certbot paths |

## Drafts

Drafts are saved **in the browser**, under several names, and the generated file downloads as `.conf`. They are not shared with other users and disappear if you clear browser data.

## Snippets: metadata

A snippet can declare its metadata in comments at the top of the file, so that the generator knows how to offer it:

```nginx
# name: proxy-common
# description: Standard proxy headers
# emplacement: server,location
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
```

| Field | Values | If absent |
|---|---|---|
| `name` | Displayed label | File name without `.conf` |
| `description` | Short description | Empty |
| `emplacement` | `server`, `location` or both | `server,location` |

Snippets whose name starts with `ssl-` are automatically limited to the `server` location.
