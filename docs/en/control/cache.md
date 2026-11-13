# Nginx cache control with NGX Ops

**NGX Ops** lets you manage the Nginx cache of virtual hosts when it is configured.

Nginx can cache responses coming from the backend server to avoid hitting it on every request. This feature is particularly useful for static files such as **JavaScript, CSS, images, fonts**, etc.

The cache thus lets you:

* reduce the number of requests sent to the backend server;
* lower the application load;
* improve response times;
* speed up delivery of frequently requested resources.

## View the cache

From the menu:

**CONTROL → Nginx Cache**

NGX Ops gives an overview of the caches configured on Nginx.

For each cache directory, the interface notably shows:

* the number of files present;
* the size taken by the cache.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-002-overview.png" width="800" />

From this page, you can:

* **clear all caches**;
* manage the different cache directories individually;
* view the space taken by each cache.

> **Note:** after a cache operation, it is recommended to reload the Nginx configuration to make sure the changes are properly taken into account.

## Configure a cache in a virtual host

Cache management by NGX Ops first requires a cache to be configured in the VHost.

### Static file cache

The following example configures a cache for a site's static resources:

```nginx
proxy_cache_path /var/cache/nginx/myvhost_static_file
    levels=1:2
    keys_zone=cache_myvhost_static_file:10m
    max_size=1g
    inactive=60m
    use_temp_path=off;

server {
    listen 80;
    server_name example.com;

    location ~* \.(?:jpg|jpeg|gif|png|ico|woff2|ttf|woff|css|js)$ {
        proxy_cache cache_myvhost_static_file;
        proxy_pass http://192.168.1.1;

        include snippets/proxy-common.conf;

        # Shows the cache status
        add_header X-Cache-Status $upstream_cache_status;

        access_log off;
        log_not_found off;
    }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

In this example, requests matching the extensions defined in the `location` block use the `cache_myvhost_static_file` cache.

The parameter:

```nginx
add_header X-Cache-Status $upstream_cache_status;
```

adds the cache status to the HTTP response. It is particularly useful to check that the cache works during setup or diagnosis.

Depending on the request, this value can notably indicate whether the response comes from the cache or had to be fetched from the backend server.

## Cache dynamic content

You can also cache content generated dynamically by the application.

Take the example of an application that generates images with a URL like this:

```text
/image.php?id=123
```

Even if the response is generated dynamically by PHP, the result can be cached by Nginx to avoid hitting the application on every request.

You can also use a separate cache for static resources.

```nginx
proxy_cache_path /var/cache/nginx/myvhost_static_file
    levels=1:2
    keys_zone=cache_myvhost_static_file:10m
    max_size=1g
    inactive=60m
    use_temp_path=off;

proxy_cache_path /var/cache/nginx/myvhost_dyna_img
    levels=1:2
    keys_zone=cache_myvhost_dyna_img:10m
    max_size=4g
    inactive=24h
    use_temp_path=off;

server {
    listen 80;
    server_name example.com;

    # Cache for dynamically generated images
    location ~ /(?:.*/)?image\.php$ {
        proxy_pass http://192.168.1.1;

        proxy_ssl_verify off;

        access_log off;
        log_not_found off;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Enable the cache
        proxy_cache cache_myvhost_dyna_img;

        # How long responses are kept
        proxy_cache_valid 200 302 24h;
        proxy_cache_valid 404 1m;

        # Ignore the cache instructions returned by the application
        proxy_ignore_headers Cache-Control Expires Set-Cookie;

        # Use the query string in the cache key
        proxy_cache_key "$scheme$request_method$host$request_uri";

        # Diagnostic header
        add_header X-Cache-Status $upstream_cache_status;
    }

    # Static file cache
    location ~* \.(?:jpg|jpeg|gif|png|ico|woff2|ttf|woff|css|js)$ {
        proxy_cache cache_myvhost_static_file;
        proxy_pass http://192.168.1.1;

        include snippets/proxy-common.conf;

        add_header X-Cache-Status $upstream_cache_status;

        access_log off;
        log_not_found off;
    }

    # Other requests
    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

In this example, two cache zones are used:

* `cache_myvhost_static_file` for static resources;
* `cache_myvhost_dyna_img` for images generated dynamically by `image.php`.

The cache key:

```nginx
proxy_cache_key "$scheme$request_method$host$request_uri";
```

notably takes the **query string** into account. Thus, `/image.php?id=123` and `/image.php?id=456` match two different entries in the cache.

> **Warning:** caching dynamic content must be done with care. Before using `proxy_ignore_headers Cache-Control Expires Set-Cookie`, check that the responses concerned can really be cached and that they contain no personalized or sensitive data.
