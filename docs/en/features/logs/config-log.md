# Log configuration

The first step to make use of logs in **NGX Ops** is to configure the `access.log` files of your virtual hosts.

Since **NGX Ops** uses Nginx in the standard way, you just need to add the `access_log` directive to your virtual hosts:

```nginx
access_log /var/log/nginx/<server-name>.access.log;
```

This configuration records the HTTP requests received by each virtual host in a dedicated log file.

## Optimize logs

Logs can quickly become large, notably for Internet sites that generate many requests for static files such as JavaScript, CSS, images or fonts.

To limit the volume of data to analyze, **NGX Ops** provides the [`logging-config.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/conf/logging-config.conf) file.

This file notably contains a `map` that identifies requests for static resources so they can be excluded from the logs.

Here is its content:

```nginx
# name: logging-config
# description: log format configuration and filtering
# require:
# usage:
# version: 1.0.0

# Avoids logging static files.
# To use this filter, add if=$is_not_static
# at the end of the access_log directive.

map $request_uri $is_not_static {

    # Extensions or paths to ignore
    ~*\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|otf|map)(\?|$) 0;
    ~*\/robots\.txt 0;

    # By default, the request is logged
    default 1;
}

# Support for Nginx versions from 1.29.X:
# the $server_name variable can no longer be used directly
# in some file paths.
log_format combined_vhost '$server_name $remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent"';
```

> 💡 The **`logging-config.conf`** file is in Nginx's `conf.d` folder. It is therefore loaded automatically by Nginx and the `is_not_static` and `combined_vhost` variables are available in your virtual hosts.

To use static file filtering, use the following directive:

```nginx
access_log /var/log/nginx/<server-name>.access.log combined if=$is_not_static;
```

With this configuration, only requests whose `$is_not_static` variable equals `1` are recorded. Requests for the static files defined in the `map` are therefore excluded.

## Use a common log file

If you do not want to create a separate log file for each virtual host, you can use the [`logging.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/snippets/logging.conf) snippet.

It centralizes the requests of your different virtual hosts in the file:

```text
/var/log/nginx/vhosts_access.log
```

To use it, just include the snippet in your virtual host:

```nginx
include snippets/logging.conf;
```

This approach keeps the configuration simple when you manage many virtual hosts, while giving **NGX Ops** a single log file to analyze.
