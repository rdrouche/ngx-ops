# Diagnostics

The **Diagnostics** feature gives a global or detailed view of a VHost.

It groups several pieces of information to quickly get an overview of the VHost's configuration and operation:

* an overview of the VHost;
* the different backends used by the `proxy_pass` directives;
* backend tests with `curl` and `curl -v`;
* security-related information;
* monitoring information when it is enabled;
* a graphical diagram of the VHost and its backends;
* the VHost configuration file.

## Overview

This section presents the general configuration information of the VHost in **NGX Ops**.

It notably gives a quick view of the VHost configuration and the elements that make it up.

## Backends

This section lets you test individually the backends used by the `proxy_pass` directives.

For each backend, **NGX Ops** runs a test using `curl`.

The `curl -v` test goes further by notably displaying the HTTP headers returned by the backend.

This lets you quickly check:

* whether the backend responds;
* the HTTP response code;
* the returned headers;
* any communication problems with the backend.

## Security

This section presents an overview of the security best practices applied to the VHost.

It notably lets you check the security headers as well as the HTTP/HTTPS links used by the VHost.

## Monitoring

When monitoring is enabled on the VHost, this section shows the supervision information associated with the backends.

It lets you find the monitoring information directly from the VHost diagnostics.

## Diagram

This section shows a graphical representation of the VHost and its backends.

It lets you quickly visualize the different `location` blocks and the targets used by the `proxy_pass` directives.

A bit of visualization in an Nginx configuration never hurts... **just fun!**

## Conf

This section directly shows the VHost configuration file.

It lets you view the configuration used by Nginx from the diagnostics, without having to look for the corresponding file manually.

## Customization flags

As with the other analysis features of **NGX Ops**, you can disable diagnostics for a VHost or for a configuration file.

### Exclude a virtual hosts file

To completely disable diagnostics for a configuration file, add the comment:

```nginx
# nginx-control-diagnostic: off

server {
    ...
}
```

### Exclude a `server` block

You can also disable diagnostics for a single `server` block:

```nginx
server {
    # nginx-control-diagnostic-vhost: off

    ...
}
```

This is notably useful when several VHosts are in the same file and some must not be analyzed.
