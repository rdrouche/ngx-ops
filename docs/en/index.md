# Nginx reverse proxy with a web interface

## About NGX Ops

**Nginx, without compromise.**

This Docker stack provides a ready-to-use Nginx environment to deploy and administer a reverse proxy while keeping the philosophy and the native configuration of Nginx.

The goal of the project is simple: **make Nginx easier to operate without adding a new layer of abstraction**.

Unlike some reverse proxy solutions that impose their own syntax, conventions or way of declaring services, this stack uses the Nginx configuration files directly.

If you know how to configure Nginx, you already know how to use this stack.

```text
nginx/config/
├── conf.d/
├── sites/
├── snippets/
└── streams/
```

Your existing Nginx configurations can therefore be reused directly, with only a few adjustments if needed.

But the stack is more than an Nginx container. Around the engine, it adds a set of tools that simplify day-to-day administration:

* dashboard and monitoring;
* viewing and managing configurations;
* real-time log viewing;
* certificate management;
* configuration backups;
* Nginx validation and reload;
* cache management;
* Git / GitOps deployment;
* CrowdSec integration;
* advanced log analysis;
* ModSecurity and Coraza integration;
* GoAccess statistics;
* DNS management with GoDNS;
* Let's Encrypt certificate generation.

The approach is deliberately **modular**: the core of the stack remains a classic Nginx, and additional features can be added as needed.

### The principle

**Nginx stays the engine. The stack takes care of the rest.**

You keep the power and flexibility of Nginx, including directives such as `map`, `limit_req`, `proxy_cache`, GeoIP and the many possibilities of native configuration.

The goal is therefore not to replace Nginx with a new solution, but to provide **a complete environment around Nginx to ease its deployment, administration, monitoring and integration with other tools.**

## The components of the suite

The core of the stack is an Nginx and its dashboard. Around it, optional components add log analysis, protection, remote server management, supervision of several installations and log retention: the analyzer, the emulated WAF, the challenge, the agent, the Hub and the log store. Each one can be used on its own.

See [Suite architecture](architecture.md) for roles and flows, and [Versions and updates](versions.md) for the single version number of the suite.

## How Nginx is used

The goal of this stack, and of the Nginx part in particular, is to keep a configuration as close as possible to a classic use of Nginx.

The idea is not to impose a new configuration convention, as some "packaged" reverse proxy solutions do, which require learning a specific syntax or organization.

This makes adoption much simpler: if you already have Nginx configurations, they should work directly, or need only minor adjustments to fit into the stack.

It also lets you keep using all the native features of Nginx, which can sometimes be limited or harder to reach with other reverse proxy solutions.

You can notably keep using:

- the file cache;
- rate limiting with the `limit_req` and `limit_conn` directives;
- GeoIP;
- `map` directives to build dynamic configuration rules;
- and more generally the many directives natively available in Nginx.

The choice was therefore not to hide Nginx behind an abstraction layer, but to keep all its flexibility while simplifying its deployment and operation.

All Nginx configuration files are in the `nginx/config` directory.

The configuration is organized in several directories to keep a clear structure:

- conf.d: general Nginx configuration, loaded in the `http { }` context
- sites: configurations of the various sites and virtual hosts
- snippets: reusable configuration fragments
- streams: configurations for TCP/UDP connections

For a file to be loaded automatically in the Nginx configuration, it must have the `.conf` extension.

This convention also makes it easy to disable a configuration without deleting the file. Just change its extension, for example:

```
site.conf
```

becomes:

```
site.conf.DISABLE
```

Nginx no longer loads the file, and the configuration can be kept and re-enabled later by simply giving it the `.conf` extension again.

## The Nginx images

To configure your reverse proxy, three Docker images are available, depending on the features you need:

- Standard Nginx: based on the stable Nginx version (1.30.6);
- Nginx with ModSecurity: adds WAF features to Nginx (1.30.6-waf);
- Nginx with Coraza: integrates the next-generation Coraza WAF (1.30.6-coraza). This version is currently considered experimental.

The images follow the stable version published by nginx.org: the number above is the one at the time of writing and changes with updates. The exact tag is in the `sample.env` file of the stack.

The behavior and configuration of Nginx are the same whichever image you use. The choice of image only enables or not the WAF features you need.

For a classic reverse proxy use, the standard Nginx image is enough. If you want to add a WAF protection layer, you can use the ModSecurity version or try Coraza.
