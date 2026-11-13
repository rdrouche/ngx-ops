# HTTP challenge

NGX Ops lets you set up an **HTTP challenge** to ask clients for an extra verification before allowing them to reach a protected resource.

The HTTP challenge can be used to limit automated requests, slow down malicious bots, or add a verification step before access to certain resources.

NGX Ops supports two HTTP challenge engines:

* **Builtin**: engine built into NGX Ops, running in a container managed by NGX Ops.
* **Anubis**: use of the [Anubis](https://github.com/TecharoHQ/anubis) project.

The two engines cannot be used at the same time. The engine in use is set with the `challenge_engine` parameter.

The HTTP challenge can be applied at several levels:

* manually in the configuration of a virtual host;
* on a specific `location` block;
* automatically as the **remediation of an IP blocklist**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-001-challenge-http.png" width="800" />

### Builtin or Anubis?

The **Builtin** engine is integrated directly into NGX Ops and notably provides statistics on HTTP challenges.

Anubis is an external solution specialized in HTTP challenges. It works differently, and NGX Ops does not have the same statistics as for the Builtin engine.

With the Builtin engine, statistics are available directly from **NGX Ops → Integration → HTTP Challenge**.

---

## Enable the HTTP challenge in NGX Ops

To enable the HTTP challenge, go to:

**Administration → Configuration → HTTP Challenge**

In the configuration area, enter for example:

```yaml
challenge_enable: true
challenge_engine: builtin
enable: true
difficulty_bits: 16
```

Then click **Save**.

### Main parameters

* `challenge_enable`: enables generation of the HTTP challenge configuration in Nginx.
* `challenge_engine`: sets the engine used (`builtin` or `anubis`).
* `enable`: enables the container of the selected engine.
* `difficulty_bits`: sets the challenge difficulty for the Builtin engine.

Once the configuration is saved, go to:

**Integration → HTTP Challenge**

Then start the container.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-002-challenge-http.png" width="800" />

The container is then created and started by NGX Ops.

After it starts, click **Regenerate and reload Nginx**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-003-challenge-http.png" width="800" />

This operation generates the required configuration files and reloads Nginx to apply the new configuration.

---

## Apply the HTTP challenge to a vhost

The HTTP challenge can be enabled manually on a virtual host.

In the `server` block, add the snippet:

```nginx
include snippets/challenge-all-allowbots.conf;
```

For example:

```nginx
server {
    listen 80;
    server_name example.com;

    include snippets/challenge-all-allowbots.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

The `challenge-all-allowbots.conf` snippet applies the HTTP challenge to the whole vhost while keeping the configured behavior for **good bots**.

---

## Apply the HTTP challenge to a `location` block

You may prefer not to protect a whole site, but only some sensitive resources.

A few examples:

* login form;
* contact form;
* administration interface;
* endpoint particularly targeted by bots;
* resource needing extra protection.

### WordPress example

In this example, the HTTP challenge is applied only to `wp-login.php`.

Two files must be included:

- `challenge-location-support.conf` in the `server { ... }` block.
- `challenge-location.conf` in the `location { ... }` block where you want to enable it.

```nginx
server {
    listen 80;
    server_name wordpress.example.com;

    include snippets/challenge-location-support.conf;

    location = /wp-login.php {
        # HTTP Challenge
        include snippets/challenge-location.conf;

        proxy_pass http://192.168.1.1;
    }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

The rest of the site stays reachable normally, while requests to `wp-login.php` must go through the HTTP challenge.

---

## Use the HTTP challenge as the remediation of a blocklist

The HTTP challenge can also be used automatically as a **remediation action** when an IP address is present in a [blocklist](blocklist-ips.md).

This lets you, for example, ask a suspicious IP address for an extra verification instead of blocking it immediately.

In the blocklist configuration, enable the following parameters:

```yaml
challenge_enable: true
challenge_engine: builtin
```

When the Builtin engine is used, NGX Ops can then apply the HTTP challenge to the IP addresses concerned by the remediation.

This approach notably gives several levels of response:

1. let the request through;
2. ask for an HTTP challenge;
3. block the IP address.

---

## Available snippets

| Snippet | Who is challenged |
| ------- | ----------------- |
| `challenge-gate.conf` | Only IPs of the "challenge" list of analysis rules |
| `challenge-all.conf` | All visitors of the vhost, except exempt paths and User-Agents |
| `challenge-all-allowbots.conf` | All visitors except good indexing bots |
| `challenge-location.conf` | A `location` block (with `challenge-location-support.conf` or its `-allowbots` variant, included once in the `server`) |

Do not combine the `gate`, `all`, `allowbots` snippets or a profile with the `location` snippet in the same `server` block.

---

## Effectiveness and failing IPs

The **HTTP Challenge** page shows:

* **Effectiveness**: challenged, passed, failures, visitors without JavaScript and success rate, over 24 h, 7 days or 30 days. The dashboard must be able to reach the challenge container on the Docker network.
* **IPs failing the challenge**: the Builtin engine tracks, in memory, IPs that never manage to pass it (typically bots without JavaScript).

### Automatic blocking

With `autoblock: true` in `challenge.yml`, an IP that accumulates `autoblock_threshold` failures (30 by default) within `autoblock_window_minutes` (60) **without ever having solved** the challenge is blocked for `autoblock_hours` (24). The container immediately answers 403, then Nginx blocks the IP through a source of type `challenge` in [IP blocklists](blocklist-ips.md).

```yaml
sources:
  - name: challenge-bans
    type: challenge
    action: deny_403   # or drop_444
```

* An IP that solved the challenge at least once is never blocked (shared networks, NAT).
* The allowlist of `blocklists.yml` applies.
* The **Unblock** button lifts a block.
* Good bots (Google, Bing, Apple, Yandex, Baidu) are recognized by confirmed reverse DNS and are never counted or blocked; `goodbots_extra` lets you add more.
* These settings are read when the container is (re)created.

---

## Advanced configuration

The HTTP challenge configuration is defined in `challenge.yml`.

The available parameters depend on the engine used.

### Builtin

Example configuration:

```yaml
challenge_enable: true
challenge_engine: builtin

enable: true
difficulty_bits: 16

challenge_exempt_ua_regex: '^(forgejo-runner/|git/|docker/|buildkit/|containerd/|NGXOps)'
```

The `challenge_exempt_ua_regex` parameter excludes some User-Agents from the HTTP challenge.

In this example, requests coming notably from Forgejo Runner, Git, Docker, BuildKit, containerd and NGX Ops are exempt.

> This is particularly useful for automated services that cannot solve an HTTP challenge the way a browser does.

#### Challenge difficulty

Difficulty is controlled by `difficulty_bits`.

```yaml
difficulty_bits: 16
```

Each extra bit roughly doubles the work needed to solve the challenge.

Too high a difficulty can make the challenge very long, or even impossible to solve for a legitimate user.

It is therefore recommended to raise this value gradually according to the protection level you want.

---

### Anubis

To use Anubis, change the engine:

```yaml
challenge_enable: true
challenge_engine: anubis

enable: true

challenge_exempt_ua_regex: '^(forgejo-runner/|git/|docker/|buildkit/|containerd/|NginxControl)'

anubis_difficulty: 8
```

The `anubis_difficulty` parameter sets the difficulty used by Anubis.

Anubis-specific parameters, such as `redirect_domains` or `cookie_domain`, can also be set in `challenge.yml`.

---

## Per-vhost profiles

NGX Ops also lets you define HTTP challenge profiles specific to some vhosts.

Each profile can have its own mode and its own exemptions.

Example:

```yaml
profiles:
  - name: forgejo
    mode: allbots
    exempt_ua_regex: '^forgejo-runner/'

  - name: wiki
    mode: all
    exempt_path_regex: '^/(api/|[.]well-known/)'
```

Profiles let you notably adapt the HTTP challenge behavior to the exposed service.

A profile can be used with the following modes:

* `listed`: applies the challenge to IPs present in the relevant lists;
* `all`: applies the challenge to all requests;
* `allbots`: applies the challenge while taking good-bot handling into account.

---

## Reference `challenge.yml` file

The `challenge.yml` file centralizes the configuration of the HTTP challenge and of the container managed by NGX Ops.

```yaml
# HTTP challenge — settings and container managed from NGX Ops.
#
# Editable from "Configuration editor".
# After changing challenge_* keys, use
# "Regenerate and reload Nginx" from the HTTP Challenge page.
#
# Priority:
# NC_* variables > challenge.yml > default values.
#
# challenge_* keys take priority over those of
# blocklists.yml.

# ── Nginx ────────────────────────────────────────────────────────────────

# Enable generation of the HTTP challenge configuration.
challenge_enable: false

# Engine used:
#   builtin  → NGX Ops built-in engine
#   anubis   → Anubis engine
challenge_engine: builtin

# Address of the HTTP challenge backend.
# By default:
#   builtin → nginx-challenge:8080
#   anubis  → anubis:8923
challenge_upstream: ""

# DNS resolver used by Nginx.
challenge_resolver: 127.0.0.11

# Paths exempt from the HTTP challenge.
challenge_exempt_path_regex: '^/[.]well-known/'

# User-Agents exempt from the HTTP challenge.
challenge_exempt_ua_regex: ""

# Example:
# challenge_exempt_ua_regex: '^NGXOps$'


# ── Per-vhost profiles ──────────────────────────────────────────────────

# Lets you define a specific behavior for some vhosts.
#
# name:
#   lowercase, digits and underscore
#   30 characters maximum
#
# mode:
#   listed
#   all
#   allbots (default)
#
# A profile generates a dedicated snippet:
# snippets/challenge-<name>.conf

profiles:

  # - name: forgejo
  #   mode: allbots
  #   exempt_ua_regex: '^forgejo-runner/'

  # - name: wiki
  #   mode: all
  #   exempt_path_regex: '^/(api/|[.]well-known/)'


# ── Container managed by NGX Ops ────────────────────────────────────────

# Automatically start/recreate the container at startup.
enable: false

# Image used for the engine.
# If empty:
#   CHALLENGE_DEFAULT_IMAGE / ANUBIS_DEFAULT_IMAGE
container_image: ""

# Secret used by the engine.
# If empty, NGX Ops generates and keeps a secret automatically.
secret: ""

# Builtin engine difficulty.
#
# Supported values: 8 to 64.
#
# Each extra bit roughly doubles
# the work needed.
difficulty_bits: 16

# Validity of the Builtin engine cookie.
# Values: 1 to 720 hours.
cookie_hours: 24

# Language of the challenge page:
#   auto
#   fr
#   en
language: auto

# Allow good bots after reverse DNS verification.
goodbots: true

# Add custom good bots.
#
# Format:
# name|UA-regex|.suffix[,.suffix][;name2|...]
goodbots_extra: ""

# Anubis difficulty.
anubis_difficulty: 4

# Anubis: domains allowed for redirects.
redirect_domains: ""

# Anubis: domain used for the cookie.
cookie_domain: ""
```

> **Tip:** after changing any `challenge_*` parameter, use **Regenerate and reload Nginx** so NGX Ops regenerates the snippets and applies the new configuration.
