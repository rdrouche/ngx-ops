# NGX Ops

**Nginx stays the engine. NGX Ops takes care of the rest.**

[Français](README.fr.md) · [Documentation](https://docs.ngx-ops.net/en/) · [Website](https://ngx-ops.net)

NGX Ops is an open-source operations stack for **Nginx reverse proxies**: dashboard, monitoring, GitOps deployment, SSL, logs, CrowdSec and WAF. Your configuration stays **plain Nginx**, in plain files: there is no new language to learn and no lock-in. If you know how to configure Nginx, you know how to use NGX Ops.

```text
nginx/config/
├── conf.d/      # http { } context
├── sites/       # virtual hosts (rename to .conf.DISABLE to disable)
├── snippets/    # reusable fragments
└── streams/     # TCP / UDP
```

## Features

* **Dashboard**: real-time monitoring (Nginx VTS), native configuration editing, `nginx -t` and reload from the UI, vhost generator, accounts with admin, operator and viewer roles, MFA (TOTP, security key), REST API and webhooks.
* **GitOps**: pull, backup, validate in an ephemeral container, deploy, reload. Deployment can be triggered from a CI/CD pipeline with scoped tokens.
* **SSL**: Let's Encrypt (HTTP-01 and DNS-01), PEM/KEY import, dynamic DNS with GoDNS.
* **Logs**: live logs, map, anomaly detection, GoAccess statistics, optional centralized log store (PostgreSQL/TimescaleDB).
* **Security**: emulated WAF built on log analysis, IP blocklists, CrowdSec integration, browser challenge (built-in engine or Anubis), and ModSecurity or Coraza images when you need a real WAF.
* **Docker auto-configuration**: publish containers with labels, locally or on remote hosts through an agent (direct, relay or tunnel mode).
* **Multi-instance**: a read-only Hub gives a global view of several NGX Ops servers and centralizes their backups.
* **Backups**: local ZIP, Git or S3, with encrypted archives and scheduled tasks.

## Components

A single version number covers the whole suite (see [`VERSION.md`](VERSION.md)).

| Component | Folder | Role |
| --------- | ------ | ---- |
| Nginx and dashboard | `nginx-dashboard/` | Reverse proxy, web interface, API |
| Analyzer, emulated WAF, shipper | `nginx-analyzer-go/` | Log analysis, alerts, WAF, log forwarding (Go) |
| Challenge | `nginx-challenge/` | Browser challenge |
| Agent | `nginx-agent/` | Publishes the containers of a remote Docker host |
| Hub | `nginx-hub/` | Global multi-instance view and backups |
| Log store | `nginx-logstore/` | Centralized logs (PostgreSQL/TimescaleDB) and API |
| Documentation | `ngx-ops-docs/` | Documentation site (FR and EN) |
| Website | `ngx-ops-website/` | Project website |

Images are published in the registry `forge.rdr-it.com/ngx-ops/ngx-ops`. Use a numeric tag in production: the `nightly` tag is a test build.

NGX Ops Intelligence, a threat-intelligence platform, is a hosted service that is not yet open to the public. Sending alerts to it is disabled by default.

## Quick start

You need a Linux server with Docker and Docker Compose.

```bash
mkdir -p /containers/ngxops && cd /containers/ngxops
bash <(wget -qO- https://forge.rdr-it.com/ngx-ops/compose/raw/branch/main/deploy.sh) ngx-ops
cp sample.env .env
docker compose up
```

Start the first time **without `-d`**: the generated administrator password is printed in the output. Note it, stop with `Ctrl+C`, then run `docker compose up -d`. The full guide is in the [installation documentation](https://docs.ngx-ops.net/en/installation/).

## Documentation

* [Documentation](https://docs.ngx-ops.net/en/): installation, dashboard, features, Hub, operations.
* [`CHANGELOG.md`](CHANGELOG.md): history of changes.
* Each component has its own `README.md` and `CHANGELOG.md`.

## Contributing

Issues and suggestions are welcome in the repository issue tracker. Please open an issue before a large change, and keep one topic per change. The code is modular: a new feature should be added without altering existing behaviour.

## Security

Please do not report a vulnerability in a public issue. Contact the maintainer privately: [contact to be defined].

## License

[License to be defined: add a `LICENSE` file at the root of the repository.]

## Author

Created by [RDR-IT](https://rdr-it.com).
