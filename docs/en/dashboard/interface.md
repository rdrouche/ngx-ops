# Interface, menus and System page

## Dashboard pages

| Group | Pages |
|---|---|
| Monitoring | **Overview** (requests, connections, errors, traffic), **Virtual Hosts** (VTS statistics per vhost), **Upstreams** (backends and response times) |
| Configuration | **Config files** (explorer for `sites`, `conf`, `snippets`, `streams` with highlighting), **SSL Certificates**, **Live logs**, **VHost Generator** |
| Deployment and backups | **Git Deployment**, **Backups** |
| Control | **NGX Ops** (test, reload, status), **Events** (action log) |
| Diagnostics | **Diagnostic**, **Monitoring** (continuous supervision), **Schema** (graphical view of vhosts and their targets) |
| Integrations | **REST API**, **Webhooks**, **CrowdSec**, **IP Blocklists**, **GoAccess** |
| Administration | **Users**, **System** |

Some pages only appear if the matching feature is configured: CrowdSec, GoAccess, WAF, REST API, Webhooks, Docker auto-configuration, remote hosts. See [Optional menus](#optional-menus).

## Theme and language

- **Interface**: the header selector switches between the **Classic** interface (sidebar) and the **Conductor** theme (drop-down menus at the top), in **Light** or **Dark**.
- **Color**: green (default) or blue. It only changes the visual identity (logo, badges, active menu, main buttons). Status colors stay the same: green for healthy, red for a failure.
- **Language**: the interface is available in French and English, with a selector in the header.

These choices are remembered **in the browser**: they are not shared between users or between your browsers.

## Custom text in the header

`BRANDING_HEADER_TEXT` shows a free string between the "NGX Ops" name and the version badges: a customer name, an environment (`STAGING`, `PROD-EU`)... Useful to avoid mixing up several installations. When absent, nothing is shown.

```bash
BRANDING_HEADER_TEXT=Client ACME — Production
```

The links at the bottom of the menu (documentation, site, repository, support) are set with the `BRANDING_*` variables, fixed when the image is built. See [Environment variables](../environment.md).

## Collapsible menu

Each menu section (Monitoring, Configuration, Control, Integrations, Administration) collapses with a click on its header. The state is remembered per browser and per section.

## Optional menus

Some menus only make sense in some installations. They are set with an environment variable, or in `config/menu.yml`. The variable wins over the file.

| Variable | `menu.yml` key | Default | Behavior in `auto` |
|---|---|---|---|
| `MENU_WAF` | `waf_menu` | `auto` | Shown if the Nginx image tag ends with `-waf` or `-coraza` |
| `MENU_GODNS` | `godns_menu` | `show` | No `auto` mode: `show` or `hide` |
| `MENU_API` | `api_menu` | `auto` | Shown if `API_TOKEN` is configured |
| `MENU_WEBHOOKS` | `webhooks_menu` | `auto` | Shown if `WEBHOOK_SECRET` is configured |
| `MENU_DOCKER_AUTOCONFIG` | `docker_autoconfig_menu` | `auto` | Follows `enable` in `docker-autoconfig.yml` |
| `MENU_AGENTS` | `agents_menu` | `auto` | Follows `enable` in `agents.yml` |
| `MENU_GOACCESS` | `goaccess_menu` | `auto` | Shown if GoAccess sources are configured |

Possible values are `auto`, `show` and `hide`. Other entries, shown by default, can also be hidden: `sync_menu`, `vhostgen_menu`, `graph_menu`, `deploy_menu`, `blocklists_menu`, `wafemu_menu`, `geomap_menu`, `digest_menu`, `cache_menu` and `notifications_menu`, with the variables `MENU_SYNC`, `MENU_VHOSTGEN`, `MENU_GRAPH`, `MENU_DEPLOY`, `MENU_BLOCKLISTS`, `MENU_WAFEMU`, `MENU_GEOMAP`, `MENU_DIGEST`, `MENU_CACHE` and `MENU_NOTIFICATIONS`.

```yaml
# config/menu.yml
waf_menu: hide        # this instance does not use a WAF image
godns_menu: hide      # dynamic DNS never used
api_menu: hide        # REST API never used
```

Hiding a menu does not disable the feature: only the display changes. To disable a feature, use its own configuration file.

## System page

The **System** page, reserved to administrators, lists all dashboard settings: current value, default value, where to change them and an explanation. Secrets never appear in clear text: only the "configured" or "not configured" state is shown.

From this page, you can:

- generate the REST API token and the webhook secret, without editing `.env`: the value is shown **once** and only its fingerprint is kept for the API token;
- change menu visibility with the **Menu** button, which writes `config/menu.yml` and keeps its comments. A `MENU_*` variable defined in the environment locks the matching row;
- see the dashboard version and the change history with the **Changelog** button, if `CHANGELOG_URL` is set.
