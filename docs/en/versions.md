# Versions and updates

## A single number for the whole suite

The dashboard, the analyzer, the agent, the challenge, the Hub and the log store carry **the same version number**. A version is a number and a tag: the components that carry it were validated together.

- The current number is in the `VERSION.md` file at the root of the repository.
- Each component has its own `CHANGELOG.md`. For each version, each component receives an entry, even when it says "no change".
- The root `CHANGELOG.md` is that of the dashboard and of the suite.
- The dashboard shows its version in the header and in the **System** page. The **Changelog** button of that page shows the history when `CHANGELOG_URL` is set.

## Images and their tags

Images are published in the `forge.rdr-it.com/ngx-ops/ngx-ops` registry.

| Image | Component |
|---|---|
| `ngx-ops-dashboard` | Dashboard |
| `analyzer-agent-go` | Analyzer, emulated WAF and shipper (three programs in one image) |
| `ngx-ops-challenge-http` | Browser challenge |
| `ngx-ops-agent` | Agent for remote servers |
| `ngx-ops-hub` | Hub with SQLite |
| `ngx-ops-hub` with the `-pg` suffix | Hub with PostgreSQL (for example `X.Y.Z-pg`) |
| `ngx-ops-logstore` | Log store |

The documentation is built by a separate workflow, started on demand, and is not rebuilt with the rest of the suite.

The tag is chosen at build time:

- A build can publish **several tags at once**: the version number, `stable`, `latest`, and so on. The first in the list is the main tag.
- The default tag is `nightly`. A `nightly` image is a test build, **not to be used in production**.
- The version written in the image and its labels is, in order of priority, the one requested at launch, the repository variable `NGX_OPS_VERSION`, then the main tag.
- For production, use a **numeric tag** (for example `X.Y.Z`) rather than a moving tag. You then know what is running and can roll back.

The dashboard is built with the image names of the analyzer, the emulated WAF, the challenge and the agent, **at the same tag as itself**. As long as `container_image` is not set in a YAML file of `config/`, these containers follow the dashboard version.

## Update

### Before you start

1. Read the `CHANGELOG.md` of the components involved, between your version and the new one.
2. Make a backup: **Backups** page of the dashboard, and for the Hub, the data folder **and** the master key `HUB_SECRET_KEY`.
3. Note the current tag of each image, so you can go back.

### The dashboard and Nginx

Change the tag in the `.env` file or in the compose, then:

```bash
docker compose pull
docker compose up -d
```

Containers whose image changed are recreated, the others are not touched. The `config/` folders and volumes keep your configuration and data.

### Containers managed by the dashboard

The analyzer, the emulated WAF, the challenge, the shipper, certbot, GeoIP and error pages are created by the dashboard. Each of their pages offers the **Update image** button: it pulls the configured image and **only recreates the container if the image changed**.

- With a moving tag (`latest`, `stable`), this button fetches the new image.
- With a numeric tag set in `container_image`, change that tag in the feature's YAML file, then use the button.
- A container deliberately stopped from its page is never restarted by force.

### Standalone components

The Hub and the log store each have their own compose file: change the tag of their image, then `docker compose pull` and `docker compose up -d` in their folder.

These components are independent: updating one does not require stopping the others.

- The Hub polls dashboards with a contract that only evolves by additions. A part that the dashboard does not provide yet is simply hidden in the Hub.

To keep the same consistency as the one validated at release, update all components to **the same number**.

### Roll back

Put the old tag back in the compose, then `docker compose up -d`. If the new version changed files in `config/`, restore the backup made before the update.
