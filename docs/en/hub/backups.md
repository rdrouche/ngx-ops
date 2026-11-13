# Hub backups and database

## Dashboard backups

The Hub can keep the backup archives of each dashboard. In an instance's detail, the **Backups** panel (administrator) offers two methods.

### Push: the dashboard sends

1. Click **Enable sending**: the Hub shows a `HUB_PUSH_TOKEN` token **only once** (only its fingerprint is kept).
2. Set it on the dashboard side: the `hub_backup` task sends the archive to the Hub.
3. Set `server.public_base_url` so the upload URL is displayed.

Nginx must have the upload location from the `nginx/hub.conf.example` example (body up to `max_archive_mb`, no buffering).

### Pull: the Hub fetches

1. Click **Enable retrieval**: the Hub shows a fingerprint to put in `HUB_BACKUP_TOKEN_SHA256` on the dashboard side, with `backup_enable`.
2. The Hub fetches the manifest and the archive every `pull_interval_hours`, or immediately with **Fetch now**.

## Storage and retention

* Archives are stored under `/data/backups`, addressed by SHA-256: two identical archives are only stored once.
* Retention: the shorter of the duration announced by the dashboard and `backups.retention_days`.
* An **alert** is raised if no backup has been received for `alert_after_hours` (36 h by default).
* **Download** is reserved for administrators.

## Open an encrypted archive

The Hub **does not know the passphrase** of the archives. It is set on the dashboard side (`HUB_BACKUP_PASSPHRASE`, or `BACKUP_PASSPHRASE` as a fallback).

The **Open** button decrypts the archive **in the browser**: the passphrase is typed locally and is never sent to the Hub. It lets you browse the files, preview one and download a file or the whole set as `tar.gz`. HTTPS (or `localhost`) is required.

The `ngxb-decrypt.js` command-line tool, shipped with the dashboard, remains usable.

!!! info "Restoration"
    The Hub keeps archives and lets you open them, but does not restore them: restoration is done from the dashboard concerned.

## What to back up for the Hub itself

The `/data` folder (database and archives) **and** the `HUB_SECRET_KEY` master key.

## PostgreSQL (option)

SQLite is enough for dozens of instances. PostgreSQL is useful for high availability, more than 200 instances, several Hub replicas or long retention.

```bash
mkdir -p secrets && openssl rand -base64 24 > secrets/db_password && chmod 600 secrets/db_password
# config/hub.yml: storage.driver: postgres
WITH_PG=1 docker compose -f docker-compose.example.yml -f docker-compose.postgres.example.yml up -d --build
```

A ready-to-use image exists: it is the same Hub image with the `-pg` tag suffix (see [Versions and updates](../versions.md)). The password goes through `HUB_DB_PASSWORD_FILE` (Docker secret) or `HUB_DB_PASSWORD`, never through the YAML. Migrations apply by themselves at startup.

!!! warning "Migration from SQLite"
    Moving from SQLite to PostgreSQL is not automated: start from an empty database and re-register the instances.

### Maintenance

* **SQLite**: `storage.sqlite_maintenance_hours` (24 h, `0` to disable) performs the WAL checkpoint, optimization, a `VACUUM` if useful and a check. The "Database maintenance" page (administrator) shows its status.
* **PostgreSQL**: `VACUUM (ANALYZE)` of all tables every `storage.postgres.maintenance_hours` (24 h, `0` to disable; autovacuum remains active). A lock prevents two simultaneous runs with several Hubs.
