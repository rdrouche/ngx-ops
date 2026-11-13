# Backups

NGX Ops backs up the Nginx configuration: `sites/`, `conf/`, `snippets/`, `streams/`, `ssl/` and the Let's Encrypt certificates (`certs/live/`). A backup can be made on demand from the **Backups** page, by a [scheduled task](scheduler.md), or automatically before a configuration change and before a deployment.

## Destinations

| Mode | Local ZIP | Git push | S3 |
| ---- | :-------: | :------: | :-: |
| Local only | ✓ | | |
| Git only | | ✓ | |
| Local + Git | ✓ | ✓ | |
| S3 only | | | ✓ |
| Local + Git + S3 | ✓ | ✓ | ✓ |

Local ZIPs are rotated automatically: `BACKUP_KEEP` sets the number kept (20 by default).

The Git push uses the repository configured for [Git deployment](../features/git.md), in the branch dedicated to backups (`backup` by default), with a timestamped tag.

## S3 destination

It is configured in **Configuration → Backups (S3, automatic targets)**, `backup.yml` file, without restart. It works with AWS, MinIO, Scaleway, OVH and Ceph. Signing is built in, with no dependency. HTTPS is mandatory, unless `s3_allow_insecure: true` (private network or test).

| Key | Role |
| --- | ---- |
| `s3_enable` | Enables the destination |
| `s3_endpoint`, `s3_region`, `s3_bucket` | Service, region and bucket |
| `s3_prefix` | Bucket folder (`ngx-ops/` by default) |
| `s3_path_style` | `true` for MinIO, Ceph and most S3-compatible services; `false` for AWS in virtual-host mode |
| `s3_keep` | Backups kept in the bucket, per family (30; `0` disables rotation) |
| `s3_timeout_s` | Request timeout (60) |

**Credentials**: preferably set `BACKUP_S3_ACCESS_KEY` and `BACKUP_S3_SECRET_KEY` in the container environment; they win over the file. The minimum rights are `s3:PutObject`, `s3:ListBucket` and `s3:DeleteObject` on the prefix.

!!! warning "Dedicated prefix"
    Remote rotation deletes old `.zip` and `*_ngxops.*` files in the prefix. Use a folder reserved for NGX Ops backups.

The **S3 destination** card of the Backups page lists the bucket content and tests the connection.

!!! info "Restoring from S3"
    NGX Ops does not restore from S3: download the archive with your S3 tools.

### NGX Ops configuration files

`s3_include_ngxops: true` also sends a `<date>_<label>_ngxops.tar.gz` archive of the `config/*.yml` files. Secrets (tokens, keys) are **excluded** by default.

`s3_include_secrets: true` includes them, but requires a passphrase (`S3_BACKUP_PASSPHRASE` or the `BACKUP_PASSPHRASE` fallback): the archive is then encrypted in the `.ngxb` format.

## Passphrases

One passphrase per feature, so as not to mix services deployed separately:

| Variable | Used for |
| -------- | -------- |
| `HUB_BACKUP_PASSPHRASE` | Backups sent to the [Hub](../hub/backups.md) |
| `S3_BACKUP_PASSPHRASE` | Encrypted S3 archives |
| `BACKUP_PASSPHRASE` | Common fallback when the specific variable is absent |

There is no crossover: the Hub passphrase is never used for S3, nor the reverse.

!!! danger "Keep passphrases outside NGX Ops"
    An encrypted archive whose passphrase is lost is unrecoverable.

## Open an encrypted archive

A `.ngxb` archive (NGXB1 format, AES-256-GCM) is decrypted with the dashboard's `tools/ngxb-decrypt.js` tool (Node 16 or later, no dependency):

```bash
HUB_BACKUP_PASSPHRASE='my passphrase' node ngxb-decrypt.js backup.ngxb output.tar.gz --extract ./folder
```

The passphrase is read from `HUB_BACKUP_PASSPHRASE`, `S3_BACKUP_PASSPHRASE` or `BACKUP_PASSPHRASE`, or from standard input: never as an argument, so it does not appear in `ps` or the shell history. A wrong passphrase or a tampered archive causes an error and nothing is written. For Hub archives, the **Open** button does this in the browser.

## Automatic backup

Without any of the `auto_local`, `auto_git` and `auto_s3` keys in `backup.yml`, the historical behavior applies: local ZIP, plus Git during a Git deployment. As soon as one of these keys is present, they apply everywhere, and those that are absent default to: local `true`, Git `false`, S3 `false`.

Choose a single destination type (S3 only, for example) to avoid storing three copies at each change.

## Restoration

!!! warning "With Git configured"
    As long as Git is configured, restoring a local backup is refused, and the button disappears: the repository is the source of truth. To go back, use a `git revert` followed by a redeployment.
