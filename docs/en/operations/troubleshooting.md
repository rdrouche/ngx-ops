# Troubleshooting

This page lists common symptoms, their probable cause and the action to take. It is limited to cases documented in NGX Ops behavior.

## Installation and dashboard

| Symptom | Cause | Action |
| ------- | ----- | ------ |
| The CrowdSec page stays empty or "not available" | The NGX Ops container cannot reach CrowdSec | Connect the container to CrowdSec's Docker network (see [CrowdSec](../features/security/crowdsec.md)) |
| Challenge statistics are empty | The dashboard cannot reach the challenge container | Put them on the same Docker network; the challenge image must be up to date |
| The first Git clone fails | An interrupted temporary folder remains in the Git workspace | NGX Ops cleans known folders; otherwise it names what remains, to delete manually |
| Online editing or local restoration is refused | Git is configured: the repository is the source of truth | Change the repository then deploy; `git revert` to go back |
| `challenge_*` settings are not taken into account | The Nginx configuration was not regenerated | Use **Regenerate and reload Nginx** from the HTTP challenge page |
| Webhooks disappear after a restart | They are only kept in memory | Recreate them, see [REST API and webhooks](../dashboard/api.md) |

## Backups

| Symptom | Cause | Action |
| ------- | ----- | ------ |
| S3 archives disappear | Rotation deletes old `.zip` files in the prefix | Use a dedicated prefix; adjust `s3_keep` |
| Unreadable `.ngxb` archive | Wrong passphrase or tampered archive | Check the passphrase variable (`HUB_`, `S3_` or `BACKUP_`); no recovery without it |
| Three copies at each change | `auto_local`, `auto_git` and `auto_s3` are all active | Choose a single automatic destination |

## Logging

| Symptom | Cause | Action |
| ------- | ----- | ------ |
| The log store refuses to start | `pseudonymized` mode without `LOGSTORE_PSEUDO_KEY`, or `LOGSTORE_REQUIRE_TIMESCALE=true` without TimescaleDB | Provide the key (32 characters minimum) or a TimescaleDB database |
| The shipper no longer sends | `write` token refused, or log store unreachable | See the shipper's `GET /status`; access logs are caught up on return, the buffer is capped |
| Access lines are missing after a rotation | Rotation by renaming to a name outside the pattern | Use `copytruncate`, or a name that matches the pattern |
| Decisions are missing | The shipper was stopped: they are not replayed | Accepted behavior; keep the shipper started |
| A statistic times out | Period too long on a large volume (15 s timeout) | Reduce the period, see [Log store capacity](../features/logs/log-store-capacity.md) |

## Hub

| Symptom | Cause | Action |
| ------- | ----- | ------ |
| Instance "Offline" | 3 consecutive collection failures | Check the HTTPS URL, the certificate, `HUB_TOKEN_SHA256` on the dashboard side |
| Instance refused on a private network | Protection against requests to internal destinations | Set `security.allow_private_networks` or `allowed_cidrs` |
| Tokens and MFA unreadable after a restore | `HUB_SECRET_KEY` lost or different | Restore the original key along with `/data` |
| `admin` password lost | — | `docker compose exec hub node bin/hub-admin.js set-password admin --must-change` |
| The archive does not open in the browser | HTTPS (or `localhost`) required, or wrong passphrase | Switch to HTTPS; use `ngxb-decrypt.js` as a fallback |

## Remote agents

| Symptom | Cause | Action |
| ------- | ----- | ------ |
| The agent does not start | `--relay-*-advertise` is a bare port number | Give the full address, for example `http://10.0.5.9:8080` |
| 502 error in relay mode to an HTTPS service | Self-signed certificate refused by the agent | Enable `RELAY_BACKEND_INSECURE_SKIP_VERIFY=true` |
| The token is no longer displayed | It is only shown once | Regenerate the token from the Remote hosts page |
| WebSocket or SSE does not go through | Tunnel mode: not supported | Switch the vhost to `relay` mode |

To understand the state of a virtual host, the [Diagnostics](../features/diagnostics.md) page tests its backends and shows its configuration. The state of each component is visible through [Health and Redis](../dashboard/health.md).
