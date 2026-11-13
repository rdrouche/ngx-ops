# Users and roles

## Accounts

Accounts are defined in the `config/users.yml` file. This file is the **source of truth**: the dashboard lists accounts and can compute a password fingerprint, but it does not rewrite this file for you. It can therefore be versioned with the rest of the configuration.

```yaml
users:
  - username: admin
    password: my-password
    role: admin
    name: Administrator
    enabled: true
```

| Field | Role |
|---|---|
| `username` | Login name |
| `password` | Clear-text password, or `sha256:<salt>:<hash>` fingerprint |
| `role` | `admin`, `operator` or `viewer` |
| `name` | Display name |
| `enabled` | `false` disables the account without deleting it |

A password written in clear text in the file is **replaced by its fingerprint at first startup**. To compute a fingerprint yourself, the `POST /api/auth/hash` route (administrators only) returns it without saving anything.

## First startup

As long as an account keeps a known example password, the dashboard:

- writes it to its logs at each startup;
- creates the `auth.default_credentials` event, visible in the log.

For the `admin` account shipped with the password `admin`, the dashboard replaces it with a random password, shown **once** in the container logs:

```bash
docker compose logs nginx-dashboard
```

If you choose the password yourself, edit `users.yml` **before** the first startup. A value other than `admin` is never replaced.

## Roles

| Permission | `admin` | `operator` | `viewer` |
|---|:---:|:---:|:---:|
| Metrics, vhosts, upstreams | ✓ | ✓ | ✓ |
| Configuration files | ✓ | ✓ | ✓ |
| Logs | ✓ | ✓ | ✓ |
| SSL certificates | ✓ | ✓ | ✓ |
| CrowdSec and GoAccess | ✓ | ✓ | ✓ |
| Test and reload Nginx | ✓ | ✓ | — |
| Git deployment and backups | ✓ | ✓ | — |
| Interactive API documentation | ✓ | — | — |
| Webhooks | ✓ | — | — |
| User management | ✓ | — | — |

The `viewer` role is read-only. The `operator` role operates Nginx without administering the dashboard.

Two internal roles exist, which match no account:

- the **API token** `API_TOKEN` authenticates with `admin` rights: keep it like an administrator password;
- **deployment tokens** (`config/deploy-tokens.yml`) and **agent tokens** only open a few specific routes, not the rest of the API. See [GitOps](../features/git.md).

## Sessions and brute-force protection

| Setting | Default | Effect |
|---|---|---|
| `SESSION_TTL_HOURS` | 8 | Session duration, renewed while the user is active |
| `SESSION_MAX_HOURS` | 24 | Absolute maximum duration, even with continuous activity |
| `LOGIN_MAX_ATTEMPTS` | 10 | Failed logins tolerated |
| `LOGIN_WINDOW_MIN` | 15 | Window for counting failures, in minutes |
| `LOGIN_LOCKOUT_MIN` | 15 | Lockout duration, in minutes |

Behind a reverse proxy, `TRUSTED_PROXIES` tells which addresses may set `X-Forwarded-For`: without it, the lockout would apply to the proxy address instead of the visitor's.

The **Users** page also shows active sessions, for administrators.

Two-step authentication is described in [MFA](mfa.md).
