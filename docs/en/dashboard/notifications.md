# Notifications and events

NGX Ops has three complementary mechanisms.

| Mechanism | For whom | Content |
|---|---|---|
| **Header bell** | The signed-in operator | What deserves attention, with a level and a read or unread state |
| **Event log** | Audit | Every action, including administrative ones |
| **Email** | The configured recipients | A selection of events |

Webhooks, described in [REST API and webhooks](api.md), are triggered by the event log.

## The bell

The bell is in the header, between the language selector and the current user. It reports for example:

- a certificate that is about to expire or has expired;
- a certificate obtained, renewed or failed with Certbot;
- a supervised target that goes down, then comes back;
- abnormal behavior detected by the analyzer;
- a scheduled Nginx reload or restart, successful or failed.

Each entry has a level (`info`, `success`, `warning`, `error`) and a read or unread state. A badge shows the number of unread notifications. The browser polls the dashboard every 5 seconds by default (`NOTIF_POLL_INTERVAL_SEC`).

- The feed is **shared** between all users: the read or unread state is not specific to each one.
- All three roles can access it, including `viewer`.
- Notifications are kept for 90 days (`NOTIF_CENTER_RETENTION_DAYS`).

## The event log

The **Events** page lists actions chronologically: a container start, a manual backup, a change to an analysis rule, an MFA login, an agent approval... Each event has a type (`backup.manual`, `agents.approve`, `auth.mfa.failed`...), an author and associated data.

The log is kept for 30 days by default (`EVENTS_RETENTION_DAYS`).

## Emails

Email sending is configured in two files of `config/`. They are read again at each send: a change does not require a restart.

### The SMTP server: `smtp.yml`

```yaml
enable: true
host: smtp.example.com
port: 587
security: tls          # tls (STARTTLS), ssl (SMTPS) or plain
ignore_ssl: false      # true to accept a self-signed certificate
from: dashboard@example.com
from_name: NGX Ops
username: user@example.com
password: secret
```

Leave `username` empty if the server does not require authentication. This file contains a password: restrict its permissions and do not publish it in a Git repository.

### Events sent: `notifications.yml`

Each section can be enabled with `enable` and has its own recipient list.

| Section | Event | Settings |
|---|---|---|
| `cert_expiry` | Certificate about to expire | `days_before` (30), `urgent_days` (5) |
| `nginx_test_error` | Configuration test failure | — |
| `nginx_reload` | Nginx reload | — |
| `backup_failure` | Backup failure | — |
| `analyzer_alert` | Analyzer alert (brute force, scan, flood, volume) | — |

```yaml
cert_expiry:
  enable: true
  days_before: 30
  urgent_days: 5
  recipients:
    - admin@example.com
```
