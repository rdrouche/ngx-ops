# REST API and webhooks

## The REST API

Everything the interface does goes through the dashboard REST API, in JSON. The **REST API** page (reserved to administrators) is its interactive documentation: routes sorted by category, with a button to try them live.

### Authenticate

| Method | Usage |
|---|---|
| Session (cookie) | The interface's one, with the rights of the user's role |
| Bearer token | `Authorization: Bearer <API_TOKEN>`, for scripts and automation |

```bash
curl -s -H "Authorization: Bearer $API_TOKEN" https://dashboard.example.com/api/health
```

- The `API_TOKEN` token stays **disabled** as long as it is empty, starts with `changeme` or is shorter than 16 characters. Generate it with `openssl rand -hex 32`, or from the **System** page.
- A valid token authenticates with **`admin`** rights. It is not subject to MFA.
- Write and administration routes should therefore be reserved to trusted scripts, on a controlled network.
- `CORS_ORIGIN` stays empty as long as no external front end calls the API: only the same origin is then accepted.

To automate a deployment from a CI, prefer a **deployment token** limited to Git and backup routes: see [GitOps](../features/git.md).

## Webhooks

Webhooks send an HTTP request to an address of your choice each time an event of the [log](notifications.md#the-event-log) is recorded. The **Webhooks** page and the `/api/webhooks` routes are reserved to administrators.

### Create a webhook

```bash
curl -s -X POST https://dashboard.example.com/api/webhooks \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example.com/ngx","events":["backup.manual","certbot_issue"],"description":"Backup alerts"}'
```

| Field | Role |
|---|---|
| `url` | Destination address, required |
| `events` | Event types to send. `["*"]` (default value) sends everything |
| `description` | Free label |
| `active` | `false` suspends sending without deleting the webhook (update) |

The test button, or `POST /api/webhooks/<id>/test`, sends a `webhook.test` event.

### What the recipient receives

A JSON `POST` request:

```json
{
  "event": "backup.manual",
  "timestamp": "2026-11-12T15:00:00.000Z",
  "data": { }
}
```

The `X-Nginx-Dashboard-Secret` header contains the **secret** `WEBHOOK_SECRET`. The recipient compares this value with the one it knows and rejects requests that do not present it. It is not a signature computed over the content: use HTTPS so the secret does not travel in clear text.

### Limits to know

- **No private networks.** The destination address is refused if it points to a local or private address (private networks, loopback, cloud provider metadata address). The check is repeated at each send, to resist a DNS resolution change. A webhook therefore cannot target an internal service.
- **No retry.** An unreachable recipient is ignored, with a 10-second timeout, and never blocks the action that triggered the event.
- **Kept in memory.** The webhook list is not saved to disk: it is emptied when the dashboard container restarts. Recreate them after a restart, from the interface or the API.
- Without `WEBHOOK_SECRET` configured, the Webhooks menu is hidden by default. See [Optional menus](interface.md#optional-menus).
