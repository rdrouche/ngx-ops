# NGX Ops Intelligence

**NGX Ops Intelligence** is an **optional** threat-intelligence platform. It receives alerts from NGX Ops instances, correlates them, builds a reputation per IP address and publishes lists that each instance can then apply with [IP blocklists](blocklist-ips.md).

Each instance stays autonomous: if the platform is unavailable, nothing changes on the Nginx side.

!!! info "SaaS service"
    [NGX Ops Intelligence](https://intelligence.ngx-ops.net/) is a **SaaS service**: there is nothing to install on that side. This page describes how it works on the NGX Ops side, the feature remaining **disabled by default**.

## Send alerts from NGX Ops

Sending is **disabled by default**. It is configured in `config/intelligence.yml`, or with the **Configure** button of the *NGX Ops Intelligence* card on the Analysis page. The form validates the input, offers **Save and test**, and never shows the token.

### The two modes

| Mode | The instance introduces itself with | Trust on the platform side |
|---|---|---|
| `anonymous` | Its `INSTANCE_ID` alone (visible in the System page) | Low |
| `identified` | `INSTANCE_ID`, an email address and a token | Higher |

In `identified` mode, the account and the token are created on the platform (**My instances** section). The token can also come from the `INTEL_TOKEN` variable, which takes priority over the file.

```yaml
enable: true
mode: identified
api_url: "https://intelligence.example.org/api/alerts/send"
user: "you@example.org"
# token: preferably via the INTEL_TOKEN variable
```

The address must be **HTTPS**, without credentials in the URL. Its default value comes from `INTEL_API_URL`; the `api_url` key overrides it.

### What is sent

| Setting | Default | Effect |
|---|---|---|
| `exclude_rules` | `volumetric`, `country_traffic` | Rules whose alerts are not sent. Add `waf` to keep emulated WAF alerts |
| `include_rules` | empty | If set, restricts sending to these rules only |
| `min_severity` | `low` | Minimum severity: `low`, `medium` or `high` |
| `include_challenge` | `false` | Also sends the automatic blocks of the built-in challenge |
| `exclude_ips` | empty | IPs and CIDR ranges for which **no alert** is ever sent: your addresses, your monitoring, your partners |
| `backfill_hours` | `0` | `0`: future alerts only. Otherwise replays the last N hours at first send (168 at most) |

### What stays private

In all cases, the alert contains the IP, the rule, the severity and counters. The rest is your choice:

| Setting | Default | Data |
|---|---|---|
| `share_user_agents` | `true` | Observed User-Agents |
| `share_paths` | `true` | Sample of requested paths (10 at most) |
| `share_vhost` | `false` | Name of the targeted vhost |

### Cadence

| Setting | Default | Range |
|---|---|---|
| `interval_seconds` | 300 | 60 to 3600 |
| `batch_size` | 100 | 1 to 500 |
| `timeout_seconds` | 10 | 3 to 60 |

Delivery follows a cursor on the alert identifier, with replayable batches: a restart sends no duplicates.

### Behavior on error responses

| Response | Behavior |
|---|---|
| 2xx | Batch processed, the cursor advances |
| 429 | Pause until `Retry-After`, the batch is replayed as is |
| 401 or 403 | Identity refused: sending is suspended until the configuration changes |
| 413 | Batch too large: its size is halved |
| Other 4xx | Invalid batch: dropped and logged |
| 5xx, network, timeout | Retry with increasing wait |

### Connection test

A ping is sent at startup, after any file change, then periodically (`ping_enable`, `ping_interval_minutes`, 5 by default). It is skipped if a send has just succeeded. The **Test connection** button of the **System** page shows the latency, the server, the authentication and the announced limits.

### Monitoring

The **Events** page logs `intelligence.sent`, `intelligence.error`, `intelligence.recovered`, `intelligence.initialized`, `intelligence.config_error` and `intelligence.config_ok`. The card on the Analysis page shows the sending state and a preview of the next batch.

## Use the published lists

The platform publishes three lists:

| List | Content | Suggested use |
|---|---|---|
| `blocklist` | Addresses whose malicious nature is established | Blocking |
| `watchlist` | Doubtful addresses | Monitoring |
| `paranoid` | Low WAF noise (optional) | Challenge |

They are consumed like any external list of [IP blocklists](blocklist-ips.md), with one action per list:

```yaml
sources:
  - name: paranoid
    url: "https://intelligence.example.org/lists/paranoid.txt"
    action: challenge
    enable: true
```
