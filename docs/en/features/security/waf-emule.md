# Emulated WAF

The **emulated WAF** rereads the Nginx access logs and replays each line as a synthetic request in the **Coraza v3** engine, in detection-only mode, with the **OWASP CRS** rule set. It thus spots application attacks (injections, path traversal, sensitive file probes) without touching Nginx.

!!! warning "This is not an inline WAF"
    - Analysis is done **after the fact**: the emulated WAF **never** blocks a request itself.
    - It does not see the request **body** (POST) or headers absent from the log.
    - Remediation goes through IP lists: it only protects the **following** requests from the address.

    To block inline, use an Nginx image with WAF: see [Use a WAF version of Nginx](../../appendices/nginx-waf.md).

## Enable the emulated WAF

The emulated WAF runs in an `ngx-waf` container, created and managed by the dashboard. It is a second program of the analyzer image, so there is no extra image to deploy.

1. Edit `config/waf.yml`:

    ```yaml
    enable: true
    accept_limits: true      # required: acknowledge the limits above
    host_data_path: /containers/nginx-rproxy/waf
    host_rules_path: /containers/nginx-rproxy/waf-rules
    host_logs_path: /containers/nginx-rproxy/logs
    ```

    Paths are **absolute paths on the host**.

2. Open the **Emulated WAF** page and start the container.
3. At first start, the CRS rule set is downloaded from github.com into the rules volume. The container starts even if this download fails: the error is visible on the page.

| `waf.yml` key | Default | Role |
|---|---|---|
| `enable` | `false` | Enables the feature |
| `accept_limits` | `false` | Must be `true` to start |
| `container_name` | `ngx-waf` | Container name |
| `container_image` | analyzer image | Overrides `WAF_DEFAULT_IMAGE` |
| `port` | `9101` | Port internal to the Docker network, never published |
| `host_data_path` | — | Settings and detection database |
| `host_rules_path` | — | Downloaded CRS and custom rules |
| `host_logs_path` | `HOST_LOGS` | Nginx logs, mounted read-only |
| `log_pattern` | shipped pattern | Regular expression for `combined` and `combined_vhost` logs |
| `waf_log_pattern` | shipped pattern (`*.wafemu.log`) | Regular expression for the enriched `waf_json` log |
| `crs_version` | `v4.8.0` | CRS version |
| `hit_retention_days` | `30` | Retention of detections |
| `shipper_url` | empty | Sends detections to the [log store](../logs/index.md) |

The secret shared with the container (`WAF_TOKEN`) is generated at first start. See [Environment variables](../../environment.md).

## Logs read

| Format | Detail |
|---|---|
| `combined` or `combined_vhost` | Works directly. Without a vhost prefix, you need one file per vhost |
| `waf_json` | Enriched format (`Accept`, `Content-Type`, `Origin` headers...), to write in a **separate file** `*.wafemu.log` |

The `waf_json` format gives the best results: the page's **Tips** tab provides the definition to copy into Nginx. Both logs can be active together: duplicates are discarded, and the `waf_json` line takes priority.

With a `combined` log, CRS rules that judge headers absent from the log are disabled automatically ("system rules"), to avoid false positives. Static requests excluded by `$is_not_static` are not analyzed.

## Page settings

| Setting | Detail |
|---|---|
| Mode | **Observation** (default) or **remediation**, global or per vhost |
| Paranoia level | From 1 to 4, global or per vhost. The higher it is, the more detections and false positives |
| Analyzed vhosts | All, or a selection |
| Disabled rules | Globally or per vhost |
| Exceptions | Rule, vhost and path prefix, User-Agent or IP, creatable in one click from a detection |
| Exclusions | Ignored statuses and excluded IPs. Private IPs are always ignored |
| Simulator | Shows the score, the retained rules and the suppressed ones, with the reason |

Start in **observation**: at level 2 or more, a few false positives are possible. Custom rules can be placed in the `custom/` folder of the rules volume.

## Score and IP lists

Each CRS rule adds its score according to severity: critical 5, error 4, warning 3, notice 2. Scores are added **per IP** over a 60-minute window by default, only for vhosts in remediation mode.

- At the **challenge** threshold, the IP enters the `waf-challenge` list.
- At the **block** threshold, the IP enters the `waf-block` list, for 24 h or 72 h depending on the case.

These lists are applied by [IP blocklists](blocklist-ips.md), with sources of type `waf`:

```yaml
sources:
  - name: waf-challenge
    type: waf
    list: challenge
    enable: true
  - name: waf-block
    type: waf
    list: block
    action: drop_444
    enable: true
```

`waf-challenge` requires `challenge_enable: true`: see [HTTP challenge](challenge-http.md). In the page's **Lists** tab, each IP shows whether the blocklists apply it, and the cause if not (missing source, allowlist, challenge disabled...). The **Evidence** button details the triggered rules and the latest requests.

## Alerts

A `waf` alert is created per IP and per window when the score reaches the alert threshold. A disabled rule **never sends an alert**: when read, its points are removed, and the alert disappears if the remaining score is insufficient.

These alerts are also passed to [Intelligence](intelligence.md), unless you add `waf` to `exclude_rules`.

## Diagnostic tips

The **Tips** tab reports: a log format to improve, vhosts without a log or without traffic, a missing CRS, a saturated queue (lines are then dropped), unreadable lines, an engine not ready, and remediation enabled with no blocklist or active challenge.

## Performance

Reference measurement, with CRS 4.8 at level 1 and two cores: about 2,400 lines per second, or about 0.8 ms per request. On 38 varied legitimate requests, no detection at level 1.
