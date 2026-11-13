# Log analysis (experimental)

Viewing Nginx logs is useful, but being able to run an **automatic analysis** of them goes further by detecting potentially abnormal behavior.

This is the goal of this **NGX Ops** feature, which relies on **Analyzer Agent (AA)** to analyze logs and detect different types of behavior.

The analysis notably lets you:

* run a **volumetric analysis per virtual host**, to detect an abnormal increase in traffic that could, for example, signal a denial-of-service attack;
* run a **traffic analysis per country**, to detect unusual variations;
* use a **rules engine** to detect various unwanted behaviors;
* get statistics on the type of visitors (**humans / robots**) from the User-Agent.

This feature requires [**Nginx Analyzer Agent**](../nginx-analyzer.md).

> **Warning:** the analysis works on logs, so **after** the requests. It detects and reports behavior; it does not block the request it detects.

Remediation is optional: a rule can feed the **analyzer** IP list of the [IP blocklists](../security/blocklist-ips.md), with a threshold, a time window, a block duration and an action (refuse, drop or [challenge](../security/challenge-http.md)). Alerts can also be shared with [Intelligence](../security/intelligence.md). In addition, **CrowdSec** remains a good option for blocking at the firewall level: see [CrowdSec](../security/crowdsec.md).

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-020-analysis.png" width="800" />

## Volumetric analysis

Volumetric analysis monitors the volume of requests received by the different virtual hosts.

It notably detects an unusual increase in the number of requests on a VHost and raises an alert when the observed behavior exceeds the thresholds defined by the analysis engine.

This analysis can notably be used to identify:

* a sudden increase in traffic;
* automated behavior;
* an attempt to saturate a service;
* a denial-of-service attack.

The analysis is performed by **Nginx Analyzer Agent**, which observes traffic to establish a baseline of usual behavior and then detect significant variations.

## Unusual analysis per country

Per-country analysis tracks the geographic origin of the requests received by the different virtual hosts.

Nginx Analyzer Agent uses the available GeoIP information to determine the country of origin of IP addresses and detect unusual traffic variations.

This analysis can notably identify a sudden increase in traffic coming from a country that is usually absent or barely present on a VHost.

> This feature is an indicator and must not be considered a sufficient security method on its own. An IP address can be hidden by a VPN, a proxy or another intermediary.

## Rules engine alerts

The rules engine detects specific behavior from the Nginx logs.

It works much like the principle used by **CrowdSec**: Nginx Analyzer Agent analyzes the requests recorded in the logs and applies a set of rules to identify potentially unwanted behavior.

By default, **6 rules** are available:

* **Brute force**
* **Path scan**
* **Flood per address**
* **Content scraping**
* **Volumetric anomaly (per VHost)**
* **Volumetric anomaly (per country)**

To view the configured rules, click the **Rules** button.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-021-analysis.png" width="800" />

## Handle alerts

When a rule is triggered, an alert is generated and appears in the analysis interface.

This page notably lets you:

* **acknowledge the alert**;
* view the elements that triggered the rule;
* add an **exception for an IP address**;
* add an **exception for a virtual host**.

Exceptions notably prevent a legitimate, known behavior from regularly generating new alerts.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-022-analysis.png" width="800" />

## Add custom rules

The rules engine can be extended with your own rules.

To do so, click the **Rules** button. In the window that opens, a field lets you add custom rules in **YAML** format.

Custom rules must use an ID **greater than or equal to 100**. Lower IDs are reserved for the rules built into Nginx Analyzer Agent.

### Anatomy of a rule

A rule has the following structure:

```yaml
rules:

  - id: 101                    # required, integer >= 100 (1 to 6 reserved for built-in rules)
    name: my_rule_name         # required, letters/digits/_/- only
    description: "Free text shown in the dialog and in alerts"
    severity: medium           # low | medium | high (default: medium)
    min_matches: 10            # required, number of matches to reach
    window_minutes: 5          # sliding window in minutes (default: 5)
    scope: ip                  # optional: ip (default) or global, see below
    min_ips: 5                 # optional, with scope: global: minimum distinct IPs (default: 5)
    blocklist_remediation_type: block   # optional: block (default) or challenge
    path_hint: "regex"         # optional, applied to the request path
    ua_hint: "regex"           # optional, applied to the User-Agent
    status_in: [401, 403, 404] # optional, list of HTTP codes
    method_in: ["POST"]        # optional, list of HTTP methods
    enable: true               # optional (default: true)
```

### Campaign rules: `scope: global`

With `scope: ip` (the default value), matches are counted **IP by IP**. A distributed campaign, where each address sends only one or two requests, escapes this counting.

With `scope: global`, the matches of **all IPs** are added up within the window. The rule triggers when the total reaches `min_matches` **and** at least `min_ips` distinct addresses matched. The alert is then **single** for the campaign: it shows the number of IPs and requests, the rate, the most frequent paths and User-Agents, the breakdown of HTTP codes, sample requests and the list of IPs, which can be copied from the interface.

```yaml
- id: 102
  name: botnet_login
  severity: high
  scope: global
  min_ips: 20
  min_matches: 60
  window_minutes: 10
  path_hint: "/login"
```

The alert is raised again if the number of IPs grows by 50% or after a full window. Exceptions and per-vhost exclusion apply IP by IP before counting.

### Rule remediation

The `blocklist_remediation_type` field chooses the effect on detected addresses: `block` (refuse or drop) or `challenge` (browser verification). It is taken into account by the **analyzer** source of the [IP blocklists](../security/blocklist-ips.md).

Three other fields tune remediation, in the manner of a CrowdSec scenario: `blocklist_threshold` (number of detections), `blocklist_window_minutes` (window in minutes) and `blocklist_remediation_minutes` (block duration). Remediation is disabled by default (`blocklist_remediation: false`). Details in [IP blocklists](../security/blocklist-ips.md).

### The form and the templates

The **Rules** button opens a window with four tabs: the **built-in rules**, **My rules** (a form with a plain-language sentence and a request tester), **templates per application** (Forgejo and Gitea, GitLab, WordPress, Nextcloud, User-Agents, generic web) that you add with one click, and the **advanced mode** in YAML. YAML remains the storage format: saving from the form does not keep comments written by hand in advanced mode.

The read-only **Hosts and directives** button lists, for each vhost, the state of the `# nginx-control-…` comments: diagnostics, analysis, ignored rules, monitoring.

### Example 1: detecting a WordPress scan

The following example detects requests targeting typical WordPress paths on a site that does not use WordPress:

```yaml
rules:

  - id: 101
    name: wp_admin_probe
    description: "Probe of wp-admin/wp-login on a non-WordPress site"
    severity: high
    min_matches: 5
    window_minutes: 10
    path_hint: "wp-admin|wp-login|xmlrpc\\.php"
    enable: true
```

In this example, `path_hint` is a regular expression tested against the path of each request.

As soon as the same IP address makes **5 requests** matching one of these paths over a period of **10 minutes**, an alert is generated.

> **Possible false positive:** if the site really uses WordPress, this rule can naturally generate alerts. You can then disable it with `enable: false` or increase the value of `min_matches`.

### Example 2: suspicious User-Agent

You can also look for User-Agents typical of certain analysis or scanning tools:

```yaml
rules:

  - id: 104
    name: known_attack_tool_ua
    description: "User-agent of a known scanning/exploitation tool"
    severity: high
    min_matches: 1
    window_minutes: 5
    ua_hint: "sqlmap|nikto|dirbuster|nessus|acunetix"
    enable: true
```

Here, `min_matches: 1` means a single request is enough to trigger the alert.

Unlike a volumetric rule, there is no need to wait for several requests: the presence of a User-Agent matching one of the defined patterns is enough to trigger the rule.

> **Warning:** since the User-Agent is supplied by the client, it can easily be changed or forged. This type of rule must therefore be considered an indicator, not proof.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-023-analysis.png" width="800" />

## Customize rule application per virtual host

By default, the analysis engine is active for all virtual hosts.

You can, however:

* disable analysis completely for a VHost;
* disable some rules for a VHost;
* keep the other rules active.

This configuration is not done directly from the **NGX Ops** web interface. It is done in the VHost configuration file.

This choice is deliberate: **NGX Ops was designed with a GitOps approach**, and virtual host configuration must stay managed in the configuration files and your Git repository.

Customization is done with comments placed in the `server { ... }` block.

### Disable analysis completely

To disable analysis on a VHost, add:

```nginx
# nginx-control-analyze: off
```

Example:

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze: off

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Analysis is then disabled for this virtual host.

### Disable a rule

To disable the rule with ID `3` on a VHost, use:

```nginx
# nginx-control-analyze-ignore-rules: 3
```

Example:

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-ignore-rules: 3

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

### Disable several rules

Several IDs can be given, separated by commas.

For example, to disable rules `3` and `102`:

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-ignore-rules: 3, 102

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

This method lets you adapt the analysis engine to the specifics of each application without changing the global rules configuration.

### Disable rule remediation on a virtual host

This solution keeps the alerts on the virtual host without blocking IP addresses.

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-no-remediation: on

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

---

## Summary per VHost

The interface also provides a summary of the analysis status for each virtual host.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-024-analysis.png" width="800" />

## Statistics per country

Per-country statistics show the geographic distribution of the analyzed requests.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-025-analysis.png" width="800" />

## Statistics per VHost

Per-VHost statistics compare the activity of the different virtual hosts and track how it evolves.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-026-analysis.png" width="800" />
