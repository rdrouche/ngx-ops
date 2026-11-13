# Security

NGX Ops adds several protection layers to Nginx. They are **independent** and enabled one by one: you can use only the blocklists, or combine everything.

| Layer | Role | Acts |
|---|---|---|
| [Log analysis](../logs/analysis.md) | Detects brute force, scans, floods, scraping and traffic anomalies, with built-in rules and your own | After the request |
| [Emulated WAF](waf-emule.md) | Replays logs through a rule engine (Coraza and OWASP CRS) to spot application attacks | After the request |
| [IP blocklists](blocklist-ips.md) | Applies in Nginx external IP lists, or lists produced by analysis and the emulated WAF | Before the request, for listed IPs |
| [HTTP challenge](challenge-http.md) | Asks the visitor for a proof of work in their browser | Before the request |
| [CrowdSec](crowdsec.md) | Shows the decisions of the CrowdSec engine and lets you ban or unban | Depending on the CrowdSec setup |
| [Intelligence](intelligence.md) | Shares alerts with a central platform and fetches reputation lists | Feeds the lists |
| [Nginx WAF](../../appendices/nginx-waf.md) | ModSecurity or Coraza built into Nginx, inline | During the request |

## How the layers chain

```text
Nginx logs ─▶ Analyzer ──alerts──▶ "analyzer" list ─┐
          └─▶ Emulated WAF ─scores──▶ waf-challenge, waf-block lists ─┤
                                                    ├─▶ IP blocklists ─▶ Nginx: 403 deny, 444 drop, or challenge
external lists, Intelligence lists ─────────────────┘
```

1. Analysis and the emulated WAF **read the logs** and detect a behavior.
2. Depending on the chosen remediation, the IP is added to a list.
3. **IP blocklists** publishes the lists in an Nginx configuration. The action is a `403` deny, a `444` connection drop, or a [challenge](challenge-http.md).

Analysis and the emulated WAF work **after the fact**: they do not block the request they detect, they protect the following requests from the same address. To block during the request, you need a WAF inside Nginx, see the appendix [Use a WAF version of Nginx](../../appendices/nginx-waf.md).

## Protect a vhost selectively

Comments in the `server` block of a vhost let you turn off or adjust these protections vhost by vhost: analysis disabled, ignored rules, remediation disabled, diagnostics turned off. See [Log analysis](../logs/analysis.md#customize-rule-application-per-virtual-host).

## Vhost audit

The **Diagnostic** page audits the configuration of each vhost (security headers, static configuration, live analysis of response headers). See [Diagnostic](../diagnostics.md).
