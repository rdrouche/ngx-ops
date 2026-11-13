# CrowdSec

**NGX Ops** can interface with [**CrowdSec**](../../appendices/deploy-crowdsec-docker.md) to bring the information and features related to CrowdSec directly into the interface.

The integration can be done at **three levels**, depending on your needs:

* **Prometheus**: retrieves CrowdSec statistics and metrics, notably with a display equivalent to the `cscli metrics` command.
* **Bouncer**: lets NGX Ops query the CrowdSec local API to view decisions, notably the IP addresses currently blocked.
* **Machine**: lets NGX Ops interact with the CrowdSec API and notably create or delete decisions from the interface.

These three integrations can be used independently of each other.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-032-crowdsec.png" width="800" />

> **Note:** the CrowdSec integration only appears in the NGX Ops menu when a CrowdSec configuration is defined.

## Requirements

NGX Ops must be able to communicate with CrowdSec.

When CrowdSec and NGX Ops run in Docker containers on the same host, the NGX Ops container must notably be connected to the Docker network used by CrowdSec.

For example, if the CrowdSec network is an external Docker network named `crowdsec-net`, create a `compose.override.yml` file:

```yaml
services:
  ngx-ops-dashboard:   # name of the NGX Ops service in your compose
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    external: true
```

This configuration lets the NGX Ops container reach the CrowdSec container directly on its Docker network.

---

## Prometheus integration

The first integration lets NGX Ops retrieve the **metrics exposed by CrowdSec**.

It notably provides information in NGX Ops similar to that returned by:

```bash
cscli metrics
```

### Configuration

Go to: **ADMINISTRATION → Configuration → CrowdSec**

In the configuration, enter the URL of the CrowdSec Prometheus endpoint:

```yaml
prometheus_url: http://10.199.0.5:6060/
```

Adapt the IP address to your environment.

Then click **Save**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-033-crowdsec.png" width="800" />

Then refresh **NGX Ops** with the **F5** key to reload the configuration.

The CrowdSec integration is then available in the menu: **INTEGRATION → CrowdSec**

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-034-crowdsec.png" width="800" />

This first integration is enough if you only want **CrowdSec statistics** in NGX Ops.

---

## Bouncer integration to access the API

The second integration lets NGX Ops query the CrowdSec local API to notably retrieve the **decisions** made by CrowdSec.

For this, we will create a Bouncer dedicated to NGX Ops to obtain an API key.

From the CrowdSec container, run:

```bash
docker compose exec crowdsec cscli bouncers add ngx-ops
```

CrowdSec then returns an API key.

Go back to: **ADMINISTRATION → Configuration → CrowdSec**

and add the following information:

```yaml
url: http://10.199.0.5:8080/
api_key: "****************"
local_only: true
```

Adapt the URL to your environment and replace the value of `api_key` with the key returned by CrowdSec.

Click **Save**, then reload **NGX Ops** with the **F5** key.

CrowdSec decisions are now available from the **CrowdSec** page of NGX Ops.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-035-crowdsec.png" width="800" />

> **Note:** the API used here only returns the **first 100 decisions**.

This integration gives NGX Ops visibility on the decisions made by CrowdSec, but does not yet let NGX Ops change those decisions.

---

## Machine integration to act on the API

The third integration goes further.

NGX Ops can be declared as a **CrowdSec Machine** to interact with the API and notably **add or delete decisions**.

This integration is particularly useful when an IP address detected by the NGX Ops analysis rules must be blocked directly in CrowdSec.

### Create the CrowdSec Machine

From the CrowdSec container, run:

```bash
docker compose exec crowdsec cscli machines add ngx-ops --auto --file /etc/crowdsec/lapi_api_cred_ngx_ops.yaml
```

This command creates the credentials that let NGX Ops authenticate to the CrowdSec API as a Machine.

The file containing the credentials is:

```text
/etc/crowdsec/lapi_api_cred_ngx_ops.yaml
```

In our example, this file corresponds on the host to the path:

```text
./crowdsec/config/lapi_api_cred_ngx_ops.yaml
```

Open this file and get the password generated for the Machine `ngx-ops`.

### Configure NGX Ops

Go back to: **ADMINISTRATION → Configuration → CrowdSec**

and add the following information:

```yaml
machine_id: ngx-ops
machine_password: "*******"
```

Click **Save**, then reload **NGX Ops** with the **F5** key.

NGX Ops now has the rights needed to interact with CrowdSec decisions.

It notably becomes possible to **block an IP address directly from NGX Ops**, by creating a CrowdSec decision.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-036-crowdsec.png" width="800" />

## The three integration levels

To sum up:

| Integration    | Function                   | Rights             |
| -------------- | -------------------------- | ------------------ |
| **Prometheus** | Statistics and metrics     | Read               |
| **Bouncer**    | Viewing decisions          | Read               |
| **Machine**    | Managing decisions         | Read / write       |

The configuration therefore depends on what you want to do with CrowdSec in NGX Ops.

If you only want to view metrics, **Prometheus is enough**.

To display banned IPs and CrowdSec decisions, add the **Bouncer** integration.

Finally, if you want to let NGX Ops **create or delete CrowdSec decisions**, the **Machine** integration is required.

---

## Equivalent environment variables

Each key of `crowdsec.yml` has a fallback Docker variable (`CROWDSEC_PROMETHEUS_URL`, `CROWDSEC_URL`, `CROWDSEC_API_KEY`, `CROWDSEC_LOCAL_ONLY`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD`). A key set in the file wins over the variable. Secrets (`api_key`, `machine_password`) are never shown again once saved.

To clear a field, see [Environment variables](../../environment.md).

## Known limits

* The CrowdSec API does not expose the list of registered Bouncers or Machines: NGX Ops does not show it. Use `cscli bouncers list` or `cscli machines list` on the CrowdSec host.
* `local_only: true` hides decisions from the community list (CAPI) and keeps only local decisions.
