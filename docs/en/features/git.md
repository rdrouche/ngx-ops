# Configuration management with Git (GitOps)

**NGX Ops** lets you use a Git repository as the **source of truth** for the Nginx configuration files.

The following elements can thus be versioned in the repository:

* `sites`
* `conf.d`
* `snippets`
* `streams`
* `ssl`

The goal is to stop treating the configuration on the Nginx server as the only reference, and to keep a reference version in Git.

This feature notably lets you:

* keep the history of changes;
* identify who made a change;
* go back to a previous version of the configuration;
* work with the usual Git tools;
* prepare and validate changes before deploying them.

> **Why this feature?**
>
> The GitOps approach is one of the reasons that motivated the development of **NGX Ops**. The goal was to manage the Nginx configuration with a Git repository and have a history of changes, while keeping control over the deployment of the configuration.

## Requirements

You need a Git repository reachable by **NGX Ops**.

A **private** repository is recommended, notably because the configuration can contain SSL certificates and their private keys (`.pem` and `.key`).

An access token for the Git repository is also required.

## Initialize your repository

The first step is to initialize the Git repository with the Nginx configuration currently in use.

To do so, you can use the **Backup** feature of **NGX Ops** to retrieve the configuration files and push them to your Git repository.

The goal is to start from the currently working configuration before setting up GitOps deployment.

## NGX Ops configuration

Go to **ADMINISTRATION → Configuration**, then select the **Git (config repo)** tab.

Enter your repository configuration then click **Save**.

For example:

```yaml
repo_url: https://forge.domain.tld/organisation/nginx-reverse-proxy-config.git

token: **********

user_name: NginxControl
user_email: nginxcontrol@domain.tld
```

Then go to **CONFIGURATION → Git deployment** to check that the repository configuration has been taken into account.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-050-git.png" width="800" />

## Initialize the Backup branch

During Git operations, notably a **Pull** or a **Deployment**, **NGX Ops** backs up the configuration currently used by Nginx.

This backup is sent to a **Backup** branch of the Git repository.

A *tag* is also created so you can identify and retrieve an old version of the configuration.

Before using the backup mechanism, the branch must be initialized.

Click **Initialize the Backup branch** once.

This operation creates the branch needed for the automatic backups of previous configurations.

## Usage

Using GitOps is deliberately simple.

After changing the configuration in your Git repository and pushing it, go to **CONFIGURATION → Git deployment**.

First click **Pull** to fetch the changes present in the repository.

Once the new configuration is fetched, click **Deploy** to start deploying it to Nginx.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-051-git.png" width="800" />

### Verification before deployment

Before any update of the production Nginx configuration, **NGX Ops** tests the configuration in an **ephemeral container**.

The configuration is only applied to Nginx if this test succeeds.

If the test fails, the configuration currently used by Nginx **is not modified**.

This mechanism keeps a working configuration in production even when a change contains a configuration error.

### The same actions from a CI/CD pipeline

Pull, test, backup and full deployment can be triggered through the API with a **deployment token**, created in **Configuration → Editor → Deployment tokens (CI/CD)** (`deploy-tokens.yml` file).

Unlike the administrator API token, a deployment token only opens five routes: `POST /api/git/pull`, `POST /api/git/test`, `POST /api/git/deploy`, `GET /api/git/status` and `POST /api/backups`. Each token can also restrict its actions.

```yaml
tokens:
  - name: forgejo-ci
    token: "a-random-secret-of-at-least-16-characters"
    enable: true
    actions: [test]   # test only: this pipeline can never deploy
```

The HTTP response reflects the result (2xx on success, 422 for an invalid `nginx -t`, 500 for a server error): a `curl -f` is enough to fail the step.

```bash
curl -sS -f -X POST -H "Authorization: Bearer ${DEPLOY_TOKEN}" "${DASHBOARD_URL}/api/git/deploy"
```

## Git, source of truth

As soon as Git is configured, the repository is the reference and NGX Ops prevents anything that would silently contradict it: online editing is disabled, file creation too, and restoring a local backup is refused. To go back, use a `git revert` followed by a redeployment. For backups, see [Backups](../operations/backups.md).
