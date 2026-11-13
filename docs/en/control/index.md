# Actions on Nginx

From **NGX Ops**, you can perform various actions on Nginx from the **CONTROL → Nginx control** page:

* **Test the configuration**: checks the Nginx configuration before applying it.
* **Reload the configuration**: reloads the configuration without restarting the Nginx container.
* **Fetch VTS metrics**: fetches the metrics provided by the VTS module.
* **Restart Nginx**: restarts the Nginx container.

To perform these operations, Nginx must run in a Docker container and **NGX Ops must have access to the Docker socket**.

This page also shows the main metrics of the Nginx container:

* **CPU**
* **RAM**
* **Network**

This notably lets you quickly follow the reverse proxy's resource consumption and check its state during a maintenance operation or after a configuration change.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-038-control.png" width="800" />
