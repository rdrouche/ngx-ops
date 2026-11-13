# Install NGX Ops

## Requirements

A Linux server with Docker and Docker Compose installed.

> This documentation was written on a Debian 13 server.

## Prepare the folders

On your server, create a folder for the files and folders of the stack.

> This documentation uses the `/containers/ngxops` folder.

Create the folder:

```bash
mkdir -p /containers/ngxops
cd /containers/ngxops
```

## Get the files

The files and folders of the stack are available here:
- https://forge.rdr-it.com/ngx-ops/compose

Use the command below to clone the directory from the repository:

```bash
bash <(wget -qO- https://forge.rdr-it.com/ngx-ops/compose/raw/branch/main/deploy.sh) ngx-ops
```

## Basic configuration

Start by copying [`sample.env`](https://forge.rdr-it.com/ngx-ops/compose/src/branch/main/ngx-ops/sample.env) to `.env`, then edit it. No secret is required to start: see [Environment variables](environment.md).

```bash
cp sample.env .env
nano .env
```

By default, the dashboard is not published. Create a `compose.override.yml` file with the following content:

```yaml
services:
  nginx-dashboard:
    ports:
      - "3000:3000"
```

## Start the containers

Download the images and start the containers:

```bash
docker compose up
```

> The images are downloaded, then the containers start.

> Without the `-d` option, you see the container logs, which lets you check that they start and note the **admin account password**, displayed only once.
>
> Once the password is noted, pressing the **d** key detaches the display and leaves the containers running in the background (recent versions of Docker Compose). Otherwise, `Ctrl+C` stops the containers: run `docker compose up -d` again.

## Access the Dashboard

From a browser, go to `http://ip:3000`, which opens the login page.

- Username: admin
- Password: the one displayed in the container logs. If you lost it: `docker compose logs nginx-dashboard`

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-001-login.png" width="800" />

Once logged in, you land on a page that shows the request metrics from Nginx VTS.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-002-overview.png" width="800" />

<hr />
