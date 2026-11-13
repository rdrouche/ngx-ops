# Start using NGX Ops

In this part, we will see how to get started with your new reverse proxy by creating your first virtual host from the terminal.

The virtual host declaration files are in the following folder: `./nginx/config/sites/`.

To be "active", files must have the `.conf` extension so that they are loaded.

> To disable a virtual host, just change the extension; by convention, add `.DISABLE`.

## Create the virtual host file

1- Create your file:

```bash
nano ./nginx/config/sites/example.com.conf
```

2- Enter the virtual host configuration

```nginx
server{
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

## Apply the configuration <a id="#apply-the-configuration"></a>

You have two ways to test and apply the server configuration:

- From the terminal
- From the web interface

### From the terminal

Test the Nginx configuration:

```bash
docker compose exec nginx nginx -t
```

Reload the configuration:

```bash
docker compose exec nginx nginx -s reload
```

### From the web interface

In the navigation menu, click Nginx Control. From this page you can:

- Test the configuration
- Reload Nginx

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-003-reload.png" width="800" />

<hr />

You now know how to create a file to configure a virtual host, test the configuration and reload Nginx.
