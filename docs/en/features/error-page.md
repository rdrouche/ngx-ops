# Custom error page

This feature customizes the 4XX and 5XX error pages returned by Nginx, relying on the project [tarampampam/error-pages](https://github.com/tarampampam/error-pages).

> This is the first feature I integrated into my Nginx stack. It replaces the default Nginx error pages with more modern and visually pleasant ones.

Like all auxiliary features, it must be configured at the dashboard level.

## Enable custom error pages

Start by going to: Integration / Error pages and copy the configuration code.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-004-error-page.png" width="800" />

Then go to Administration / Configuration, open the Error pages tab, paste the text into the configuration area and click Save.

```yaml
enable: true
container_image: tarampampam/error-pages:latest
template_name: connection
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-005-error-page.png" width="800" />

Go back to Error pages and click the Start button.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-006-error-page.png" width="800" />

The container is started to serve the custom error pages.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-007-error-page.png" width="800" />

## Configure custom error pages in virtual hosts

To serve custom error pages, use the [`global-error.conf`](https://forge.rdr-it.com/ngx-ops/reference-files/src/branch/main/snippets/global-error.conf) snippet.

In the server{...} block, add the call to the snippet:

```nginx
server {
    listen 80;
    server_name example.com;

    # Custom error pages
    include snippets/global-error.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```
