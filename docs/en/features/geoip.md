# GeoIP - geographic location of visitors

Nginx builds are compiled with the [geoip2](https://nginx-extras.getpagespeed.com/modules/geoip2/) module, which lets you use the [MaxMind](https://www.maxmind.com/en/home) databases to determine the geographic origin of the requests received on your reverse proxy.

The MaxMind databases are required for several **NGX Ops** features:

- Real-time map
- Geographic analysis of requests
- Periodic summary
- Live logs

Besides being used in **NGX Ops**, you can use these databases in your virtual host configurations to filter traffic on your site.

**NGX Ops** relies on 3 databases:

- GeoLite2-City: determines the city of origin
- GeoLite2-Country: determines the country of origin
- GeoLite2-ASN: lets you filter on the [ASN](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) (Autonomous System) of the IP address

## Requirements

To download the databases from the MaxMind site, you must create an account if you do not have one yet.

- https://www.maxmind.com/en/create-account
- https://www.maxmind.com/en/account/sign-in

Once logged in to your account, click View license key:

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-008-geoip.png" width="800" />

Then create a new key that will be used for the geoipupdate container.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-009-geoip.png" width="800" />

> While you are there, note your **Account ID**

## Configuration in NGX Ops

From the menu, go to Integration / GeoIP, select the configuration template and copy it.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-010-geoip.png" width="800" />

Then go to Configuration, open the GeoIP tab, paste the configuration code, adapting it to your environment, and click Save.

```yaml
enable: true
account_id: 123456
license_key: YOUR_KEY
edition_ids: GeoLite2-City GeoLite2-Country GeoLite2-ASN
frequency_hours: 168
geoip_host_path: /containers/nginx/geoip_data
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-011-geoip.png" width="800" />

> The `geoip_host_path` parameter must match the absolute path on the Docker host where the database files will be stored.

Then go back to Integration / GeoIP and click the Start button.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-012-geoip.png" width="800" />

Wait a few seconds while the container starts and the databases are downloaded, then click the Refresh button to check that it works.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-013-geoip.png" width="800" />

The MaxMind databases can now be used with Nginx and NGX Ops.

## Use geolocation in your virtual hosts

### Load the databases with `geoip2`

The first step to use the databases is to tell Nginx to load them.

In the folder `./nginx/config/conf.d/`, rename the file `geoip2-load-database.conf.DISABLE` to `geoip2-load-database.conf` so that it is loaded.

```bash
mv ./nginx/config/conf.d/geoip2-load-database.conf.DISABLE ./nginx/config/conf.d/geoip2-load-database.conf
```

[Test the Nginx configuration and reload it](../start-with-dashboard.md#apply-the-configuration).

### Use in a virtual host

GeoIP restrictions must be applied with care, depending on the site or application you want to publish.

For a business application that you want to restrict to one country, such as France, the impact is generally limited. For a public website, however, the situation is more delicate, notably if you want it to be properly indexed by search engines.

Another precaution concerns using the same reverse proxy for external access (exposed to the Internet) and internal access. In this case, internal users can reach the reverse proxy with a private IP address. If a GeoIP restriction is configured, these addresses cannot be matched to a country and users risk being blocked.

To solve this problem, several approaches are possible. You can notably set up a loop through your firewall (*NAT loopback / hairpin NAT*), so internal users reach the reverse proxy through its public IP address. This implies that internal DNS resolution also uses the public name and public IP address of the service.

Another solution is to adapt the `map` directive used for the GeoIP restriction to explicitly allow private IP address ranges. This approach keeps direct access to the reverse proxy from the internal network, without sending connections through the public IP address.

> ***Separate the reverse proxies***
>
>For reasons of logical separation and security, it can be preferable to set up two distinct reverse proxies: one exposed to the Internet and dedicated to published applications, and a second reserved for internal use.
>
>This architecture notably clearly separates Internet flows from internal flows, and also lets you apply different security policies on each reverse proxy. GeoIP restrictions, filtering rules, attack protections or the accessible applications can thus be configured independently.
>
>This separation also brings an interesting operational advantage. An application can be removed from Internet publication while remaining accessible from the internal network. This can be particularly useful for maintenance, test or pre-production environments.
>
>For example, an application can be published on the Internet reverse proxy during its production phase, then removed from it during a maintenance operation while remaining accessible to administrators through the internal reverse proxy. Likewise, a test application can be accessible only from the internal network without ever being exposed on the Internet.
>
>This dual reverse proxy architecture is therefore a particularly interesting solution when internal and external access needs differ.

In this documentation, we present several use cases to illustrate these different configurations and help you choose the approach best suited to your environment.

#### Case 1: Only allow IP addresses from France

To start, we will see how to allow traffic to a virtual host only when it comes from a French IP address.

1 - Create the `map` configuration

Create a configuration file in `./nginx/config/conf.d/`. This file must have the `.conf` extension so it is loaded automatically by Nginx.

```nginx
# file : allow-from-france.conf

map $geoip2_data_country_iso_code $allow_from_france {
    default 0;       # By default, traffic is denied
    FR 1;            # If the ISO country code is FR (France), traffic is allowed
}
```

> The `map` directive creates the `$allow_from_france` variable and gives it the value `0` or `1` depending on the country code returned by GeoIP2.
>
> In our example, all IP addresses are denied by default. Only IP addresses identified as coming from France (`FR`) are allowed.
>
> This variable can then be used in the virtual host configuration to filter traffic.

2 - Configure the virtual host

In the virtual host, then add: `if ($allow_from_france = 0) { return 403; }` to filter traffic.

```nginx
server {
    listen 80;
    server_name example.com;

    # Custom error pages
    include snippets/global-error.conf;

    # Traffic filtering: France only
    if ($allow_from_france = 0) { return 403; }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

> 💡 **Tip:** The `$allow_from_france` variable can be used in several virtual hosts. That is why I advise declaring your `map` directives in dedicated configuration files rather than directly in your virtual host files, before the `server { ... }` block.
>
> This organization notably makes it easy to reuse the same variables in several virtual hosts and to centralize filtering rules.


#### Case 2: Only block IP addresses from France

In this second example, we take the problem the other way around and block all traffic coming from French IP addresses.

1 - Create the `map` configuration

Create a configuration file in `./nginx/config/conf.d/`. This file must have the `.conf` extension so it is loaded automatically by Nginx.

```nginx
# file : block-from-france.conf

map $geoip2_data_country_iso_code $block_from_france {
    default 1;       # By default, all traffic is allowed
    FR 0;            # If the ISO country code is FR (France), traffic is blocked
}
```

2 - Configure the virtual host

In the virtual host, then add: `if ($block_from_france = 1) { return 403; }` to filter traffic.

```nginx
server {
    listen 80;
    server_name example.com;

    # Custom error pages
    include snippets/global-error.conf;

    # Traffic filtering: block France
    if ($block_from_france = 1) { return 403; }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

#### Case 3: Allow IP addresses from France and private IP addresses

We start again from the first case and now see how to also allow connections coming from private IP addresses.

In the reverse proxy's base configuration files, you will find the [`private-ips.conf`](https://forge.rdr-it.com/romain/Docker-Compose/src/branch/main/ReverseProxy/nginx/config/conf.d/private-ips.conf) file. It contains a mapping of the different private IP address ranges and sets the `$is_private_ip` variable.

This variable equals `1` when the client IP address belongs to a private address range, and `0` otherwise.

We can use this variable in our GeoIP configuration to allow connections coming from the internal network, even though GeoIP2 cannot match a private IP address to a country.

1 - Create the `map` configuration

Create a configuration file in `./nginx/config/conf.d/`. This file must have the `.conf` extension so it is loaded automatically by Nginx.

```nginx
# file : allow-from-france-and-private-ips.conf

map "$geoip2_data_country_iso_code:$is_private_ip" $allow_from_france_and_private_ips {
    default 0;           # By default, traffic is denied
    "~^FR:" 1;           # If the ISO country code is FR (France), traffic is allowed
    "~:1$"  1;           # If the IP address is private, traffic is allowed
}
```

>The value evaluated by the map is made of the two variables, separated by `:`. For example:
>
>- `FR:0`: public IP address located in France;
>- `US:0`: public IP address located in the United States;
>- `:1`: private IP address, for which GeoIP2 returns no country.
>
>The two regular expressions therefore allow traffic in the two situations we care about:
>
>- `~^FR:`: the country code starts with FR;
>- `~:1$`: the value ends with `:1`, indicating the IP address is private.
>
>All other combinations match the `default` value `0` and are therefore denied.

2 - Configure the virtual host

In the virtual host, then add: `if ($allow_from_france_and_private_ips = 0) { return 403; }` to filter traffic.

```nginx
server {
    listen 80;
    server_name example.com;

    # Custom error pages
    include snippets/global-error.conf;

    # Traffic filtering
    if ($allow_from_france_and_private_ips = 0) { return 403; }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

#### Case 4: Allow IP addresses from France, reference bots and private IP addresses

We start again from **Case 3** and this time add the search engine indexing bots.

The goal is to make our site accessible only to visitors coming from a French or private IP address, while allowing search engine robots to access the site, whatever their IP address.

This configuration therefore keeps a geographic restriction for visitors while letting search engines crawl and index the site content.

To determine the "good" robots, we use the [`good-bots.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/conf/good-bots.conf) file.

This file uses Nginx's `map` directive to identify indexing robots from their **User-Agent** and set the value of the `$is_good_bot` variable.

The `$is_good_bot` variable thus determines whether the request comes from a robot identified as legitimate and allowed to access the site.

1 - Create the `map` configuration

Create a configuration file in `./nginx/config/conf.d/`. This file must have the `.conf` extension so it is loaded automatically by Nginx.

```nginx
# file : allow-from-france-and-private-ips-and-bots.conf

map "$geoip2_data_country_iso_code:$is_good_bot:$is_private_ip" $allow_from_france_and_private_ips_and_bots {
    default 0;           # By default, traffic is denied
    "~^FR:" 1;           # If the ISO country code is FR (France), traffic is allowed
    "~:1:"  1;           # If the request comes from an allowed bot, traffic is allowed
    "~:1$"  1;           # If the IP address is private, traffic is allowed
}
```

>This time the value evaluated by the map is made of three variables, separated by `:`:
>
>`$geoip2_data_country_iso_code`: the country code determined by GeoIP2;
>`$is_good_bot`: indicates whether the User-Agent matches a bot identified as allowed;
>`$is_private_ip`: indicates whether the IP address is a private address.
>
>For example, the evaluated values could be:
>
>`FR:0:0` → visitor with a French public IP → allowed;
>`US:1:0` → allowed bot from the United States → allowed;
>`US:0:0` → visitor with a US public IP → denied;
>`:0:1` → visitor from a private IP address → allowed.
>
>The three map rules then define the allow conditions:
>
>`~^FR:`: the value starts with `FR:`. The IP address is therefore identified as French, whatever the bot or private address status;
>`~:1:`: the value contains `:1:`. This means `$is_good_bot` equals `1`, whatever the country of origin or whether the IP address is private;
>`~:1$`: the value ends with `:1`. This means `$is_private_ip` equals `1`, and access is therefore allowed.
>
>All other combinations match the `default` rule `0` and are denied.

2 - Configure the virtual host

In the virtual host, then add: `if ($allow_from_france_and_private_ips_and_bots = 0) { return 403; }` to filter traffic.

```nginx
server {
    listen 80;
    server_name example.com;

    # Custom error pages
    include snippets/global-error.conf;

    # Traffic filtering
    if ($allow_from_france_and_private_ips_and_bots = 0) { return 403; }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```
