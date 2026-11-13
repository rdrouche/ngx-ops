# SSL certificate management in NGX Ops

**NGX Ops** supports several methods of managing SSL/TLS certificates:

* **PEM/KEY certificate**: a certificate obtained from a public certificate authority or issued by your own certificate authority (CA).
* **Certbot certificate with HTTP challenge**: automatic generation and renewal of the certificate using an HTTP challenge.
* **Certbot certificate with DNS challenge**: automatic generation and renewal of the certificate using a DNS challenge. For now, only **Cloudflare** has been tested.

Whatever the certificate source, it can be viewed from the **NGX Ops** dashboard, in: **CONFIGURATION → SSL Certificates**

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-014-ssl.png" width="800" />

By clicking a certificate, you can access various information about it, notably its expiry date, its issuer and the associated domain names.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-015-ssl.png" width="800" />
