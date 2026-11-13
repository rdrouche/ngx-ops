# PEM/KEY certificate

The `.pem` and `.key` files, containing respectively the certificate and the private key in text/Base64 format, must be placed on the host in the folder:

```text
./certificats/ssl/
```

This folder is mounted in the Nginx container at the following location:

```text
/ssl
```

For example, if you have the following files:

* `exemplecom.cer`
* `exemplecom.key`

You can use them in your virtual host with the following directives:

```nginx
ssl_certificate /ssl/exemplecom.cer;
ssl_certificate_key /ssl/exemplecom.key;
```

> 💡 **Tip:** If you use the same certificate in several virtual hosts, I advise creating a *snippet* to avoid duplicating the configuration.
>
> ```nginx
> # file: snippets/ssl-exemplecom.conf
>
> ssl_certificate /ssl/exemplecom.cer;
> ssl_certificate_key /ssl/exemplecom.key;
> ```
>
> You can then include this *snippet* in the virtual hosts concerned:
>
> ```nginx
> include snippets/ssl-exemplecom.conf;
> ```
>
> This method centralizes the certificate configuration and simplifies replacing or changing it.
