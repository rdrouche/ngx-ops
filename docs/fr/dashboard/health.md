# Santé et Redis optionnel

## Santé du dashboard

Deux routes permettent de superviser NGX Ops depuis un outil externe.

| Route | Accès | Contenu |
|---|---|---|
| `GET /health` | **Publique**, sans session | `{"status":"ok"}`, `"degraded"` ou `"down"`. Code HTTP 200 pour `ok` et `degraded`, **503** pour `down`. Mise en cache 5 secondes |
| `GET /api/health` | Session ou jeton, permission de lecture des métriques | État de chaque composant |

`/api/health` renvoie un état pour `dashboard`, `nginx`, `analyzer`, `waf`, `challenge`, `crowdsec`, `log_store`, `shipper` et `redis`, parmi `ok`, `degraded`, `down`, `disabled` et `unknown`. Elle ne donne ni version précise, ni chemin, ni adresse, ni message d'erreur.

### Comment l'état global est calculé

- `down` : Nginx ne répond pas.
- `degraded` : un composant **activé** est en panne.
- Un composant désactivé (`disabled`) ou dont l'état est illisible (`unknown`) ne dégrade pas l'état global.

### Restreindre l'accès

La route publique ne révèle qu'un seul mot, mais NGX Ops n'y ajoute aucune authentification. Pour la couper : `HEALTH_PUBLIC=false` (la route répond alors 404). Pour la limiter à votre supervision, restreignez-la dans le reverse proxy :

```nginx
location = /health {
    allow 10.0.0.0/8;          # supervision interne
    allow 192.168.0.0/16;
    allow 203.0.113.10;        # sonde externe, à remplacer par son adresse
    deny  all;
    proxy_pass http://nginx-dashboard:3000;
}
```

Derrière un autre proxy ou un CDN, l'adresse vue par Nginx est celle du proxy : utilisez le module `real_ip` (voir `cloudflare-real-ip.conf`) pour que `allow` et `deny` s'appliquent à la vraie adresse du visiteur.

## Redis optionnel

Redis n'est **jamais requis**. Sans `REDIS_URL`, tout fonctionne comme avant. Lorsqu'il est présent, il conserve ce qui est perdu à chaque redémarrage de l'analyseur ou du challenge.

| Composant | Conservé dans Redis | Effet |
|---|---|---|
| Analyseur | Les heures de trafic en cours d'agrégation (vhost, pays), l'appartenance des IP aux listes de blocage et leur mode | La baseline n'est plus faussée par une heure tronquée |
| Challenge | Compteurs horaires, IP en échec, blocages automatiques en cours, historique des blocages, jetons anti-rejeu | Un redémarrage ne débloque plus les IP bannies |

### Mise en place

1. Dans `.env`, renseigner l'adresse et un mot de passe long et aléatoire :

    ```bash
    REDIS_URL=redis://redis:6379/0
    REDIS_PASSWORD=<openssl rand -hex 32>
    ```

2. Démarrer le service avec son profil :

    ```bash
    docker compose --profile redis up -d
    ```

3. Recréer une fois l'analyseur et le challenge, pour qu'ils reçoivent ces variables.

L'état de Redis s'affiche dans `GET /api/health` et les variables dans la page **Système**.

### Sécurité

- Réseau Docker interne uniquement : aucun port n'est publié.
- Mot de passe obligatoire : le service refuse de démarrer sans lui.
- Les commandes `FLUSHALL`, `FLUSHDB` et `DEBUG` sont désactivées.
- Mémoire plafonnée par `REDIS_MAXMEMORY` (256 Mo par défaut), avec éviction des clés les plus anciennes.
- Aucune écriture sur disque.
- Les clés sont préfixées par `REDIS_PREFIX` : à distinguer si plusieurs installations partagent le même Redis. Elles expirent après 7 jours.
