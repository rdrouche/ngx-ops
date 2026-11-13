# Versions et mise à jour

## Un numéro unique pour toute la suite

Le dashboard, l'analyseur, l'agent, le challenge, le Hub et le log store portent **le même numéro de version**. Une version correspond à un numéro et à un tag : les composants qui la portent ont été validés ensemble.

- Le numéro courant figure dans le fichier `VERSION.md` à la racine du dépôt.
- Chaque composant a son propre `CHANGELOG.md`. À chaque version, chaque composant reçoit une entrée, même lorsqu'elle indique « aucun changement ».
- Le `CHANGELOG.md` racine est celui du dashboard et de la suite.
- Le dashboard affiche sa version dans l'en-tête et dans la page **Système**. Le bouton **Changelog** de cette page affiche l'historique quand `CHANGELOG_URL` est renseignée.

## Les images et leurs tags

Les images sont publiées dans le registre `forge.rdr-it.com/ngx-ops/ngx-ops`.

| Image | Composant |
|---|---|
| `ngx-ops-dashboard` | Dashboard |
| `analyzer-agent-go` | Analyseur, WAF émulé et shipper (trois programmes dans une même image) |
| `ngx-ops-challenge-http` | Challenge navigateur |
| `ngx-ops-agent` | Agent pour les serveurs distants |
| `ngx-ops-hub` | Hub avec SQLite |
| `ngx-ops-hub` avec le suffixe `-pg` | Hub avec PostgreSQL (par exemple `X.Y.Z-pg`) |
| `ngx-ops-logstore` | Log store |

La documentation est construite par un workflow séparé, lancé à la demande, et n'est pas reconstruite avec le reste de la suite.

Le tag est choisi au moment de la construction :

- Une construction peut publier **plusieurs tags en même temps** : le numéro de version, `stable`, `latest`, etc. Le premier de la liste est le tag principal.
- Le tag par défaut est `nightly`. Une image `nightly` est une construction d'essai, **à ne pas utiliser en production**.
- La version écrite dans l'image et dans ses étiquettes est, par ordre de priorité, celle demandée au lancement, la variable `NGX_OPS_VERSION` du dépôt, puis le tag principal.
- Pour la production, utilisez un **tag numérique** (par exemple `X.Y.Z`) plutôt qu'un tag mobile. Vous savez ainsi ce qui tourne et vous pouvez revenir en arrière.

Le dashboard est construit avec les noms d'images de l'analyseur, du WAF émulé, du challenge et de l'agent, **au même tag que lui**. Tant que `container_image` n'est pas fixé dans un fichier YAML de `config/`, ces conteneurs suivent donc la version du dashboard.

## Mettre à jour

### Avant de commencer

1. Lire le `CHANGELOG.md` des composants concernés, entre votre version et la nouvelle.
2. Faire une sauvegarde : page **Sauvegardes** du dashboard, et pour le Hub, le dossier de données **et** la clé maître `HUB_SECRET_KEY`.
3. Noter le tag actuel de chaque image, pour pouvoir y revenir.

### Le dashboard et Nginx

Changer le tag dans le fichier `.env` ou dans le compose, puis :

```bash
docker compose pull
docker compose up -d
```

Les conteneurs dont l'image a changé sont recréés, les autres ne sont pas touchés. Les dossiers `config/` et les volumes conservent votre configuration et vos données.

### Les conteneurs gérés par le dashboard

L'analyseur, le WAF émulé, le challenge, le shipper, certbot, GeoIP et les pages d'erreur sont créés par le dashboard. Chacune de leurs pages propose le bouton **Mettre à jour l'image** : il télécharge l'image configurée et **ne recrée le conteneur que si l'image a changé**.

- Avec un tag mobile (`latest`, `stable`), ce bouton récupère la nouvelle image.
- Avec un tag numérique fixé dans `container_image`, changez ce tag dans le fichier YAML de la fonction, puis utilisez le bouton.
- Un conteneur arrêté volontairement depuis sa page n'est jamais relancé de force.

### Les composants à part

Le Hub et le log store ont chacun leur fichier compose : changez le tag de leur image, puis `docker compose pull` et `docker compose up -d` dans leur dossier.

Ces composants sont indépendants : la mise à jour de l'un n'oblige pas à arrêter les autres.

- Le Hub interroge les dashboards avec un contrat qui n'évolue que par ajouts. Une partie que le dashboard ne fournit pas encore est simplement masquée dans le Hub.

Pour garder la même cohérence que celle validée à la publication, mettez à jour tous les composants vers **le même numéro**.

### Revenir en arrière

Remettez l'ancien tag dans le compose, puis `docker compose up -d`. Si la nouvelle version a modifié des fichiers de `config/`, restaurez la sauvegarde faite avant la mise à jour.
