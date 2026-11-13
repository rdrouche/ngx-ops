# Générateur de vhost et snippets

Le générateur de la page **VHost Generator** produit un fichier de configuration de reverse proxy complet à partir d'un formulaire. **Rien n'est écrit sur le disque** : vous relisez le résultat, puis vous le placez dans `sites/` (à la main ou par le [déploiement Git](../features/git.md)).

## Ce que l'on peut régler

| Option | Effet |
|---|---|
| Noms de serveur | Un ou plusieurs noms dans `server_name` |
| HTTPS | `listen 443 ssl` (ou le port choisi), avec le certificat sélectionné |
| Redirection HTTP vers HTTPS | Ajoute un bloc sur le port 80 qui répond `301` |
| HTTP/2 | Ajoute `http2 on;` |
| Journal d'accès | Fichier automatique nommé d'après le vhost, chemin personnalisé, ou aucune directive (par exemple si un snippet s'en charge) |
| Snippets de serveur et de location | Une ligne `include snippets/<fichier>;` par snippet choisi |
| Taille maximale du corps | `client_max_body_size` |
| Délai de lecture du backend | `proxy_read_timeout`, 60 secondes par défaut |
| Configuration libre | Lignes ajoutées dans le bloc `server` ou dans le bloc `location` |

## Le backend

- **URL classique** : `proxy_pass` vers l'adresse saisie.
- **Conteneur Docker** : en cochant « Docker container », le générateur écrit le nom, le port et le schéma du conteneur dans une variable, et ajoute le résolveur DNS de Docker. Nginx retrouve ainsi l'adresse du conteneur à chaque résolution, même après sa recréation.

```nginx
set $backend http://mon-conteneur:3000;
resolver 127.0.0.11 valid=30s;
```

## Le certificat

Le formulaire propose trois sources :

| Source | Ce que le générateur écrit |
|---|---|
| Snippets `ssl-*.conf` du dossier `snippets/` | `include snippets/ssl-xxx.conf;` |
| Certificats du dossier `ssl/` | `ssl_certificate` et `ssl_certificate_key` pré-remplis. Une paire sans clé est signalée « clé manquante » |
| Certificats Let's Encrypt de `certs/live/` | Les chemins Certbot |

## Les brouillons

Les brouillons sont enregistrés **dans le navigateur**, sous plusieurs noms, et le fichier généré se télécharge en `.conf`. Ils ne sont pas partagés avec les autres utilisateurs et disparaissent si vous videz les données du navigateur.

## Snippets : métadonnées

Un snippet peut déclarer ses métadonnées dans des commentaires, en tête de fichier, pour que le générateur sache comment le proposer :

```nginx
# name: proxy-common
# description: Headers proxy standard
# emplacement: server,location
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
```

| Champ | Valeurs | Si absent |
|---|---|---|
| `name` | Libellé affiché | Nom du fichier sans `.conf` |
| `description` | Description courte | Vide |
| `emplacement` | `server`, `location` ou les deux | `server,location` |

Les snippets dont le nom commence par `ssl-` sont automatiquement limités à l'emplacement `server`.
