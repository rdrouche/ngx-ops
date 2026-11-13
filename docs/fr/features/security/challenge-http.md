# Challenge HTTP

NGX Ops permet de mettre en place un **Challenge HTTP** afin de demander une vérification supplémentaire aux clients avant de leur permettre d'accéder à une ressource protégée.

Le Challenge HTTP peut notamment être utilisé pour limiter les requêtes automatisées, ralentir les robots malveillants ou ajouter une étape de vérification avant l'accès à certaines ressources.

NGX Ops prend en charge deux moteurs de Challenge HTTP :

* **Builtin** : moteur intégré à NGX Ops, exécuté dans un conteneur géré par NGX Ops.
* **Anubis** : utilisation du projet [Anubis](https://github.com/TecharoHQ/anubis).

Les deux moteurs ne peuvent pas être utilisés simultanément. Le moteur utilisé est défini avec le paramètre `challenge_engine`.

Le Challenge HTTP peut être appliqué à différents niveaux :

* manuellement dans la configuration d'un hôte virtuel ;
* sur un bloc `location` spécifique ;
* automatiquement comme **remédiation d'une Blocklist IP**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-001-challenge-http.png" width="800" />

### Builtin ou Anubis ?

Le moteur **Builtin** est intégré directement à NGX Ops et permet notamment de disposer de statistiques sur les Challenges HTTP.

Anubis est une solution externe spécialisée dans le Challenge HTTP. Son fonctionnement est différent et NGX Ops ne dispose pas des mêmes statistiques que pour le moteur Builtin.

Avec le moteur Builtin, les statistiques sont accessibles directement depuis **NGX Ops → Intégration → Challenge HTTP**.

---

## Activer le Challenge HTTP dans NGX Ops

Pour activer le Challenge HTTP, aller dans :

**Administration → Configuration → Challenge HTTP**

Dans la zone de configuration, renseigner par exemple :

```yaml
challenge_enable: true
challenge_engine: builtin
enable: true
difficulty_bits: 16
```

Puis cliquer sur **Enregistrer**.

### Paramètres principaux

* `challenge_enable` : active la génération de la configuration du Challenge HTTP dans Nginx.
* `challenge_engine` : définit le moteur utilisé (`builtin` ou `anubis`).
* `enable` : active le conteneur du moteur sélectionné.
* `difficulty_bits` : définit la difficulté du challenge pour le moteur Builtin.

Une fois la configuration enregistrée, aller dans :

**Intégration → Challenge HTTP**

Puis démarrer le conteneur.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-002-challenge-http.png" width="800" />

Le conteneur est alors créé et démarré par NGX Ops.

Après son démarrage, cliquer sur **Régénérer et recharger Nginx**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-003-challenge-http.png" width="800" />

Cette opération génère les fichiers de configuration nécessaires et recharge Nginx afin d'appliquer la nouvelle configuration.

---

## Appliquer le Challenge HTTP à un VHost

Le Challenge HTTP peut être activé manuellement sur un hôte virtuel.

Dans le bloc `server`, ajouter le snippet :

```nginx
include snippets/challenge-all-allowbots.conf;
```

Par exemple :

```nginx
server {
    listen 80;
    server_name example.com;

    include snippets/challenge-all-allowbots.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Le snippet `challenge-all-allowbots.conf` applique le Challenge HTTP à l'ensemble du VHost tout en conservant le comportement configuré pour les **bons robots**.

---

## Appliquer le Challenge HTTP à un bloc `location`

Il peut être intéressant de ne pas protéger l'ensemble d'un site, mais uniquement certaines ressources sensibles.

Quelques exemples :

* formulaire de connexion ;
* formulaire de contact ;
* interface d'administration ;
* endpoint particulièrement ciblé par des robots ;
* ressource nécessitant une protection supplémentaire.

### Exemple avec WordPress

Dans cet exemple, le Challenge HTTP est appliqué uniquement à `wp-login.php`.

Il faut inclure deux fichiers : 

- `challenge-location-support.conf` dans le bloc `server { ... }`.
- `challenge-location.conf` dans le lbloc `location / { ... }` où vous souhaitez l'activer.

```nginx
server {
    listen 80;
    server_name wordpress.example.com;

    include snippets/challenge-location-support.conf;

    location = /wp-login.php {
        # HTTP Challenge
        include snippets/challenge-location.conf;

        proxy_pass http://192.168.1.1;
    }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Le reste du site reste accessible normalement, tandis que les requêtes vers `wp-login.php` doivent passer par le Challenge HTTP.

---

## Utiliser le Challenge HTTP comme remédiation d'une Blocklist

Le Challenge HTTP peut également être utilisé automatiquement comme **action de remédiation** lorsqu'une adresse IP est présente dans une [Blocklist](blocklist-ips.md).

Cela permet par exemple de demander une vérification supplémentaire à une adresse IP suspecte plutôt que de la bloquer immédiatement.

Dans la configuration de la Blocklist, activer les paramètres suivants :

```yaml
challenge_enable: true
challenge_engine: builtin
```

Lorsque le moteur Builtin est utilisé, NGX Ops peut alors appliquer le Challenge HTTP aux adresses IP concernées par la remédiation.

Cette approche permet notamment d'avoir plusieurs niveaux de réponse :

1. laisser passer la requête ;
2. demander un Challenge HTTP ;
3. bloquer l'adresse IP.

---

## Les snippets disponibles

| Snippet | Qui est challengé |
| ------- | ----------------- |
| `challenge-gate.conf` | Seulement les IP de la liste « challenge » des règles d'analyse |
| `challenge-all.conf` | Tous les visiteurs du VHost, hors chemins et User-Agent exemptés |
| `challenge-all-allowbots.conf` | Tous les visiteurs sauf les bons robots d'indexation |
| `challenge-location.conf` | Un bloc `location` (avec `challenge-location-support.conf` ou sa variante `-allowbots`, inclus une fois dans le `server`) |

Ne pas combiner les snippets `gate`, `all`, `allowbots` ou un profil avec le snippet de `location` dans le même bloc `server`.

---

## Efficacité et IP en échec

La page **Challenge HTTP** affiche :

* **Efficacité** : challengés, réussis, échecs, visiteurs sans JavaScript et taux de réussite, sur 24 h, 7 jours ou 30 jours. Le dashboard doit pouvoir joindre le conteneur du challenge sur le réseau Docker.
* **IP qui échouent au challenge** : le moteur Builtin suit, en mémoire, les IP qui n'arrivent jamais à le passer (typiquement des robots sans JavaScript).

### Blocage automatique

Avec `autoblock: true` dans `challenge.yml`, une IP qui cumule `autoblock_threshold` échecs (30 par défaut) dans `autoblock_window_minutes` (60) **sans jamais avoir résolu** le challenge est bloquée pendant `autoblock_hours` (24). Le conteneur répond immédiatement 403, puis Nginx bloque l'IP via une source de [Blocklist IP](blocklist-ips.md) de type `challenge`.

```yaml
sources:
  - name: challenge-bans
    type: challenge
    action: deny_403   # ou drop_444
```

* Une IP qui a résolu le challenge au moins une fois n'est jamais bloquée (réseaux partagés, NAT).
* La liste blanche de `blocklists.yml` s'applique.
* Le bouton **Débloquer** lève un blocage.
* Les bons robots (Google, Bing, Apple, Yandex, Baidu) sont reconnus par DNS inverse confirmé et ne sont jamais comptés ni bloqués ; `goodbots_extra` permet d'en ajouter.
* Ces réglages sont lus à la (re)création du conteneur.

---

## Configuration avancée

La configuration du Challenge HTTP est définie dans `challenge.yml`.

Les paramètres disponibles dépendent du moteur utilisé.

### Builtin

Exemple de configuration :

```yaml
challenge_enable: true
challenge_engine: builtin

enable: true
difficulty_bits: 16

challenge_exempt_ua_regex: '^(forgejo-runner/|git/|docker/|buildkit/|containerd/|NGXOps)'
```

Le paramètre `challenge_exempt_ua_regex` permet d'exclure certains User-Agent du Challenge HTTP.

Dans cet exemple, les requêtes provenant notamment de Forgejo Runner, Git, Docker, BuildKit, containerd et NGX Ops sont exemptées.

> Cette possibilité est particulièrement utile pour les services automatisés qui ne peuvent pas résoudre un Challenge HTTP comme le ferait un navigateur.

#### Difficulté du Challenge

La difficulté est contrôlée par `difficulty_bits`.

```yaml
difficulty_bits: 16
```

Chaque bit supplémentaire augmente approximativement par deux le travail nécessaire pour résoudre le challenge.

Une difficulté trop élevée peut rendre le Challenge très long, voire impossible à résoudre pour un utilisateur légitime.

Il est donc recommandé d'augmenter progressivement cette valeur en fonction du niveau de protection recherché.

---

### Anubis

Pour utiliser Anubis, modifier le moteur :

```yaml
challenge_enable: true
challenge_engine: anubis

enable: true

challenge_exempt_ua_regex: '^(forgejo-runner/|git/|docker/|buildkit/|containerd/|NginxControl)'

anubis_difficulty: 8
```

Le paramètre `anubis_difficulty` permet de définir la difficulté utilisée par Anubis.

Les paramètres spécifiques à Anubis, comme `redirect_domains` ou `cookie_domain`, peuvent également être configurés dans `challenge.yml`.

---

## Profils par VHost

NGX Ops permet également de définir des profils de Challenge HTTP spécifiques à certains VHosts.

Chaque profil peut avoir son propre mode et ses propres exemptions.

Exemple :

```yaml
profiles:
  - name: forgejo
    mode: allbots
    exempt_ua_regex: '^forgejo-runner/'

  - name: wiki
    mode: all
    exempt_path_regex: '^/(api/|[.]well-known/)'
```

Les profils permettent notamment d'adapter le comportement du Challenge HTTP en fonction du service exposé.

Un profil peut être utilisé avec les modes suivants :

* `listed` : applique le Challenge aux IP présentes dans les listes concernées ;
* `all` : applique le Challenge à toutes les requêtes ;
* `allbots` : applique le Challenge en tenant compte de la gestion des bons robots.

---

## Fichier `challenge.yml` de référence

Le fichier `challenge.yml` centralise la configuration du Challenge HTTP et du conteneur géré par NGX Ops.

```yaml
# Challenge HTTP — réglages et conteneur géré depuis NGX Ops.
#
# Éditable depuis « Éditeur de configuration ».
# Après modification des clés challenge_*, utiliser
# « Régénérer et recharger Nginx » depuis la page Challenge HTTP.
#
# Priorité :
# variables NC_* > challenge.yml > valeurs par défaut.
#
# Les clés challenge_* sont prioritaires sur celles de
# blocklists.yml.

# ── Nginx ────────────────────────────────────────────────────────────────

# Activer la génération de la configuration Challenge HTTP.
challenge_enable: false

# Moteur utilisé :
#   builtin  → moteur intégré NGX Ops
#   anubis   → moteur Anubis
challenge_engine: builtin

# Adresse du backend Challenge HTTP.
# Par défaut :
#   builtin → nginx-challenge:8080
#   anubis  → anubis:8923
challenge_upstream: ""

# Résolveur DNS utilisé par Nginx.
challenge_resolver: 127.0.0.11

# Chemins exemptés du Challenge HTTP.
challenge_exempt_path_regex: '^/[.]well-known/'

# User-Agent exemptés du Challenge HTTP.
challenge_exempt_ua_regex: ""

# Exemple :
# challenge_exempt_ua_regex: '^NGXOps$'


# ── Profils par VHost ───────────────────────────────────────────────────

# Permet de définir un comportement spécifique pour certains VHosts.
#
# name :
#   minuscules, chiffres et underscore
#   30 caractères maximum
#
# mode :
#   listed
#   all
#   allbots (défaut)
#
# Un profil génère un snippet dédié :
# snippets/challenge-<name>.conf

profiles:

  # - name: forgejo
  #   mode: allbots
  #   exempt_ua_regex: '^forgejo-runner/'

  # - name: wiki
  #   mode: all
  #   exempt_path_regex: '^/(api/|[.]well-known/)'


# ── Conteneur géré par NGX Ops ──────────────────────────────────────────

# Démarrer/recréer automatiquement le conteneur au démarrage.
enable: false

# Image utilisée pour le moteur.
# Si vide :
#   CHALLENGE_DEFAULT_IMAGE / ANUBIS_DEFAULT_IMAGE
container_image: ""

# Secret utilisé par le moteur.
# S'il est vide, NGX Ops génère et conserve automatiquement un secret.
secret: ""

# Difficulté du moteur Builtin.
#
# Valeurs supportées : 8 à 64.
#
# Chaque bit supplémentaire double approximativement
# le travail nécessaire.
difficulty_bits: 16

# Durée de validité du cookie du moteur Builtin.
# Valeurs : 1 à 720 heures.
cookie_hours: 24

# Langue de la page de Challenge :
#   auto
#   fr
#   en
language: auto

# Autoriser les bons robots après vérification DNS inverse.
goodbots: true

# Ajouter des bons robots personnalisés.
#
# Format :
# nom|regex-UA|.suffixe[,.suffixe][;nom2|...]
goodbots_extra: ""

# Difficulté Anubis.
anubis_difficulty: 4

# Anubis : domaines autorisés pour les redirections.
redirect_domains: ""

# Anubis : domaine utilisé pour le cookie.
cookie_domain: ""
```

> **Conseil :** après toute modification d'un paramètre `challenge_*`, utiliser **Régénérer et recharger Nginx** afin que NGX Ops régénère les snippets et applique la nouvelle configuration.
