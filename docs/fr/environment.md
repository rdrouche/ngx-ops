# Variables d'environnement

Cette page décrit les variables du **dashboard**, puis les variables essentielles des autres composants. Elle suit la page **Système** du dashboard, réservée aux administrateurs, qui affiche pour chaque réglage sa valeur courante, sa valeur par défaut et l'endroit où le modifier.

## Règles générales

- Les variables se placent dans le fichier `.env` à côté du fichier compose. **Pas de guillemets** autour des valeurs.
- Pour un même réglage, la priorité est : **variable d'environnement**, puis **fichier YAML** de `config/` lorsqu'il existe, puis valeur par défaut. Une valeur définie dans `.env` l'emporte donc toujours.
- Aucun secret n'est obligatoire pour démarrer. Quand ils sont absents, le dashboard génère une fois les secrets suivants et les conserve dans `config/.generated-secrets.json` : `SESSION_SECRET`, `WAF_TOKEN`, `SHIPPER_LOCAL_TOKEN`, `NC_SECRET` et `INSTANCE_ID`.
- Les secrets s'affichent dans la page **Système** sous la forme « configuré » ou « non configuré », jamais en clair.
- Une variable marquée **build** se fixe à la construction de l'image (`build.args` du compose) et peut aussi être surchargée à l'exécution.
- Pour générer un secret : `openssl rand -hex 32`.

## Dashboard

### Général

| Variable | Défaut | Rôle |
|---|---|---|
| `PORT` | `3000` | Port d'écoute interne. Le port publié se règle dans `ports:` du compose |
| `NGINX_CONTAINER` | `nginx` | Nom du conteneur Nginx à piloter (test, rechargement, statistiques) |
| `NGINX_IMAGE` | détectée | Image du conteneur éphémère qui teste une configuration avant déploiement |
| `NGINX_NETWORK` | `nginx-net` | Réseau Docker partagé, utilisé pour le conteneur de test et la résolution DNS |
| `NGINX_VTS_URL` | `http://nginx:8080/status.json` | Point d'accès du module VTS qui fournit les statistiques par vhost |
| `NGINX_CONF_FILE` | `/etc/nginx/nginx.conf` | Chemin de `nginx.conf` dans le conteneur Nginx |
| `NOTIF_POLL_INTERVAL_SEC` | `5` | Fréquence d'interrogation des notifications par le navigateur (minimum 2) |
| `INSTANCE_ID` | généré | Identifiant unique de l'installation (UUID), qui n'est pas un secret |
| `HTTP_USER_AGENT` | `NGXOps` | User-Agent de toutes les requêtes sortantes, sans numéro de version pour pouvoir le filtrer |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Socket Docker utilisé pour piloter Nginx et les conteneurs gérés |

### Sécurité et sessions

| Variable | Défaut | Rôle |
|---|---|---|
| `SESSION_SECRET` | généré | Clé de signature des sessions |
| `SESSION_TTL_HOURS` | `8` | Durée d'une session, renouvelée tant que l'utilisateur est actif |
| `SESSION_MAX_HOURS` | `24` | Durée maximale d'une session, même active |
| `LOGIN_MAX_ATTEMPTS` | `10` | Échecs de connexion tolérés avant blocage temporaire |
| `LOGIN_WINDOW_MIN` | `15` | Fenêtre de comptage des échecs, en minutes |
| `LOGIN_LOCKOUT_MIN` | `15` | Durée du blocage, en minutes |
| `API_TOKEN` | désactivé | Jeton de l'API REST (`Authorization: Bearer`). Il reste inactif s'il est vide, s'il commence par `changeme` ou s'il fait moins de 16 caractères |
| `WEBHOOK_SECRET` | non configuré | Secret de signature des webhooks sortants |
| `CORS_ORIGIN` | vide | Origine autorisée en cross-origin. Vide : même origine uniquement, ce qui est recommandé |
| `TRUSTED_PROXIES` | réseaux privés et loopback | Adresses autorisées à fixer `X-Forwarded-For` |
| `HEALTH_PUBLIC` | `true` | Route publique `/health`. `false` la désactive |
| `MFA_RP_ID` | déduit de `Host` | Domaine WebAuthn pour les clés de sécurité. À fixer derrière un proxy qui réécrit `Host` |
| `MFA_ORIGIN` | déduit | Origines HTTPS autorisées pour WebAuthn, séparées par des virgules |

L'API et les webhooks se règlent aussi depuis la page **Système** : le bouton **Générer** affiche la valeur une seule fois et ne conserve que son empreinte.

### Déploiement et sauvegardes

| Variable | Défaut | Rôle |
|---|---|---|
| `ALLOW_EDIT` | `false` | Autorise l'édition des fichiers de configuration depuis l'interface |
| `ALLOW_CREATE` | `false` | Autorise la création de fichiers. Sans effet quand Git est configuré |
| `DEPLOY_SYNC_SSL` | `true` | Inclut `ssl/` dans le déploiement Git. `certs/` n'est jamais synchronisé |
| `GIT_REPO_URL` | vide | Dépôt de référence. Vide : déploiement Git désactivé |
| `GIT_BRANCH` | `main` | Branche source |
| `GIT_BACKUP_BRANCH` | `backup` | Branche qui reçoit l'état précédent avant chaque déploiement |
| `GIT_TOKEN` | vide | Jeton HTTPS du dépôt |
| `GIT_SSH_KEY` | vide | Chemin de la clé SSH dans le conteneur, à monter en volume |
| `GIT_USER_NAME`, `GIT_USER_EMAIL` | `Nginx Dashboard`, `dashboard@localhost` | Identité des commits |
| `BACKUP_KEEP` | `20` | Nombre de sauvegardes ZIP locales conservées |
| `BACKUP_PASSPHRASE` | vide | Phrase de passe commune de repli pour les archives chiffrées |
| `HUB_BACKUP_PASSPHRASE` | vide | Phrase de passe des sauvegardes envoyées au Hub |
| `S3_BACKUP_PASSPHRASE` | vide | Phrase de passe de l'archive envoyée vers S3 |

Une phrase de passe perdue rend l'archive chiffrée irrécupérable : conservez-les en dehors du dashboard.

### Répertoires

Les variables `DIR_*` indiquent où les volumes sont montés **dans le conteneur du dashboard**. Elles doivent correspondre aux volumes du compose.

| Variable | Défaut |
|---|---|
| `DIR_SITES` | `/nginx/sites` |
| `DIR_CONF` | `/nginx/conf` |
| `DIR_SNIPPETS` | `/nginx/snippets` |
| `DIR_STREAMS` | `/nginx/streams` |
| `DIR_SSL` | `/nginx/ssl` |
| `DIR_CERTS` | `/nginx/certs` |
| `DIR_LOGS` | `/nginx/logs` |
| `DIR_CACHE` | vide, ce qui désactive le bouton de vidage du cache |
| `DIR_BACKUPS` | `/nginx/backups` |
| `DIR_GIT_WORK` | `/git-work` |
| `DIR_GOACCESS` | `/nginx/goaccess` |
| `DIR_GEOIP` | `/geoip` |

`HOST_LOGS` et `HOST_GOACCESS` sont différentes : ce sont des chemins **absolus sur l'hôte**, utilisés pour les volumes des conteneurs que le dashboard crée. Docker résout ces chemins côté hôte, un chemin qui n'existe que dans le conteneur du dashboard monterait un dossier vide.

### Intégrations

| Variable | Défaut | Rôle |
|---|---|---|
| `CROWDSEC_PROMETHEUS_URL` | vide | Point d'accès Prometheus du moteur CrowdSec (recommandé) |
| `CROWDSEC_LOCAL_ONLY` | `false` | N'affiche que les décisions locales |
| `CROWDSEC_URL`, `CROWDSEC_API_KEY` | vides | API locale CrowdSec et clé de bouncer, en lecture seule |
| `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD` | vides | Identité machine, nécessaire pour bannir, débannir et gérer les listes blanches |
| `GOACCESS_IMAGE` | `allinurl/goaccess:latest` | Image de GoAccess |
| `GOACCESS_LOG_FORMAT` | `COMBINED` | Format de journal lu par GoAccess |
| `GOACCESS_REFRESH` | `30` | Régénération du rapport, en secondes |
| `GEOIP_CITY_DB`, `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB` | `/geoip/GeoLite2-*.mmdb` | Chemins des bases MaxMind |
| `GODNS_IP_CHECK` | `true` | Vérifie l'IP publique rapportée par GoDNS auprès de plusieurs services |
| `GODNS_IP_CHECK_URLS` | ipify, icanhazip, ifconfig.me | Services interrogés pour cette vérification |
| `REDIS_URL` | vide | Adresse du Redis optionnel, par exemple `redis://redis:6379/0` |
| `REDIS_PASSWORD` | vide | Mot de passe Redis, obligatoire quand Redis est utilisé |
| `REDIS_PREFIX` | `INSTANCE_ID` ou `ngx` | Préfixe des clés Redis |

### Analyse, WAF, challenge et journal centralisé

| Variable | Défaut | Rôle |
|---|---|---|
| `ANALYZER_DEFAULT_IMAGE` | image de l'analyseur de la suite (**build**) | Image par défaut du conteneur d'analyse |
| `WAF_DEFAULT_IMAGE` | `ANALYZER_DEFAULT_IMAGE` (**build**) | Image du WAF émulé |
| `WAF_TOKEN` | généré | Secret partagé avec le WAF émulé |
| `CHALLENGE_DEFAULT_IMAGE` | image du challenge de la suite (**build**) | Image du challenge navigateur |
| `ANUBIS_DEFAULT_IMAGE` | `ghcr.io/techarohq/anubis:latest` (**build**) | Image du moteur Anubis |
| `AGENT_DEFAULT_IMAGE` | image de l'agent de la suite (**build**) | Image proposée dans le kit de déploiement des agents |
| `NC_SECRET` | généré | Secret de signature des cookies du challenge |
| `NC_DIFFICULTY_BITS` | `16` | Difficulté de la preuve de travail (8 à 64) |
| `NC_COOKIE_HOURS` | `24` | Validité du cookie « navigateur vérifié », de 1 à 720 heures |
| `NC_GOODBOTS` | `true` | Laisse passer les robots d'indexation dont le DNS inverse est confirmé |
| `NC_GOODBOTS_EXTRA` | vide | Robots supplémentaires : nom, expression régulière du User-Agent et suffixe DNS, séparés par une barre verticale (format détaillé dans `sample.env`) |
| `NC_LANG` | `auto` | Langue de la page de vérification : `auto`, `fr` ou `en` |
| `SHIPPER_DEFAULT_IMAGE` | `ANALYZER_DEFAULT_IMAGE` | Image du shipper |
| `SHIPPER_LOCAL_TOKEN` | généré | Jeton local partagé entre dashboard, shipper et WAF (24 caractères minimum) |
| `LOGSINK_TOKEN` | vide | Jeton `write` de cette instance, utilisé par le shipper |
| `LOGSTORE_READ_TOKEN` | vide | Jeton `read` du log store, utilisé par la page **Journaux** |
| `INTEL_API_URL` | vide (**build**) | Adresse de la plateforme Intelligence |
| `INTEL_TOKEN` | vide | Jeton du mode identifié d'Intelligence |

Les réglages de ces fonctions (activation, limites, chemins) se trouvent dans les fichiers de `config/` : `analyzer.yml`, `waf.yml`, `challenge.yml`, `logstore.yml`, `intelligence.yml`. Ils sont modifiables depuis les pages correspondantes du dashboard.

### Rétention et maintenance

| Variable | Défaut | Rôle |
|---|---|---|
| `EVENTS_RETENTION_DAYS` | `30` | Conservation du journal d'événements |
| `MONITOR_RETENTION_DAYS` | `30` | Conservation de l'historique de supervision. Un incident ouvert n'est jamais purgé |
| `NOTIF_CENTER_RETENTION_DAYS` | `90` | Conservation des notifications |
| `DB_COMPACT_ON_START` | `auto` | Compactage SQLite au démarrage : `auto`, `always` ou `off` |
| `DB_COMPACT_MIN_FREE_MB` | `16` | Espace libre minimal qui déclenche le compactage en mode `auto` |
| `DB_COMPACT_MIN_FREE_PCT` | `20` | Part minimale de pages libres qui déclenche le compactage en mode `auto` |

### Interface et menu

| Variable | Défaut | Rôle |
|---|---|---|
| `BRANDING_HEADER_TEXT` | vide | Texte affiché dans l'en-tête (nom de client, environnement) |
| `BRANDING_DOC`, `BRANDING_DOC_LABEL` | vide, `Documentation` | Lien vers la documentation, en bas du menu (**build**) |
| `BRANDING_SITE`, `BRANDING_SITE_LABEL` | vides | Lien vers un site (**build**) |
| `BRANDING_REPO`, `BRANDING_REPO_LABEL` | vide, `Source repository` | Lien vers le dépôt (**build**) |
| `BRANDING_KOFI`, `BRANDING_KOFI_LABEL` | vide, `Support on Ko-fi` | Lien de soutien. Vide : masqué (**build**) |
| `MENU_WAF`, `MENU_GODNS`, `MENU_API`, `MENU_WEBHOOKS`, `MENU_DOCKER_AUTOCONFIG`, `MENU_AGENTS`, `MENU_GOACCESS` | `auto` | Visibilité des menus optionnels : `auto`, `show` ou `hide` (GoDNS n'a pas de mode `auto` : `show` par défaut). Réglable aussi dans `menu.yml` |

### Mise à jour et synchronisation

| Variable | Défaut | Rôle |
|---|---|---|
| `SYNC_REF_URL` | vide | Dépôt de référence pour la synchronisation de snippets et de configuration |
| `SYNC_REF_PATH_PREFIX` | vide | Sous-dossier du dépôt de référence, si `conf`, `sites`, `snippets` et `streams` n'y sont pas à la racine |
| `DASHBOARD_VERSION_URL`, `NGINX_VERSION_URL` | vides | Adresses consultées pour détecter une nouvelle version. Vides : vérification désactivée |
| `CHANGELOG_URL` | vide | Adresse du changelog affiché par le bouton **Changelog** |
| `ALERTING_URL`, `ALERTING_POLL_INTERVAL_MIN` | vide, `60` | Messages importants distribués par une adresse Markdown, avec un intervalle minimal de 5 minutes |

## Nginx

Variables lues par le compose, dans `.env` :

| Variable | Défaut | Rôle |
|---|---|---|
| `NGINX_TAG` | voir `sample.env` | Tag de l'image Nginx |
| `NGINX_RESTART_POLICY` | `always` | Politique de redémarrage |
| `NGINX_WORKER_PROCESSES` | `auto` | Nombre de processus de travail |
| `NGINX_WORKER_CONNECTIONS` | `768` | Connexions par processus |

## Hub

Fichier `.env` de `nginx-hub/`. Le reste de la configuration est dans `config/hub.yml`.

| Variable | Rôle |
|---|---|
| `HUB_SECRET_KEY` | Clé maître qui chiffre les jetons des instances. Se génère avec `docker compose run --rm hub node bin/hub-admin.js generate-key`. À sauvegarder avec les données |
| `HUB_PORT` | Port d'écoute, `8090` par défaut |
| `HUB_BOOTSTRAP_ADMIN_PASSWORD` | Mot de passe initial imposé au compte `admin` (12 caractères minimum, changement obligatoire à la première connexion). Sans lui, un mot de passe aléatoire est affiché une fois dans les logs |
| `HUB_LOG_LEVEL` | Niveau de journalisation, `info` par défaut |
| `HUB_LOGSTORE_TOKEN`, `HUB_LOGSTORE_URL` | Jeton `read` global et adresse du log store, pour la vue **Journaux** |
| `HUB_DB_DRIVER`, `HUB_DB_HOST` | Utilisation de PostgreSQL à la place de SQLite |

En production, préférez un secret Docker (`HUB_SECRET_KEY_FILE`, `HUB_LOGSTORE_TOKEN_FILE`) à une variable en clair.

## Log store

| Variable | Défaut | Rôle |
|---|---|---|
| `LOGSTORE_DB_PASSWORD` | à définir | Mot de passe PostgreSQL |
| `LOGSTORE_ADMIN_TOKEN` | à définir | Jeton d'administration (32 caractères minimum) qui sert à créer les jetons `write` et `read` |
| `LOGSTORE_IP_MODE` | `clear` | Mode initial des adresses IP : `clear`, `pseudonymized` ou `truncated` |
| `LOGSTORE_PSEUDO_KEY` | vide | Clé de pseudonymisation, obligatoire en mode `pseudonymized` (32 caractères minimum) |
| `LOGSTORE_RETENTION_DAYS` | `30` | Rétention initiale des journaux bruts, de 7 à 30 jours |
| `LOGSTORE_TLS_CERT`, `LOGSTORE_TLS_KEY` | vides | Certificat TLS monté dans le conteneur |
| `LOGSTORE_INSECURE_HTTP` | `true` dans l'exemple | HTTP clair, réservé au réseau interne ou derrière un proxy TLS de confiance |
| `LOGSTORE_LISTEN` | `:8443` | Adresse d'écoute |
| `LOGSTORE_REQUIRE_TIMESCALE` | voir `sample.env` | Refuse de démarrer sans TimescaleDB |
| `LOGSTORE_RATE_READ`, `LOGSTORE_RATE_WRITE` | `20`, `10` | Requêtes par seconde et par jeton |
| `LOGSTORE_MAX_BODY_BYTES`, `LOGSTORE_MAX_BATCH_EVENTS` | `4194304`, `5000` | Limites d'un lot |
| `LOGSTORE_QUERY_TIMEOUT_SECONDS` | `15` | Délai maximal d'une requête |
| `LOGSTORE_MAINTENANCE`, `LOGSTORE_MAINTENANCE_HOURS` | `true`, `24` | Maintenance planifiée de la base et son intervalle |
| `LOGSTORE_UI` | `true` | Interface web `/ui/` de gestion des jetons |

## Agent

Fichier `.env` du dossier `nginx-agent/`, sur le **serveur distant**. Le dashboard peut générer ce fichier et le fichier compose depuis la page des hôtes distants.

| Variable | Défaut | Rôle |
|---|---|---|
| `DASHBOARD_URL` | à définir | Adresse du dashboard, joignable depuis le serveur distant |
| `AGENT_HOSTNAME` | nom du conteneur | Nom proposé lors de l'enrôlement |
| `AGENT_FINGERPRINT` | vide | Empreinte libre affichée à l'opérateur au moment de l'approbation |
| `POLL_INTERVAL` | `30s` | Intervalle entre deux envois du manifeste |
| `TUNNEL_ENABLE` | `true` | Ouvre la connexion tunnel quand un vhost est en mode `tunnel` |
| `RELAY_HTTP_LISTEN`, `RELAY_HTTPS_LISTEN` | vides | Ports d'écoute du mode relais. Vides : relais désactivé |
| `RELAY_HTTP_ADVERTISE`, `RELAY_HTTPS_ADVERTISE` | vides | Adresse complète (`http://ip:port`) que Nginx utilisera pour joindre le relais |
| `RELAY_HTTPS_CERT`, `RELAY_HTTPS_KEY` | vides | Certificat du relais HTTPS. Vides : certificat auto-signé généré en mémoire |
| `RELAY_BACKEND_INSECURE_SKIP_VERIFY` | `false` | Accepte un backend HTTPS au certificat auto-signé |
| `TARGETS_FILE` | vide | Fichier JSON qui décrit plusieurs dashboards cibles |
| `INSECURE_SKIP_VERIFY` | `false` | Désactive la vérification TLS du dashboard. À ne jamais activer en production |

Le détail des modes direct, tunnel et relais est dans le README de `nginx-agent/`.
