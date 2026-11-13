# NGX Ops Hub

Le **Hub** donne une vue globale, **en lecture seule**, de plusieurs dashboards NGX Ops (un par serveur ou par site), sans les remplacer. Il centralise aussi les [sauvegardes](backups.md) de leur configuration.

C'est un conteneur Node.js autonome. Il stocke ses données dans SQLite (sans dépendance supplémentaire) ou, en option, dans PostgreSQL.

```
navigateur ──HTTPS──► Nginx (TLS) ──► Hub ──HTTPS (pull, lecture seule)──► dashboard A / B / C
                                      │
                                      ├─ base : inventaire, jetons chiffrés, historique 30 jours
                                      └─ /data/backups : archives des sauvegardes
```

Le Hub **interroge** les dashboards, jamais l'inverse : un dashboard n'a besoin de connaître ni l'adresse ni l'existence du Hub.

## Installation

```bash
cp config/hub.sample.yml config/hub.yml        # adapter public_base_url, allow_private_networks…
cp sample.env .env
cp docker-compose.example.yml docker-compose.yml
docker compose run --rm hub node bin/hub-admin.js generate-key   # coller la valeur dans .env : HUB_SECRET_KEY=
docker compose up -d --build
docker compose logs hub      # mot de passe du compte « admin », affiché une seule fois
```

Au premier démarrage, le Hub crée le compte `admin` avec un mot de passe aléatoire écrit dans les journaux du conteneur. À la première connexion :

1. changement de mot de passe obligatoire ;
2. enrôlement MFA par QR code (obligatoire par défaut) ;
3. ajout d'une première instance.

!!! warning "Protéger les journaux de premier démarrage"
    Le mot de passe initial n'apparaît qu'une fois, mais si vos journaux Docker sont collectés ailleurs, purgez ou protégez ceux du premier démarrage.

Mot de passe initial perdu : `docker compose exec hub node bin/hub-admin.js set-password admin --must-change`. Pour imposer le mot de passe initial, utiliser `HUB_BOOTSTRAP_ADMIN_PASSWORD` ; `security.bootstrap_admin: false` désactive la création automatique (créer alors un compte avec `create-user`).

!!! danger "Clé maîtresse"
    `HUB_SECRET_KEY` (32 octets, en hexadécimal sur 64 caractères ou en base64) chiffre les jetons d'instances et les secrets MFA. **Sauvegardez-la avec le volume `/data`** : sans elle, ces données sont indéchiffrables. Elle peut aussi être fournie par `HUB_SECRET_KEY_FILE` (secret Docker).

Placez Nginx devant le Hub (un exemple, `nginx/hub.conf.example`, est fourni) avant de l'exposer. Le port du Hub est lié à `127.0.0.1`.

## Brancher un dashboard

1. Dans le Hub, **Ajouter une instance** (nom et URL HTTPS) : le Hub affiche **une seule fois** un jeton et son empreinte SHA-256.
2. Sur le dashboard, renseigner `HUB_TOKEN_SHA256=<empreinte>` puis redémarrer. Il n'y a rien d'autre à installer.
3. Au cycle suivant (60 secondes au plus), l'instance passe « En ligne ».

**Rotation du jeton** : *Modifier* → *Renouveler le jeton*. Placer les deux empreintes, séparées par une virgule, côté dashboard le temps de la bascule.

Fonctionnement de la collecte : interrogation toutes les 60 secondes (8 en parallèle, délai de 5 secondes), instance « hors ligne » après 3 échecs consécutifs, historique conservé 30 jours.

## Ce que le Hub affiche

* **Vue d'ensemble et instances** : état de chaque dashboard et historique.
* **Alertes** : globales, avec un onglet par instance.
* **Virtual hosts** : tous les vhosts de toutes les instances.
* **Onglets de module** sur la page d'une instance (trafic, sécurité, supervision, rapports…), chacun avec « Données brutes » pour voir exactement ce que le dashboard envoie. Un module absent est simplement masqué ; une partie en erreur est signalée, jamais comptée comme zéro. Les modules se règlent dans le bloc `modules:` de `hub.yml`.
* **Indicateurs** (administrateur) : une ligne par IP avec toutes les sources qui la connaissent.
* **Journaux** et **Explorateur** si le log store est branché (voir plus bas).

!!! info "Adresses IP de visiteurs"
    Ce sont des données personnelles. Elles ne sont exposées que si le dashboard a `expose_ips` **et** que le Hub a `modules.indicators.enabled: true`. Elles ne sont visibles que des administrateurs et ne sont jamais journalisées.

## Consulter le log store depuis le Hub

Désactivé par défaut. Pour l'activer, dans `hub.yml` : `logstore.enabled: true` et `logstore.url: https://…`. Le jeton `read` **global** (sans `instance_id`) du [log store](../features/logs/log-store.md) se place dans `HUB_LOGSTORE_TOKEN` ou `HUB_LOGSTORE_TOKEN_FILE`, jamais dans `hub.yml`.

* Onglet **Journaux** : visites par code de statut, sécurité, blocages et tops (sites, pays, règles, types de clients, sources), de 24 heures à 31 jours, par instance. Aucune IP, aucun chemin, aucun User-Agent ni journal brut n'est relayé par cette page.
* **Corrélation par IP** (option `logstore.indicators.enabled`) : fusionne, dans les Indicateurs, l'activité par IP du log store. Une campagne probable est une IP vue par au moins 2 instances ou par au moins 3 types de signaux.
* **Explorateur** (option `logstore.explorer.enabled`, en plus de ce qui précède) : recherche de journaux bruts multi-instances, fiche IP, top des attaques et des sources, campagnes. Il manipule des données personnelles : réservé aux administrateurs, avec limitation de débit, **sans aucun stockage** dans le Hub. Le mode des IP du log store (clair, /24 ou pseudonymisé) est respecté.

## Variables

Toute clé absente prend sa valeur par défaut. Les variables d'environnement l'emportent sur `hub.yml`.

| Variable | Clé de `hub.yml` | Rôle |
| -------- | ---------------- | ---- |
| `HUB_SECRET_KEY` / `HUB_SECRET_KEY_FILE` | jamais dans le YAML | Clé maîtresse |
| `HUB_PUBLIC_BASE_URL` | `server.public_base_url` | URL publique, affichée dans les URL d'envoi des sauvegardes |
| `HUB_PORT`, `HUB_HOST`, `HUB_DATA_DIR`, `HUB_COOKIE_SECURE`, `HUB_LOG_LEVEL`, `HUB_CONFIG` | `server.*`, `log.level` | Serveur et journaux |
| `HUB_BOOTSTRAP_ADMIN_PASSWORD` | — | Mot de passe initial imposé (12 caractères minimum) |
| `HUB_LOGSTORE_ENABLED`, `HUB_LOGSTORE_URL` | `logstore.enabled`, `logstore.url` | Lecture du log store |
| `HUB_LOGSTORE_TOKEN` / `_FILE` | jamais dans le YAML | Jeton `read` du log store |
| `HUB_DB_DRIVER`, `HUB_DB_HOST`, `HUB_DB_PORT`, `HUB_DB_NAME`, `HUB_DB_USER` | `storage.*` | PostgreSQL |
| `HUB_DB_PASSWORD` / `_FILE` | jamais dans le YAML | Mot de passe PostgreSQL |

## Sécurité

* Le Hub n'envoie qu'un `GET` aux dashboards, qui n'exposent que des compteurs et des états (aucun secret, aucune IP de visiteur).
* Jetons d'instance de 256 bits, chiffrés (AES-256-GCM) dans la base ; le dashboard ne garde que l'empreinte SHA-256.
* Protection contre les requêtes vers des destinations internes (SSRF) : HTTPS imposé, DNS validé à chaque connexion, adresses de métadonnées cloud toujours bloquées, réseaux privés autorisés seulement avec `allow_private_networks` ou `allowed_cidrs`, aucune redirection suivie, certificat toujours vérifié (autorité interne avec `extra_ca_file`).
* Authentification : mots de passe hachés, verrouillage après 5 échecs (15 minutes), TOTP avec anti-rejeu, cookie `HttpOnly`, `Secure`, `SameSite=Strict`, jeton CSRF, CSP stricte.
* Journal d'audit des connexions, modifications et rotations, conservé 365 jours.
* Conteneur non-root, système de fichiers en lecture seule, capacités retirées.

À prévoir côté infrastructure : restreindre l'accès au vhost Nginx (VPN ou liste d'adresses autorisées) et ne laisser au Hub que la sortie vers les dashboards.

## Langue

Un sélecteur FR / EN dans l'en-tête mémorise le choix par navigateur ; `ui.default_language` règle la valeur par défaut.
