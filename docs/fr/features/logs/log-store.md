# Log store : journal centralisé

Le **log store** est un service facultatif qui centralise les journaux de NGX Ops : accès Nginx, décisions du challenge, du WAF émulé, des blocklists et de CrowdSec. Il permet la recherche, les statistiques de visites, l'analyse de sécurité et l'historique par adresse IP.

Il se compose d'une API (Go) et d'une base **PostgreSQL avec TimescaleDB**. Il est autonome : ni le dashboard ni le Hub ne l'embarquent, ils le consultent en HTTPS.

```
analyseur / shipper ──lots gzip, HTTPS, jeton write──► log store (API) ──► PostgreSQL + TimescaleDB
dashboard / Hub ───────────── jeton read ────────────►        (le port de la base n'est jamais publié)
```

Sans log store, rien ne change pour le reste de la suite.

## Installation

Le log store est livré avec un exemple de `docker-compose` (service API et base TimescaleDB). Copier le fichier d'exemple des variables, renseigner les deux valeurs obligatoires, puis démarrer :

```bash
cp sample.env logstore.env
# renseigner LOGSTORE_DB_PASSWORD et LOGSTORE_ADMIN_TOKEN (openssl rand -hex 32)
docker compose --env-file logstore.env -f docker-compose.example.yml up -d
curl -s localhost:8443/v1/health
```

La réponse attendue est `{"status":"ok"}`. Le jeton d'administration sert uniquement à créer les jetons d'accès : il est haché au premier démarrage.

!!! warning "TLS"
    Le log store exige TLS par défaut (`LOGSTORE_TLS_CERT` et `LOGSTORE_TLS_KEY`). `LOGSTORE_INSECURE_HTTP=true` est réservé à un réseau Docker interne ou à un reverse proxy TLS de confiance.

## Les jetons

Deux rôles existent :

| Rôle | Usage | Portée |
| ---- | ----- | ------ |
| `write` | Envoyer des journaux (le shipper) | Lié à **une instance** (`instance_id`) |
| `read` | Consulter | Avec `instance_id` : un dashboard ne voit que ses propres journaux. Sans `instance_id` : vue globale, réservée au Hub et à l'administration |

Création d'un jeton (exemple pour un serveur `web1`) :

```bash
curl -s -H "Authorization: Bearer $LOGSTORE_ADMIN_TOKEN" \
  -d '{"label":"web1","role":"write","instance_id":"web1"}' \
  localhost:8443/v1/tokens
```

Le jeton n'est affiché **qu'une seule fois**. Il est stocké haché (SHA-256), comparé à temps constant, et peut être révoqué.

L'interface `https://<log store>/ui/` permet de voir, créer et révoquer les jetons après saisie du jeton d'administration (conservé en mémoire dans l'onglet, jamais stocké). Elle se désactive avec `LOGSTORE_UI=false`. Si possible, restreindre `/ui/` par adresse IP au niveau du reverse proxy.

## Données personnelles : le mode des IP

Le mode est appliqué **à l'ingestion, côté log store** : aucun producteur ne peut le contourner. Il n'est pas rétroactif.

| Mode | Valeur stockée | Recherche par IP |
| ---- | -------------- | ---------------- |
| `clear` | L'adresse | Oui |
| `truncated` | Le préfixe /24 (IPv4) ou /48 (IPv6) | Oui, ramenée au préfixe |
| `pseudonymized` | Une empreinte HMAC-SHA256 tronquée, sans adresse | Oui, grâce à la clé |

En mode `pseudonymized`, `LOGSTORE_PSEUDO_KEY` (32 caractères minimum) est obligatoire et le service refuse de démarrer sans elle. La changer casse la corrélation entre avant et après.

Aucune query string brute ni referer complet n'est stocké : seulement une empreinte et l'hôte.

## Rétention

| Réglage | Plage |
| ------- | ----- |
| Journaux bruts | 7 à 30 jours |
| Cumuls (agrégats horaires et journaliers) | 30 à 800 jours |

Les variables ne servent qu'à l'initialisation. Ensuite, la rétention et le mode des IP se modifient à chaud avec `PUT /v1/settings` (rôle administrateur).

## Maintenance PostgreSQL

La purge, la compression et la rétention TimescaleDB sont automatiques. En plus, le service exécute un `VACUUM (ANALYZE)` des tables toutes les `LOGSTORE_MAINTENANCE_HOURS` (24 h par défaut, premier passage une dizaine de minutes après le démarrage). `LOGSTORE_MAINTENANCE=false` coupe cette tâche, l'autovacuum PostgreSQL restant actif.

L'état de la maintenance (lignes mortes, compression, rétention respectée) est visible dans la section « Maintenance PostgreSQL » de l'interface `/ui/` et via `GET /v1/maintenance` ; `POST /v1/maintenance` la lance immédiatement.

## Variables principales

| Variable | Rôle |
| -------- | ---- |
| `LOGSTORE_DB_PASSWORD` | Mot de passe PostgreSQL (obligatoire) |
| `LOGSTORE_ADMIN_TOKEN` | Jeton d'administration, 32 caractères minimum (obligatoire) |
| `LOGSTORE_IP_MODE` | Mode initial des IP : `clear`, `truncated`, `pseudonymized` |
| `LOGSTORE_PSEUDO_KEY` | Clé de pseudonymisation |
| `LOGSTORE_RETENTION_DAYS` | Rétention initiale des journaux bruts (7 à 30) |
| `LOGSTORE_TLS_CERT` / `LOGSTORE_TLS_KEY` | Certificat TLS monté dans le conteneur |
| `LOGSTORE_INSECURE_HTTP` | HTTP clair, réseau interne uniquement |
| `LOGSTORE_REQUIRE_TIMESCALE` | `true` : refuse de démarrer sans TimescaleDB |
| `LOGSTORE_UI` | Interface `/ui/` (`true` par défaut) |
| `LOGSTORE_RATE_READ` / `LOGSTORE_RATE_WRITE` | Requêtes par seconde et par jeton (20 / 10) |
| `LOGSTORE_MAX_BATCH_EVENTS` | Taille maximale d'un lot (5000) |
| `LOGSTORE_QUERY_TIMEOUT_SECONDS` | Délai maximal d'une requête (15) |

Deux rôles PostgreSQL séparés (lecture seule et écriture seule) sont possibles avec `LOGSTORE_DATABASE_URL_READ` et `LOGSTORE_DATABASE_URL_WRITE`.

## Sécurité

* TLS exigé par défaut, port PostgreSQL jamais publié, conteneur non-root avec système de fichiers en lecture seule.
* Limitation de débit par jeton et frein sur les échecs d'authentification.
* Tailles bornées partout (corps, lot, ligne, taille décompressée), SQL paramétré, fenêtre de recherche de 31 jours au plus.
* Erreurs sans détail interne ; aucun jeton ni mot de passe dans les journaux.

## Limites connues

* Sans TimescaleDB, le log store fonctionne en mode « PostgreSQL simple » : ni compression ni cumuls longs. Réservé au développement et aux tests.
* Le nombre de visiteurs distincts n'est disponible que sur la période encore stockée en brut.
* Les cumuls sont calculés en UTC.

Pour envoyer les journaux vers le log store, voir [Shipper et page Journaux](shipper.md). Pour les ordres de grandeur de volume et de performances, voir [Capacité et performances](log-store-capacity.md).
