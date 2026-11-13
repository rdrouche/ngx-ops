# Sauvegardes et base de données du Hub

## Sauvegardes des dashboards

Le Hub peut conserver les archives de sauvegarde de chaque dashboard. Dans le détail d'une instance, le panneau **Sauvegardes** (administrateur) propose deux méthodes.

### Push : le dashboard envoie

1. Cliquer sur **Activer l'envoi** : le Hub affiche **une seule fois** un jeton `HUB_PUSH_TOKEN` (seule son empreinte est conservée).
2. Le renseigner côté dashboard : la tâche `hub_backup` envoie l'archive vers le Hub.
3. Définir `server.public_base_url` pour que l'URL d'envoi soit affichée.

Nginx doit disposer de la location d'envoi de l'exemple `nginx/hub.conf.example` (corps jusqu'à `max_archive_mb`, sans mise en tampon).

### Pull : le Hub récupère

1. Cliquer sur **Activer la récupération** : le Hub affiche une empreinte à placer dans `HUB_BACKUP_TOKEN_SHA256` côté dashboard, avec `backup_enable`.
2. Le Hub va chercher le manifeste et l'archive toutes les `pull_interval_hours`, ou immédiatement avec **Récupérer maintenant**.

## Stockage et rétention

* Les archives sont stockées sous `/data/backups`, adressées par SHA-256 : deux archives identiques ne sont stockées qu'une fois.
* Rétention : la plus courte entre la durée annoncée par le dashboard et `backups.retention_days`.
* Une **alerte** est levée si aucune sauvegarde n'est reçue depuis `alert_after_hours` (36 h par défaut).
* Le **téléchargement** est réservé aux administrateurs.

## Ouvrir une archive chiffrée

Le Hub **ne connaît pas la phrase de passe** des archives. Elle est définie côté dashboard (`HUB_BACKUP_PASSPHRASE`, ou `BACKUP_PASSPHRASE` en repli).

Le bouton **Ouvrir** déchiffre l'archive **dans le navigateur** : la phrase est saisie localement et n'est jamais envoyée au Hub. Il permet de parcourir les fichiers, d'en afficher un aperçu et de télécharger un fichier ou l'ensemble en `tar.gz`. HTTPS (ou `localhost`) est requis.

L'outil en ligne de commande `ngxb-decrypt.js`, livré avec le dashboard, reste utilisable.

!!! info "Restauration"
    Le Hub conserve et permet d'ouvrir les archives, mais ne les restaure pas : la restauration se fait depuis le dashboard concerné.

## À sauvegarder pour le Hub lui-même

Le dossier `/data` (base et archives) **et** la clé maîtresse `HUB_SECRET_KEY`.

## PostgreSQL (option)

SQLite suffit pour des dizaines d'instances. PostgreSQL est utile pour la haute disponibilité, plus de 200 instances, plusieurs réplicas du Hub ou une longue rétention.

```bash
mkdir -p secrets && openssl rand -base64 24 > secrets/db_password && chmod 600 secrets/db_password
# config/hub.yml : storage.driver: postgres
WITH_PG=1 docker compose -f docker-compose.example.yml -f docker-compose.postgres.example.yml up -d --build
```

Une image prête à l'emploi existe : c'est la même image du Hub avec le suffixe de tag `-pg` (voir [Versions et mise à jour](../versions.md)). Le mot de passe passe par `HUB_DB_PASSWORD_FILE` (secret Docker) ou `HUB_DB_PASSWORD`, jamais par le YAML. Les migrations s'appliquent seules au démarrage.

!!! warning "Migration depuis SQLite"
    Le passage de SQLite à PostgreSQL n'est pas automatisé : repartir d'une base vide et ré-enregistrer les instances.

### Maintenance

* **SQLite** : `storage.sqlite_maintenance_hours` (24 h, `0` pour désactiver) effectue le checkpoint WAL, l'optimisation, un `VACUUM` si utile et une vérification. La page « Maintenance de la base » (administrateur) en montre l'état.
* **PostgreSQL** : `VACUUM (ANALYZE)` de toutes les tables toutes les `storage.postgres.maintenance_hours` (24 h, `0` pour désactiver ; l'autovacuum reste actif). Un verrou évite deux passages simultanés avec plusieurs Hub.
