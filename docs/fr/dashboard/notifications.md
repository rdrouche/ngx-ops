# Notifications et événements

NGX Ops dispose de trois mécanismes complémentaires.

| Mécanisme | Pour qui | Contenu |
|---|---|---|
| **Cloche d'en-tête** | L'opérateur connecté | Ce qui mérite son attention, avec un niveau et un état lu ou non lu |
| **Journal des événements** | L'audit | Toute action, y compris administrative |
| **Courriel** | Les destinataires configurés | Une sélection d'événements |

Les webhooks, décrits dans [API REST et webhooks](api.md), sont déclenchés par le journal des événements.

## La cloche

La cloche se trouve dans l'en-tête, entre le sélecteur de langue et l'utilisateur courant. Elle remonte par exemple :

- un certificat qui arrive à expiration ou qui a expiré ;
- un certificat obtenu, renouvelé ou en échec avec Certbot ;
- une cible supervisée qui tombe, puis qui remonte ;
- un comportement anormal détecté par l'analyseur ;
- un rechargement ou un redémarrage planifié de Nginx, réussi ou en échec.

Chaque entrée a un niveau (`info`, `success`, `warning`, `error`) et un état lu ou non lu. Un badge indique le nombre de notifications non lues. Le navigateur interroge le dashboard toutes les 5 secondes par défaut (`NOTIF_POLL_INTERVAL_SEC`).

- Le fil est **partagé** entre tous les utilisateurs : l'état lu ou non lu n'est pas propre à chacun.
- Les trois rôles y ont accès, y compris `viewer`.
- Les notifications sont conservées 90 jours (`NOTIF_CENTER_RETENTION_DAYS`).

## Le journal des événements

La page **Events** liste chronologiquement les actions : démarrage d'un conteneur, sauvegarde manuelle, modification d'une règle d'analyse, connexion MFA, approbation d'un agent… Chaque événement a un type (`backup.manual`, `agents.approve`, `auth.mfa.failed`…), un auteur et des données associées.

Le journal est conservé 30 jours par défaut (`EVENTS_RETENTION_DAYS`).

## Les courriels

L'envoi de courriels se configure dans deux fichiers de `config/`. Ils sont relus à chaque envoi : une modification n'impose pas de redémarrer.

### Le serveur SMTP : `smtp.yml`

```yaml
enable: true
host: smtp.example.com
port: 587
security: tls          # tls (STARTTLS), ssl (SMTPS) ou plain
ignore_ssl: false      # true pour accepter un certificat auto-signé
from: dashboard@example.com
from_name: NGX Ops
username: user@example.com
password: secret
```

Laissez `username` vide si le serveur n'exige pas d'authentification. Ce fichier contient un mot de passe : limitez ses droits et ne le publiez pas dans un dépôt Git.

### Les événements envoyés : `notifications.yml`

Chaque section peut être activée avec `enable`, et possède sa liste de destinataires.

| Section | Événement | Réglages |
|---|---|---|
| `cert_expiry` | Certificat qui arrive à expiration | `days_before` (30), `urgent_days` (5) |
| `nginx_test_error` | Échec du test de configuration | — |
| `nginx_reload` | Rechargement de Nginx | — |
| `backup_failure` | Échec d'une sauvegarde | — |
| `analyzer_alert` | Alerte de l'analyseur (force brute, scan, flood, volumétrie) | — |

```yaml
cert_expiry:
  enable: true
  days_before: 30
  urgent_days: 5
  recipients:
    - admin@example.com
```
