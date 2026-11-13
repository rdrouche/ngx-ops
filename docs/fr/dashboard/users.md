# Utilisateurs et rôles

## Les comptes

Les comptes sont définis dans le fichier `config/users.yml`. Ce fichier est la **source de vérité** : le dashboard liste les comptes et sait calculer l'empreinte d'un mot de passe, mais il ne réécrit pas ce fichier à votre place. Il peut ainsi être versionné avec le reste de la configuration.

```yaml
users:
  - username: admin
    password: mon-mot-de-passe
    role: admin
    name: Administrateur
    enabled: true
```

| Champ | Rôle |
|---|---|
| `username` | Identifiant de connexion |
| `password` | Mot de passe en clair, ou empreinte `sha256:<sel>:<hash>` |
| `role` | `admin`, `operator` ou `viewer` |
| `name` | Nom affiché |
| `enabled` | `false` désactive le compte sans le supprimer |

Un mot de passe écrit en clair dans le fichier est **remplacé par son empreinte au premier démarrage**. Pour calculer une empreinte vous-même, la route `POST /api/auth/hash` (réservée aux administrateurs) la renvoie sans rien enregistrer.

## Premier démarrage

Tant qu'un compte garde un mot de passe d'exemple connu, le dashboard :

- l'inscrit dans ses journaux à chaque démarrage ;
- crée l'événement `auth.default_credentials`, visible dans le journal.

Pour le compte `admin` livré avec le mot de passe `admin`, le dashboard le remplace par un mot de passe aléatoire, affiché **une seule fois** dans les journaux du conteneur :

```bash
docker compose logs nginx-dashboard
```

Si vous choisissez vous-même le mot de passe, modifiez `users.yml` **avant** le premier démarrage. Une valeur différente de `admin` n'est jamais remplacée.

## Les rôles

| Permission | `admin` | `operator` | `viewer` |
|---|:---:|:---:|:---:|
| Métriques, vhosts, upstreams | ✓ | ✓ | ✓ |
| Fichiers de configuration | ✓ | ✓ | ✓ |
| Journaux | ✓ | ✓ | ✓ |
| Certificats SSL | ✓ | ✓ | ✓ |
| CrowdSec et GoAccess | ✓ | ✓ | ✓ |
| Tester et recharger Nginx | ✓ | ✓ | — |
| Déploiement Git et sauvegardes | ✓ | ✓ | — |
| Documentation interactive de l'API | ✓ | — | — |
| Webhooks | ✓ | — | — |
| Gestion des utilisateurs | ✓ | — | — |

Le rôle `viewer` est en lecture seule. Le rôle `operator` exploite Nginx sans administrer le dashboard.

Deux rôles internes existent, qui ne correspondent à aucun compte :

- le **jeton d'API** `API_TOKEN` s'authentifie avec les droits de `admin` : conservez-le comme un mot de passe administrateur ;
- les **jetons de déploiement** (`config/deploy-tokens.yml`) et les **jetons d'agent** n'ouvrent que quelques routes précises, pas le reste de l'API. Voir [GitOps](../features/git.md).

## Sessions et protection contre la force brute

| Réglage | Défaut | Effet |
|---|---|---|
| `SESSION_TTL_HOURS` | 8 | Durée d'une session, renouvelée tant que l'utilisateur est actif |
| `SESSION_MAX_HOURS` | 24 | Durée maximale absolue, même avec une activité continue |
| `LOGIN_MAX_ATTEMPTS` | 10 | Échecs de connexion tolérés |
| `LOGIN_WINDOW_MIN` | 15 | Fenêtre de comptage des échecs, en minutes |
| `LOGIN_LOCKOUT_MIN` | 15 | Durée du blocage, en minutes |

Derrière un reverse proxy, `TRUSTED_PROXIES` indique quelles adresses peuvent fixer `X-Forwarded-For` : sans cela, le blocage s'appliquerait à l'adresse du proxy et non à celle du visiteur.

La page **Users** affiche aussi les sessions actives, pour les administrateurs.

L'authentification en deux étapes est décrite dans [MFA](mfa.md).
