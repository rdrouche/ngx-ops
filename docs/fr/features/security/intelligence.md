# NGX Ops Intelligence

**NGX Ops Intelligence** est une plateforme **facultative** de renseignement sur les menaces. Elle reçoit les alertes des instances NGX Ops, les corrèle, construit une réputation par adresse IP et publie des listes que chaque instance peut ensuite appliquer avec [Blocklists IP](blocklist-ips.md).

Chaque instance reste autonome : si la plateforme est indisponible, rien ne change côté Nginx.

!!! info "Service SaaS"
    [NGX Ops Intelligence](https://intelligence.ngx-ops.net/) est un **service SaaS** : il n'y a rien à installer de ce côté. Cette page décrit le fonctionnement côté NGX Ops, la fonction restant **désactivée par défaut**.

## Envoyer les alertes depuis NGX Ops

L'envoi est **désactivé par défaut**. Il se configure dans `config/intelligence.yml`, ou avec le bouton **Configurer** de la carte *NGX Ops Intelligence* de la page Analyse. Le formulaire valide la saisie, propose **Enregistrer et tester**, et n'affiche jamais le jeton.

### Les deux modes

| Mode | L'instance se présente avec | Confiance côté plateforme |
|---|---|---|
| `anonymous` | Son identifiant `INSTANCE_ID` seul (visible dans la page Système) | Faible |
| `identified` | `INSTANCE_ID`, une adresse de courriel et un jeton | Plus élevée |

En mode `identified`, le compte et le jeton sont créés sur la plateforme (rubrique **My instances**). Le jeton peut aussi venir de la variable `INTEL_TOKEN`, prioritaire sur le fichier.

```yaml
enable: true
mode: identified
api_url: "https://intelligence.example.org/api/alerts/send"
user: "vous@example.org"
# token: via la variable INTEL_TOKEN de préférence
```

L'adresse doit être en **HTTPS**, sans identifiants dans l'URL. Sa valeur par défaut vient de `INTEL_API_URL` ; la clé `api_url` la remplace.

### Ce qui est envoyé

| Réglage | Défaut | Effet |
|---|---|---|
| `exclude_rules` | `volumetric`, `country_traffic` | Règles dont les alertes ne partent pas. Ajoutez `waf` pour garder les alertes du WAF émulé |
| `include_rules` | vide | Si renseigné, restreint l'envoi à ces règles seulement |
| `min_severity` | `low` | Sévérité minimale : `low`, `medium` ou `high` |
| `include_challenge` | `false` | Envoie aussi les blocages automatiques du challenge intégré |
| `exclude_ips` | vide | IP et plages CIDR dont **aucune alerte** n'est jamais transmise : vos adresses, votre supervision, vos partenaires |
| `backfill_hours` | `0` | `0` : seulement les alertes futures. Sinon rejoue les N dernières heures au premier envoi (168 au maximum) |

### Ce qui reste privé

Dans tous les cas, l'alerte contient l'IP, la règle, la sévérité et des compteurs. Le reste est à votre choix :

| Réglage | Défaut | Donnée |
|---|---|---|
| `share_user_agents` | `true` | User-Agents observés |
| `share_paths` | `true` | Échantillon de chemins demandés (10 au plus) |
| `share_vhost` | `false` | Nom du vhost visé |

### Cadence

| Réglage | Défaut | Plage |
|---|---|---|
| `interval_seconds` | 300 | 60 à 3600 |
| `batch_size` | 100 | 1 à 500 |
| `timeout_seconds` | 10 | 3 à 60 |

La livraison suit un curseur sur l'identifiant d'alerte, avec des lots rejouables : un redémarrage n'envoie aucun doublon.

### Comportement en cas de réponse d'erreur

| Réponse | Comportement |
|---|---|
| 2xx | Lot traité, le curseur avance |
| 429 | Pause jusqu'à `Retry-After`, le lot est rejoué à l'identique |
| 401 ou 403 | Identité refusée : l'envoi est suspendu jusqu'à modification de la configuration |
| 413 | Lot trop gros : sa taille est divisée par deux |
| Autre 4xx | Lot invalide : abandonné et journalisé |
| 5xx, réseau, délai dépassé | Nouvel essai avec attente croissante |

### Test de connexion

Un ping part au démarrage, après toute modification du fichier, puis périodiquement (`ping_enable`, `ping_interval_minutes`, 5 par défaut). Il est sauté si un envoi vient de réussir. Le bouton **Tester la connexion** de la page **Système** affiche la latence, le serveur, l'authentification et les limites annoncées.

### Suivi

La page **Events** journalise `intelligence.sent`, `intelligence.error`, `intelligence.recovered`, `intelligence.initialized`, `intelligence.config_error` et `intelligence.config_ok`. La carte de la page Analyse affiche l'état de l'envoi et un aperçu du prochain lot.

## Utiliser les listes publiées

La plateforme publie trois listes :

| Liste | Contenu | Usage conseillé |
|---|---|---|
| `blocklist` | Adresses dont la malveillance est établie | Blocage |
| `watchlist` | Adresses douteuses | Surveillance |
| `paranoid` | Bruit faible du WAF (en option) | Challenge |

Elles se consomment comme n'importe quelle liste externe de [Blocklists IP](blocklist-ips.md), avec une action par liste :

```yaml
sources:
  - name: paranoid
    url: "https://intelligence.example.org/lists/paranoid.txt"
    action: challenge
    enable: true
```
