# Agent **Analyseur de journaux**

Pour profiter pleinement des fonctionnalités de **NGX Ops** et l'exploitation des journaux (logs), il est nécessaire de déployer l'**Agent Analyseur de journaux**.

L'agent est écrit en **Go** : il consomme environ 40 % de mémoire en moins que l'ancienne version Node, qui n'est plus publiée. Il fonctionne dans un conteneur séparé de **NGX Ops**. Il surveille les fichiers de journaux Nginx en temps réel, analyse les requêtes et transmet les informations et alertes au tableau de bord.

L'agent permet notamment d'utiliser les fonctionnalités suivantes :

* **Analyse des journaux** : détection de comportements inhabituels ou potentiellement malveillants à partir de différentes règles, comme les tentatives répétées d'authentification, les scans, les floods ou encore certaines activités de scraping.
* **Analyse volumétrique** : détection des variations inhabituelles du volume de trafic par hôte virtuel. L'analyse tient notamment compte de la saisonnalité du trafic afin de limiter les faux positifs.
* **Analyse du trafic par pays** : détection d'une augmentation inhabituelle du trafic provenant d'un pays donné.
* **Analyse des journaux WAF** : lorsque vous utilisez une version de Nginx intégrant le WAF, comme les variantes WAF ou Coraza, l'agent peut également exploiter les journaux générés par celui-ci.
* **Affichage du trafic en temps réel** : les requêtes peuvent être visualisées en temps réel sur la carte du tableau de bord.
* **Résumés périodiques** : les données collectées et analysées permettent de générer des synthèses périodiques de l'activité du reverse proxy.

L'analyse volumétrique nécessite une période d'apprentissage afin de déterminer le comportement habituel du trafic. L'agent utilise notamment une référence par créneau horaire de la semaine et recommande environ trois semaines d'observation avant de considérer les premières alertes volumétriques comme fiables.

L'**Agent Analyseur de journaux** doit pouvoir accéder en lecture aux fichiers de logs générés par Nginx. Il fonctionne indépendamment du conteneur **NGX Ops** et communique avec celui-ci via son API.

## Déployer et configurer l'Agent Analyseur de journaux

### Déploiement de l'agent

Le déploiement et la configuration de l'**Agent Analyseur de journaux** se font directement depuis **NGX Ops**.

### Configuration de l'agent

Rendez-vous dans : **ADMINISTRATION → Configuration → Analyseur de journaux**

Dans la zone de saisie, renseignez la configuration de l'agent. Voici un exemple :

```yaml
enable: true

host_logs_path: /containers/nginx/nginx/logs
host_data_path: /containers/nginx/config/analyzer
host_geoip_path: /containers/nginx/geoip_data
```

> 💡 **Tip:** Les paramètres correspondant à des chemins (*paths*) doivent contenir les **chemins absolus sur l'hôte**. Ils sont utilisés pour configurer les *bind mounts* Docker nécessaires au fonctionnement de l'agent.

Cliquez ensuite sur **Enregistrer**.

## Démarrer l'agent

Une fois la configuration enregistrée, rendez-vous dans : **INTEGRATIONS → Analyse**

Cliquez ensuite sur le bouton **Démarrer**.

NGX Ops va alors créer et démarrer le conteneur de l'**Agent Analyseur de journaux** avec la configuration fournie.

Une fois l'agent démarré, il commence à surveiller les journaux Nginx et les données collectées peuvent être exploitées par les différentes fonctionnalités d'analyse de **NGX Ops**.

## Réglages de `analyzer.yml`

Fichier `config/analyzer.yml`, modifiable depuis **ADMINISTRATION → Configuration**.

| Clé | Défaut | Rôle |
|---|---|---|
| `enable` | `false` | Active l'agent |
| `container_image` | image `analyzer-agent-go` de la suite | Image du conteneur |
| `container_name` | `ngx-analyzer` | Nom du conteneur |
| `port` | `9100` | Port de l'API de l'agent, interne au réseau Docker |
| `host_logs_path` | — | Chemin **sur l'hôte** des journaux Nginx |
| `host_data_path` | — | Chemin sur l'hôte des données de l'agent (historique, référence apprise, règles). Obligatoire pour que le conteneur soit recréé automatiquement sans perdre son état |
| `host_geoip_path` | — | Chemin sur l'hôte des bases GeoIP |
| `log_pattern` | motif livré | Expression régulière des fichiers de journaux suivis : un fichier par vhost (`site.fr.access.log`) ou le fichier partagé livré (`vhosts_access.log`) |
| `bruteforce_min_failures` | `15` | Seuil de la règle de force brute |
| `scan_min_requests` | `40` | Seuil de la règle de scan |
| `flood_min_requests` | `600` | Seuil de la règle de flood |
| `ignore_status` | vide | Codes HTTP ignorés par toutes les règles, par exemple `444` ou `444,403`. Ils restent comptés dans les statistiques |
| `learning_days` | `21` | Période d'apprentissage de l'analyse volumétrique |
| `sigma_threshold` | `6` | Sensibilité de l'analyse volumétrique |
| `notify_min_severity` | `medium` | Sévérité minimale envoyée par courriel |
| `alert_retention_days` | `90` | Conservation des alertes |
| `shipper_url` | vide | Envoi des alertes au [log store](logs/index.md) via le shipper local, par exemple `http://ngx-shipper:9181` |
| `waf_log_pattern` | motif livré (`*.waf.log`) | Expression régulière des journaux d'audit ModSecurity, un fichier par vhost, au format JSON |
| `waf_retention_days` | `60` | Conservation des données WAF |

Les seuils volontairement hauts évitent un détecteur qui « crie au loup ». Ajustez-les d'après vos alertes plutôt que de les baisser par principe.

Les clés `rule_*_enable` (`bruteforce`, `scan`, `flood`, `scraping`, `volumetric`, `country_traffic`) ne servent qu'au **tout premier démarrage**. Ensuite l'agent mémorise lui-même l'activation de chaque règle : modifiez-la depuis le bouton **Règles** de la page Analyse.

Pour que les alertes partent par courriel, la section `analyzer_alert` de `notifications.yml` doit être activée avec des destinataires : voir [Notifications et événements](../dashboard/notifications.md#les-courriels).

## Journaux d'audit ModSecurity

Les journaux d'audit ModSecurity doivent être au format **JSON** (`SecAuditLogFormat JSON`), un fichier par vhost. Le format natif multi-parties n'est pas pris en charge : il n'a pas de schéma stable d'une version à l'autre.

```nginx
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /var/log/nginx/<vhost>.waf.log
```

Ces données ont leur propre vue dans le dashboard, sans notification. Pour un WAF qui ne dépend pas de Nginx, voir le [WAF émulé](security/waf-emule.md).

## Mémoire, performances et maintenance

Mesures sur des journaux identiques, avec l'ancienne version Node en comparaison :

| Charge | Node | Go |
|---|---|---|
| 20 000 lignes, 20 000 IP | 131 Mo | 82 Mo |
| 300 000 lignes, 50 000 IP | 297 Mo | 176 Mo |

Trois variables d'environnement propres à l'agent Go se règlent dans le conteneur :

| Variable | Rôle |
|---|---|
| `GOGC` | Compromis mémoire et processeur du ramasse-miettes (40 par défaut) |
| `GOMEMLIMIT` | Plafond de mémoire souple, par exemple `256MiB`. Ne le fixez pas sous le volume réellement utilisé |
| `TZ` | Fuseau horaire : la référence hebdomadaire de l'analyse volumétrique est calculée en heure locale |

Les bases SQLite de l'agent sont compactées au démarrage quand l'espace libre le justifie, puis entretenues toutes les 6 heures. Avec [Redis](../dashboard/health.md#redis-optionnel), les statistiques en cours d'agrégation survivent à un redémarrage.

## Migrer depuis l'ancienne image Node

Si `container_image` désigne encore l'image Node (`nginx-analyzer`), le dashboard continue de fonctionner mais affiche un avertissement. La migration est un simple changement d'image :

1. Remplacer `container_image` par l'image `analyzer-agent-go`.
2. Le dashboard recrée le conteneur. Le volume `host_data_path` est repris tel quel : historique, référence apprise, exceptions, règles et positions de lecture sont conservés.
