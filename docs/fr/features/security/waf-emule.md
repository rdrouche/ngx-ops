# WAF émulé

Le **WAF émulé** relit les journaux d'accès de Nginx et rejoue chaque ligne comme une requête synthétique dans le moteur **Coraza v3**, en mode détection seule, avec le jeu de règles **OWASP CRS**. Il repère ainsi les attaques applicatives (injections, traversées de chemin, sondes de fichiers sensibles) sans toucher à Nginx.

!!! warning "Ce n'est pas un WAF en ligne"
    - L'analyse est faite **a posteriori** : le WAF émulé ne bloque **jamais** une requête lui-même.
    - Il ne voit pas le **corps** des requêtes (POST) ni les en-têtes absents du journal.
    - La remédiation passe par des listes d'IP : elle ne protège que les requêtes **suivantes** de l'adresse.

    Pour bloquer en ligne, utilisez une image Nginx avec WAF : voir [Utiliser une version WAF de Nginx](../../appendices/nginx-waf.md).

## Activer le WAF émulé

Le WAF émulé tourne dans un conteneur `ngx-waf`, créé et géré par le dashboard. C'est un second programme de l'image de l'analyseur, donc aucune image supplémentaire à déployer.

1. Éditer `config/waf.yml` :

    ```yaml
    enable: true
    accept_limits: true      # obligatoire : reconnaître les limites ci-dessus
    host_data_path: /containers/nginx-rproxy/waf
    host_rules_path: /containers/nginx-rproxy/waf-rules
    host_logs_path: /containers/nginx-rproxy/logs
    ```

    Les chemins sont des chemins **absolus sur l'hôte**.

2. Ouvrir la page **WAF émulé** et démarrer le conteneur.
3. Au premier démarrage, le jeu de règles CRS est téléchargé depuis github.com dans le volume des règles. Le conteneur démarre même si ce téléchargement échoue : l'erreur est visible sur la page.

| Clé de `waf.yml` | Défaut | Rôle |
|---|---|---|
| `enable` | `false` | Active la fonction |
| `accept_limits` | `false` | Doit valoir `true` pour démarrer |
| `container_name` | `ngx-waf` | Nom du conteneur |
| `container_image` | image de l'analyseur | Surcharge `WAF_DEFAULT_IMAGE` |
| `port` | `9101` | Port interne au réseau Docker, jamais publié |
| `host_data_path` | — | Réglages et base des détections |
| `host_rules_path` | — | CRS téléchargé et règles personnalisées |
| `host_logs_path` | `HOST_LOGS` | Journaux Nginx, montés en lecture seule |
| `log_pattern` | motif livré | Expression régulière des journaux `combined` et `combined_vhost` |
| `waf_log_pattern` | motif livré (`*.wafemu.log`) | Expression régulière du journal enrichi `waf_json` |
| `crs_version` | `v4.8.0` | Version du CRS |
| `hit_retention_days` | `30` | Conservation des détections |
| `shipper_url` | vide | Envoi des détections au [log store](../logs/index.md) |

Le secret partagé avec le conteneur (`WAF_TOKEN`) est généré au premier démarrage. Voir [Variables d'environnement](../../environment.md).

## Les journaux lus

| Format | Précision |
|---|---|
| `combined` ou `combined_vhost` | Fonctionne directement. Sans préfixe de vhost, il faut un fichier par vhost |
| `waf_json` | Format enrichi (en-têtes `Accept`, `Content-Type`, `Origin`…), à écrire dans un **fichier séparé** `*.wafemu.log` |

Le format `waf_json` donne les meilleurs résultats : l'onglet **Conseils** de la page fournit la définition à copier dans Nginx. Les deux journaux peuvent être actifs ensemble : les doublons sont écartés, la ligne `waf_json` est prioritaire.

Avec un journal `combined`, les règles du CRS qui jugent des en-têtes absents du journal sont désactivées automatiquement (« règles système »), pour éviter les faux positifs. Les requêtes statiques exclues par `$is_not_static` ne sont pas analysées.

## Les réglages de la page

| Réglage | Détail |
|---|---|
| Mode | **Observation** (par défaut) ou **remédiation**, global ou par vhost |
| Niveau de paranoïa | De 1 à 4, global ou par vhost. Plus il est élevé, plus il y a de détections et de faux positifs |
| Vhosts analysés | Tous, ou une sélection |
| Règles désactivées | Globalement ou par vhost |
| Exceptions | Règle, vhost et préfixe de chemin, User-Agent ou IP, créables en un clic depuis une détection |
| Exclusions | Statuts ignorés et IP exclues. Les IP privées sont toujours ignorées |
| Simulateur | Montre le score, les règles retenues et celles qui sont supprimées, avec la raison |

Commencez en **observation** : en niveau 2 ou plus, quelques faux positifs sont possibles. Des règles personnalisées peuvent être déposées dans le dossier `custom/` du volume des règles.

## Score et listes d'IP

Chaque règle du CRS ajoute son score selon sa gravité : critique 5, erreur 4, avertissement 3, notice 2. Les scores sont additionnés **par IP** sur une fenêtre de 60 minutes par défaut, uniquement pour les vhosts en mode remédiation.

- Au seuil **challenge**, l'IP entre dans la liste `waf-challenge`.
- Au seuil **block**, l'IP entre dans la liste `waf-block`, pour 24 h ou 72 h selon le cas.

Ces listes sont appliquées par [Blocklists IP](blocklist-ips.md), avec des sources de type `waf` :

```yaml
sources:
  - name: waf-challenge
    type: waf
    list: challenge
    enable: true
  - name: waf-block
    type: waf
    list: block
    action: drop_444
    enable: true
```

`waf-challenge` exige `challenge_enable: true` : voir [Challenge HTTP](challenge-http.md). Dans l'onglet **Listes** de la page, chaque IP indique si les Blocklists l'appliquent, et la cause si ce n'est pas le cas (source manquante, liste blanche, challenge désactivé…). Le bouton **Preuves** détaille les règles déclenchées et les dernières requêtes.

## Alertes

Une alerte de type `waf` est créée par IP et par fenêtre quand le score atteint le seuil d'alerte. Une règle désactivée **n'envoie jamais d'alerte** : à la lecture, ses points sont retirés, et l'alerte disparaît si le score restant est insuffisant.

Ces alertes sont aussi transmises à [Intelligence](intelligence.md), sauf si vous ajoutez `waf` à `exclude_rules`.

## Conseils de diagnostic

L'onglet **Conseils** signale : un format de journal à améliorer, des vhosts sans journal ou sans trafic, un CRS absent, une file saturée (des lignes sont alors abandonnées), des lignes illisibles, un moteur non prêt, et une remédiation activée sans liste de blocage ni challenge actif.

## Performances

Mesure de référence, avec le CRS 4.8 en niveau 1 et deux cœurs : environ 2 400 lignes par seconde, soit environ 0,8 ms par requête. Sur 38 requêtes légitimes variées, aucune détection en niveau 1.
