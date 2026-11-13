# Analyse des journaux (expérimentale)

Voir les journaux de Nginx est utile, mais pouvoir en effectuer une **analyse automatique** permet d'aller plus loin en détectant des comportements potentiellement anormaux.

C'est l'objectif de cette fonctionnalité de **NGX Ops**, qui s'appuie sur **Analyzer Agent (AA)** pour analyser les journaux et détecter différents types de comportements.

L'analyse permet notamment de :

* effectuer une **analyse volumétrique par hôte virtuel**, afin de détecter une augmentation anormale du trafic pouvant, par exemple, être le signe d'une attaque par déni de service ;
* effectuer une **analyse du trafic par pays**, afin de détecter des variations inhabituelles ;
* utiliser un **moteur de règles** pour détecter différents comportements indésirables ;
* obtenir des statistiques sur le type de visiteurs (**humains / robots**) à partir du User-Agent.

Cette fonctionnalité nécessite [**Nginx Analyzer Agent**](../nginx-analyzer.md).

> **Attention :** l'analyse travaille sur les journaux, donc **après** les requêtes. Elle détecte et signale des comportements ; elle ne bloque pas la requête qu'elle détecte.

La remédiation est optionnelle : une règle peut alimenter la liste d'IP **analyzer** des [Blocklists IP](../security/blocklist-ips.md), avec un seuil, une fenêtre de temps, une durée de blocage et une action (refus, abandon ou [challenge](../security/challenge-http.md)). Les alertes peuvent aussi être partagées avec [Intelligence](../security/intelligence.md). En complément, **CrowdSec** reste une bonne option pour bloquer au niveau du pare-feu : voir [CrowdSec](../security/crowdsec.md).

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-020-analysis.png" width="800" />

## Analyse volumétrique

L'analyse volumétrique permet de surveiller le volume de requêtes reçues par les différents hôtes virtuels.

Elle permet notamment de détecter une augmentation inhabituelle du nombre de requêtes sur un VHost et de générer une alerte lorsque le comportement observé dépasse les seuils définis par le moteur d'analyse.

Cette analyse peut notamment être utilisée pour identifier :

* une augmentation brutale du trafic ;
* un comportement automatisé ;
* une tentative de saturation d'un service ;
* une attaque par déni de service.

L'analyse est réalisée par **Nginx Analyzer Agent**, qui observe le trafic afin d'établir une référence du comportement habituel et de détecter ensuite les variations importantes.

## Analyse inhabituelle par pays

L'analyse par pays permet de suivre l'origine géographique des requêtes reçues par les différents hôtes virtuels.

Nginx Analyzer Agent utilise les informations GeoIP disponibles pour déterminer le pays d'origine des adresses IP et détecter des variations inhabituelles du trafic.

Cette analyse peut notamment permettre d'identifier une augmentation soudaine du trafic provenant d'un pays habituellement peu ou pas présent sur un VHost.

> Cette fonctionnalité constitue un indicateur et ne doit pas être considérée comme une méthode de sécurité suffisante à elle seule. Une adresse IP peut être masquée par un VPN, un proxy ou un autre intermédiaire.

## Alertes sur le moteur de règles

Le moteur de règles permet de détecter des comportements spécifiques à partir des journaux Nginx.

Son fonctionnement est proche du principe utilisé par **CrowdSec** : Nginx Analyzer Agent analyse les requêtes enregistrées dans les journaux et applique un ensemble de règles afin d'identifier des comportements potentiellement indésirables.

Par défaut, **6 règles** sont disponibles :

* **Force brute**
* **Scan de chemin**
* **Flood par adresse**
* **Aspiration de contenu**
* **Anomalie volumétrique (par VHost)**
* **Anomalie volumétrique (par pays)**

Pour consulter les règles configurées, cliquer sur le bouton **Règles**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-021-analysis.png" width="800" />

## Traiter les alertes

Lorsqu'une règle est déclenchée, une alerte est générée et apparaît dans l'interface d'analyse.

Cette page permet notamment de :

* **acquitter l'alerte** ;
* consulter les éléments ayant déclenché la règle ;
* ajouter une **exception pour une adresse IP** ;
* ajouter une **exception pour un hôte virtuel**.

Les exceptions permettent notamment d'éviter qu'un comportement légitime et connu ne génère régulièrement de nouvelles alertes.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-022-analysis.png" width="800" />

## Ajouter des règles personnalisées

Le moteur de règles peut être enrichi avec vos propres règles.

Pour cela, cliquer sur le bouton **Règles**. Dans la fenêtre qui s'ouvre, un champ permet d'ajouter des règles personnalisées au format **YAML**.

Les règles personnalisées doivent utiliser un ID **supérieur ou égal à 100**. Les IDs inférieurs sont réservés aux règles intégrées à Nginx Analyzer Agent.

### Anatomie d'une règle

Une règle possède la structure suivante :

```yaml
rules:

  - id: 101                    # obligatoire, entier >= 100 (1 à 6 réservés aux règles intégrées)
    name: mon_nom_de_regle     # obligatoire, lettres/chiffres/_/- uniquement
    description: "Texte libre affiché dans la modale et dans les alertes"
    severity: medium           # low | medium | high (défaut : medium)
    min_matches: 10            # obligatoire, nombre de correspondances à atteindre
    window_minutes: 5          # fenêtre glissante en minutes (défaut : 5)
    scope: ip                  # optionnel : ip (défaut) ou global, voir ci-dessous
    min_ips: 5                 # optionnel, avec scope: global : IP distinctes minimales (défaut : 5)
    blocklist_remediation_type: block   # optionnel : block (défaut) ou challenge
    path_hint: "regex"         # optionnel, appliqué au chemin de la requête
    ua_hint: "regex"           # optionnel, appliqué au User-Agent
    status_in: [401, 403, 404] # optionnel, liste de codes HTTP
    method_in: ["POST"]        # optionnel, liste de méthodes HTTP
    enable: true               # optionnel (défaut : true)
```

### Règles par campagne : `scope: global`

Avec `scope: ip` (valeur par défaut), les correspondances sont comptées **IP par IP**. Une campagne distribuée, où chaque adresse n'envoie qu'une ou deux requêtes, échappe à ce comptage.

Avec `scope: global`, les correspondances de **toutes les IP** sont additionnées dans la fenêtre. La règle se déclenche quand le total atteint `min_matches` **et** qu'au moins `min_ips` adresses distinctes ont correspondu. L'alerte est alors **unique** pour la campagne : elle indique le nombre d'IP et de requêtes, le débit, les chemins et User-Agents les plus fréquents, la répartition des codes HTTP, des requêtes d'exemple et la liste des IP, copiable depuis l'interface.

```yaml
- id: 102
  name: botnet_login
  severity: high
  scope: global
  min_ips: 20
  min_matches: 60
  window_minutes: 10
  path_hint: "/login"
```

L'alerte est émise de nouveau si le nombre d'IP augmente de 50 % ou après une fenêtre complète. Les exceptions et l'exclusion par vhost s'appliquent IP par IP avant le comptage.

### Remédiation d'une règle

Le champ `blocklist_remediation_type` choisit l'effet sur les adresses détectées : `block` (refus ou abandon) ou `challenge` (vérification dans le navigateur). Il est pris en compte par la source **analyzer** de [Blocklists IP](../security/blocklist-ips.md).

Trois autres champs règlent la remédiation, à la manière d'un scénario CrowdSec : `blocklist_threshold` (nombre de détections), `blocklist_window_minutes` (fenêtre en minutes) et `blocklist_remediation_minutes` (durée du blocage). La remédiation est désactivée par défaut (`blocklist_remediation: false`). Détails dans [Blocklists IP](../security/blocklist-ips.md).

### Le formulaire et les modèles

Le bouton **Règles** ouvre une fenêtre à quatre onglets : les **règles intégrées**, **Mes règles** (un formulaire avec une phrase en langage clair et un testeur de requête), des **modèles par application** (Forgejo et Gitea, GitLab, WordPress, Nextcloud, User-Agents, web générique) que l'on ajoute d'un clic, et le **mode avancé** en YAML. Le YAML reste le format de stockage : enregistrer depuis le formulaire ne conserve pas les commentaires écrits à la main en mode avancé.

Le bouton **Hôtes et directives**, en lecture seule, liste pour chaque vhost l'état des commentaires `# nginx-control-…` : diagnostic, analyse, règles ignorées, supervision.

### Exemple 1 : détection d'un scan WordPress

L'exemple suivant permet de détecter des requêtes visant des chemins caractéristiques de WordPress sur un site qui n'utilise pas WordPress :

```yaml
rules:

  - id: 101
    name: wp_admin_probe
    description: "Sonde de wp-admin/wp-login sur un site qui n'est pas du WordPress"
    severity: high
    min_matches: 5
    window_minutes: 10
    path_hint: "wp-admin|wp-login|xmlrpc\\.php"
    enable: true
```

Dans cet exemple, `path_hint` est une expression régulière testée sur le chemin de chaque requête.

Dès qu'une même adresse IP effectue **5 requêtes** correspondant à l'un de ces chemins sur une période de **10 minutes**, une alerte est générée.

> **Faux positif possible :** si le site utilise réellement WordPress, cette règle peut naturellement générer des alertes. Vous pouvez alors la désactiver avec `enable: false` ou augmenter la valeur de `min_matches`.

### Exemple 2 : User-Agent suspect

Il est également possible de rechercher des User-Agent caractéristiques de certains outils d'analyse ou de scan :

```yaml
rules:

  - id: 104
    name: known_attack_tool_ua
    description: "User-agent d'un outil de scan/exploitation connu"
    severity: high
    min_matches: 1
    window_minutes: 5
    ua_hint: "sqlmap|nikto|dirbuster|nessus|acunetix"
    enable: true
```

Ici, `min_matches: 1` signifie qu'une seule requête suffit à déclencher l'alerte.

Contrairement à une règle volumétrique, il n'est donc pas nécessaire d'attendre plusieurs requêtes : la présence d'un User-Agent correspondant à l'un des motifs définis suffit à déclencher la règle.

> **Attention :** le User-Agent étant fourni par le client, il peut être facilement modifié ou falsifié. Ce type de règle doit donc être considéré comme un indicateur et non comme une preuve.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-023-analysis.png" width="800" />

## Personnaliser l'application des règles par hôte virtuel

Par défaut, le moteur d'analyse est actif pour tous les hôtes virtuels.

Il est toutefois possible de :

* désactiver complètement l'analyse pour un VHost ;
* désactiver certaines règles pour un VHost ;
* conserver les autres règles actives.

Cette configuration ne se fait pas directement depuis l'interface Web de **NGX Ops**. Elle est réalisée dans le fichier de configuration du VHost.

Ce choix est volontaire : **NGX Ops a été conçu avec une approche GitOps**, et la configuration des hôtes virtuels doit rester gérée dans les fichiers de configuration et votre dépôt Git.

La personnalisation s'effectue à l'aide de commentaires placés dans le bloc `server { ... }`.

### Désactiver complètement l'analyse

Pour désactiver l'analyse sur un VHost, ajouter :

```nginx
# nginx-control-analyze: off
```

Exemple :

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze: off

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

L'analyse est alors désactivée pour cet hôte virtuel.

### Désactiver une règle

Pour désactiver la règle ayant l'ID `3` sur un VHost, utiliser :

```nginx
# nginx-control-analyze-ignore-rules: 3
```

Exemple :

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-ignore-rules: 3

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

### Désactiver plusieurs règles

Plusieurs IDs peuvent être indiqués en les séparant par des virgules.

Par exemple, pour désactiver les règles `3` et `102` :

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-ignore-rules: 3, 102

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Cette méthode permet donc d'adapter le moteur d'analyse aux spécificités de chaque application sans modifier la configuration globale des règles.

### Désactiver la remediation des règles sur un hôte virtuel

Cette solution permet de garder les alertes sur l'hôte virtuel sans bloquer les adresses IP.

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-analyze-no-remediation: on

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

---

## Récapitulatif par VHost

L'interface permet également d'obtenir un récapitulatif de l'état de l'analyse pour chaque hôte virtuel.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-024-analysis.png" width="800" />

## Statistiques par pays

Les statistiques par pays permettent de visualiser la répartition géographique des requêtes analysées.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-025-analysis.png" width="800" />

## Statistiques par VHost

Les statistiques par VHost permettent de comparer l'activité des différents hôtes virtuels et de suivre leur évolution.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-026-analysis.png" width="800" />
