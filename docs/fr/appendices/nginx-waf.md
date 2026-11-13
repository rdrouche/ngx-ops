# Utiliser une version WAF de Nginx

Par défaut, l'image proposée dans le stack **NGX Ops** est basée sur une image standard de Nginx.

Pour les environnements nécessitant des fonctionnalités de **Web Application Firewall (WAF)**, deux variantes de l'image Nginx sont également disponibles :

* **ModSecurity 3**
* **Coraza**

Ces deux solutions permettent d'intégrer un moteur WAF directement dans Nginx et d'utiliser notamment les règles de l'**OWASP Core Rule Set (CRS)**.

> **Attention :** ces deux images sont destinées à des besoins spécifiques. Leur utilisation n'est pas obligatoire pour exploiter les fonctionnalités de sécurité et d'analyse de **NGX Ops**.

## ModSecurity

**ModSecurity** est l'un des moteurs WAF historiques les plus utilisés avec Nginx.

La version proposée par NGX Ops s'appuie sur **ModSecurity 3** et permet notamment d'utiliser l'OWASP Core Rule Set afin de détecter différentes catégories d'attaques :

* SQL Injection ;
* Cross-Site Scripting (XSS) ;
* Local/Remote File Inclusion ;
* attaques par traversée de répertoires ;
* requêtes HTTP anormales ;
* et plus généralement les comportements couverts par les règles du CRS.

ModSecurity fonctionne directement dans le processus Nginx et peut donc bloquer ou journaliser les requêtes avant qu'elles n'atteignent l'application.

Dans la configuration proposée par **NGX Ops**, ModSecurity est initialement configuré en mode **DetectionOnly** afin d'éviter qu'une règle WAF mal ajustée ne bloque immédiatement une application.

## Coraza

**Coraza** est une implémentation moderne d'un moteur WAF compatible avec les règles ModSecurity et l'OWASP Core Rule Set.

Contrairement à ModSecurity, Coraza est développé en **Go**. Il permet donc d'utiliser le même principe de règles tout en reposant sur une implémentation différente.

L'image Nginx proposée par NGX Ops intègre Coraza directement dans Nginx et permet notamment d'utiliser les règles de l'OWASP CRS.

Cette intégration reste toutefois **expérimentale** dans le contexte de NGX Ops. Des différences peuvent exister entre le comportement de Coraza et celui de ModSecurity, notamment lors de la validation ou du chargement des règles.

## Images Docker

Les sources des images Nginx sont disponibles dans le dépôt :

[Sources des images Nginx](https://forge.rdr-it.com/Dockerfiles/nginx-reverse-proxy)

Les images Docker publiées sont disponibles dans le registre :

[Images Docker Nginx Reverse Proxy](https://forge.rdr-it.com/Dockerfiles/-/packages/container/nginx-reverse-proxy/)

---

## Intégration dans NGX Ops

**NGX Ops** détecte automatiquement lorsqu'une image Nginx intégrant ModSecurity ou Coraza est utilisée.

Lorsqu'une de ces images est détectée, une entrée **WAF** est ajoutée au menu de l'interface.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/ngxops-004-waf.png" width="800" />

Cette interface permet notamment d'accéder aux journaux générés par le moteur WAF afin de pouvoir les analyser.

> **Important :** pour être exploités par **NGX Ops**, les journaux WAF doivent impérativement être générés au **format JSON**.

Cette approche permet de conserver les fonctionnalités d'analyse de NGX Ops tout en laissant au moteur WAF la responsabilité de l'analyse des requêtes.

---

## Activation du WAF dans Nginx

Par défaut, **ModSecurity** et **Coraza** sont configurés en mode **DetectionOnly**.

Le moteur est également désactivé au niveau des VHosts afin qu'aucun blocage ne soit effectué involontairement.

Pour activer le WAF sur un VHost, il faut ajouter la configuration correspondante dans le bloc `server { ... }`.

### ModSecurity

```text
modsecurity on;

modsecurity_rules_file /etc/nginx/modsec/main.conf;

modsecurity_rules '

    # Passer ce VHost en mode détection uniquement
    # et ne pas bloquer les requêtes.
    SecRuleEngine DetectionOnly

    SecAuditLogParts ABIJDEFHZ

    # Activer le journal d audit pour ce VHost
    SecAuditEngine RelevantOnly

    # Journaliser les réponses 5xx et les réponses 4xx
    # à l exception des 404.
    SecAuditLogRelevantStatus "^(?:5|(?:4(?!04)))"

    # Emplacement du journal WAF
    SecAuditLog /var/log/nginx/<vhost-name>.waf.log

    SecAuditLogType Serial
    SecAuditLogFormat JSON

';
```

Pour passer le WAF en mode blocage, il est possible de remplacer :

```text
SecRuleEngine DetectionOnly
```

par :

```text
SecRuleEngine On
```

Il est toutefois recommandé de commencer par le mode **DetectionOnly** afin d'identifier les éventuels faux positifs avant d'activer le blocage.

### Coraza

La configuration de Coraza est similaire :

```text
coraza on;

coraza_rules_file /etc/nginx/coraza/coraza-main.conf;

coraza_rules '

    # Passer ce VHost en mode détection uniquement
    # et ne pas bloquer les requêtes.
    SecRuleEngine DetectionOnly

    SecAuditLogParts ABIJDEFHZ

    # Activer le journal d audit pour ce VHost
    SecAuditEngine RelevantOnly

    # Journaliser les réponses 5xx et les réponses 4xx
    # à l exception des 404.
    SecAuditLogRelevantStatus "^(?:5|(?:4(?!04)))"

    # Emplacement du journal WAF
    SecAuditLog /var/log/nginx/<vhost-name>.waf.log

    SecAuditLogType Serial
    SecAuditLogFormat JSON

';
```

---

## Limitations et retour d'expérience

Ces intégrations sont fonctionnelles, mais présentent plusieurs limitations qu'il est important de connaître avant de les utiliser en production.

### ModSecurity : consommation mémoire

L'intégration ModSecurity fonctionne correctement avec Nginx et offre actuellement l'intégration la plus mature.

Le principal point négatif constaté concerne cependant la **consommation mémoire**.

Deux éléments sont particulièrement à prendre en compte :

* les fichiers de configuration du WAF sont chargés indépendamment pour chaque VHost ;
* lors des rechargements de Nginx (`nginx -s reload`), les anciens workers peuvent rester en mémoire pendant un certain temps.

Sur une configuration comportant plusieurs VHosts utilisant le WAF, la consommation mémoire peut donc augmenter progressivement après plusieurs rechargements.

Dans ce cas, un redémarrage périodique du conteneur Nginx peut être nécessaire afin de libérer complètement la mémoire utilisée par les anciens workers.

### Coraza : intégration expérimentale

L'intégration de Coraza est actuellement considérée comme **expérimentale**.

Coraza étant développé en Go et intégré à Nginx via une architecture différente de ModSecurity, certains comportements peuvent être différents.

Un point particulièrement important concerne la validation de la configuration.

Il est possible qu'un :

```bash
nginx -t
```

soit valide alors qu'une règle Coraza présente finalement une erreur lors de son chargement ou de son exécution.

Dans certains cas, cela peut provoquer un comportement inattendu de Nginx, voire empêcher correctement son démarrage.

> **Recommandation :** si vous utilisez Coraza en production, testez systématiquement vos règles dans un environnement de préproduction avant de les déployer.

---

## Gestion des exclusions avec ModSecurity

L'utilisation de l'OWASP Core Rule Set nécessite généralement la mise en place d'exclusions pour certaines applications.

C'est notamment le cas avec des applications complexes comme **Nextcloud**, qui utilisent des méthodes HTTP et des paramètres qui peuvent déclencher certaines règles du CRS.

La gestion des exclusions peut rapidement devenir complexe.

Les exclusions doivent être placées dans le fichier :

```text
REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```

Par exemple :

```text
# ==================================================================
# EXCLUSION 1 : Nextcloud WebDAV
# ==================================================================

SecAction "id:1000000,phase:1,nolog,pass,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT DELETE PUT'"

# ==================================================================
# EXCLUSION 2
# ==================================================================

# Fix SQLi 942550 sur la recherche JSON

SecRuleUpdateTargetById 942550 "!ARGS:json.query.Url"

SecRuleUpdateTargetById 942550 "!ARGS:json.searchQuery.Url"

SecRuleUpdateTargetById 942550 "!REQUEST_COOKIES:/^ErmesSearch_/"

# Fix Content-Type 920420 pour le back-office /pro/

SecRule REQUEST_URI "@beginsWith /my-folder/" \
    "id:1000002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"
```

Il est également possible de conditionner les exclusions au `server_name`.

Par exemple :

```text
# ==================================================================
# 1. EXCLUSIONS Nextcloud
# ==================================================================

SecRule REQUEST_HEADERS:Host "@streq nextcloud.domain.tld" \
    "id:1000001,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT DELETE PUT'"

# ==================================================================
# 2. EXCLUSIONS subdom.domaine.tld
# ==================================================================

# Fix SQLi 942550

SecRule REQUEST_HEADERS:Host "@streq subdom.domaine.tld" \
    "id:1000002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveTargetById=942550;ARGS:json.query.Url,\
    ctl:ruleRemoveTargetById=942550;ARGS:json.searchQuery.Url,\
    ctl:ruleRemoveTargetById=942550;REQUEST_COOKIES:/^ErmesSearch_/"

# Fix Content-Type 920420

SecRule REQUEST_HEADERS:Host "@streq subdom.domaine.tld" \
    "id:1000003,\
    phase:1,\
    chain,\
    pass,\
    nolog"

    SecRule REQUEST_URI "@beginsWith /my-folder/" \
        "ctl:ruleRemoveById=920420"
```

Le fichier doit ensuite être monté dans le conteneur Nginx.

Par exemple avec Docker Compose :

```yaml
services:
  nginx:
    ...

    volumes:
      - ./ms-rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:/etc/nginx/modsec/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```

Un redémarrage du conteneur est ensuite nécessaire pour garantir la prise en compte de la configuration.

> **Conseil :** avant de passer le WAF en mode blocage, il est fortement recommandé d'analyser les alertes générées et de mettre en place les exclusions nécessaires.

---

## Intégration avec NGX Ops Intelligence

Les alertes générées directement par **ModSecurity** ou **Coraza** ne sont actuellement **pas remontées dans NGX Ops Intelligence**.

L'intégration native du WAF permet donc principalement de consulter et d'analyser les journaux depuis l'interface NGX Ops.

Si vous souhaitez bénéficier de la corrélation centralisée des événements WAF avec **NGX Ops Intelligence**, une autre approche est disponible.

---

## Alternative : le WAF émulé de NGX Ops

**NGX Ops** propose également une approche différente avec un **WAF émulé**.

Cette solution ne repose pas sur un module WAF exécuté directement dans Nginx.

Elle utilise un agent spécifique, déployé directement depuis **NGX Ops**, qui analyse les journaux HTTP générés par Nginx.

L'agent, développé en **Go**, embarque **Coraza** ainsi que les règles de l'OWASP Core Rule Set.

Le fonctionnement est donc différent :

```text
Client
   |
   v
Nginx
   |
   +----> Application
   |
   +----> Logs HTTP
             |
             v
       NGX Ops Agent
             |
             v
          Coraza
             |
             v
       Analyse WAF
             |
             +----> Blocklist
             |
             +----> Challenge HTTP
             |
             +----> NGX Ops Intelligence
```

La configuration et les actions de remédiation sont ensuite gérées directement depuis **NGX Ops**.

Cette approche présente plusieurs avantages :

* aucune modification du binaire Nginx ;
* aucune règle WAF directement chargée par Nginx ;
* aucune modification de configuration Nginx nécessaire lors de l'ajout d'une règle ;
* prise en compte rapide des modifications ;
* possibilité d'utiliser les mécanismes de remédiation de NGX Ops ;
* remontée des alertes vers **NGX Ops Intelligence** ;
* possibilité de corréler les événements avec les autres mécanismes de sécurité.

### Limitations du WAF émulé

Cette approche présente cependant une limitation importante : **l'agent travaille à partir des journaux Nginx**.

Il ne dispose donc pas nécessairement de l'intégralité de la requête HTTP.

Certaines règles ne peuvent ainsi pas être correctement analysées, notamment celles qui nécessitent l'accès au contenu complet d'une requête `POST`.

Une autre différence importante concerne le moment du blocage.

Puisque l'analyse intervient **après le traitement de la requête par Nginx**, la première requête provenant d'une adresse IP inconnue peut atteindre la cible.

Si l'analyse déclenche ensuite une remédiation, les requêtes suivantes pourront être bloquées ou soumises à un challenge.

Le WAF émulé doit donc être considéré comme un mécanisme de **détection et de remédiation comportementale**, et non comme un remplacement strict d'un WAF exécuté au niveau de la requête HTTP.

---

## Quelle solution choisir ?

| Solution          | Niveau d'analyse | Blocage immédiat | Consommation | NGX Ops Intelligence | Maturité           |
| ----------------- | ---------------- | ---------------: | -----------: | -------------------: | ------------------ |
| ModSecurity       | Requête HTTP     |              Oui |       Élevée |                  Non | Élevée             |
| Coraza Nginx      | Requête HTTP     |              Oui |    À évaluer |                  Non | Expérimentale      |
| WAF émulé NGX Ops | Logs Nginx       |  Après détection |       Faible |                  Oui | Intégrée à NGX Ops |

Pour une protection WAF **directement intégrée à Nginx**, ModSecurity reste aujourd'hui le choix le plus mature.

Pour une approche davantage orientée **détection, corrélation et remédiation**, le WAF émulé de **NGX Ops** est généralement plus intéressant, notamment grâce à son intégration avec **NGX Ops Intelligence**, les blocklists et les mécanismes de challenge HTTP.
