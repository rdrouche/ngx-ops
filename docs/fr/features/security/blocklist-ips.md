# Blocklists IP

**Blocklists IP** est une intégration de **NGX OPS** permettant de mettre en place un blocage ou une [Challenge HTTP](challenge-http.md) basé sur des adresses IP en utilisant la directive `geo` de Nginx.

Les adresses IP provenant des différentes listes sont agrégées et dédupliquées avant d'être intégrées à la configuration Nginx.

## Les listes

Les listes d'adresses IP doivent être accessibles depuis une URL et respecter le format suivant, avec une adresse IP par ligne :

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

Il existe différentes listes communautaires disponibles sur Internet, notamment :

* [duggytuxy/Data-Shield_IPv4_Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) — **recommandée**
* [Blocklist.de](https://www.blocklist.de/fr/export.html)
* [GreenSnow Blocklist](https://blocklist.greensnow.co/greensnow.txt)
* **CrowdSec** via une bouncer — [voir la documentation RDR-IT](https://rdr-it.com/crowdsec-integration-avec-les-pares-feu-fortigate-fortinet/)

Afin d'optimiser la configuration, les différentes listes sont automatiquement **agrégées et dédupliquées**.

Il existe également des listes intégrés basés sur : 

- l'[analyse des journaux](../logs/analysis.md) ;
- le [WAF émulé](waf-emule.md) ;
- le [challenge intégré](challenge-http.md), pour les adresses qu'il a bloquées automatiquement.

## Configuration de base des listes

Pour configurer les listes, rendez-vous dans : **ADMINISTRATION → Configuration → Blocklists IP**

Dans la zone de saisie, renseignez la configuration souhaitée, puis cliquez sur **Enregistrer**.

### Exemple 1 : une seule liste

L'exemple suivant utilise uniquement la liste **Data-Shield** et effectue une mise à jour toutes les six heures :

```yaml
enable: true
interval_cron: "0 */6 * * *"
block_action: deny_403
hit_logging_enable: true
hit_logging_method: dedicated
sources:
  - name: datashield
    url: "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
    enable: true
```

### Exemple 2 : plusieurs listes

Il est également possible d'utiliser plusieurs sources simultanément. Dans cet exemple, les listes **Data-Shield** et **GreenSnow** sont utilisées :

```yaml
enable: true
interval_cron: "0 */6 * * *"
block_action: drop_444
hit_logging_enable: true
hit_logging_method: dedicated
sources:
  - name: datashield
    url: "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
    enable: true

  - name: greensnow
    url: "https://blocklist.greensnow.co/greensnow.txt"
    enable: true
```

Chaque source possède son propre nom, son URL et un paramètre `enable` permettant de l'activer ou de la désactiver.

### Actions de blocage

Le paramètre `block_action` permet de définir le comportement de Nginx lorsqu'une adresse IP présente dans une blocklist est détectée.

Dans nos exemples :

```yaml
block_action: deny_403
```

Les requêtes provenant d'une adresse IP présente dans les listes sont alors refusées avec une réponse HTTP **403 Forbidden**.

Le paramètre `hit_logging_enable` permet d'activer la journalisation des blocages.

Avec :

```yaml
hit_logging_method: dedicated
```

les blocages sont enregistrés dans un journal dédié, ce qui facilite leur consultation et leur analyse.

> `drop_444` permet de mettre fin à la connexion.

## Consulter l'état des Blocklists

Une fois la configuration enregistrée, rendez-vous dans : **INTEGRATIONS → Blocklists IP**

Cette page permet de consulter l'état de l'intégration ainsi qu'un récapitulatif des listes configurées et des adresses IP chargées.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-017-blocklists.png" width="800" />

## Consulter la configuration générée

Vous pouvez également consulter le fichier de configuration généré par **NGX Ops** depuis : **CONFIGURATION → Fichiers de conf → conf.d**

Le fichier généré est :

```text
blocklist-ips.conf
```

Ce fichier contient la configuration nécessaire à la gestion des adresses IP provenant des différentes blocklists.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-018-blocklists.png" width="800" />

## Configuration des hôtes virtuels pour utiliser Blocklists IP

La configuration des Blocklists IP étant générée au niveau global, il est nécessaire d'indiquer dans chaque hôte virtuel pour lequel vous souhaitez appliquer le filtrage que celui-ci doit utiliser la blocklist.

Pour cela, ajoutez les directives suivantes dans l'hôte virtuel :

```nginx
# Enregistre les blocages dans un fichier dédié
access_log /var/log/nginx/blocklist-hits.log blocklist_hits if=$blocklist_ip;

# Active le blocage des adresses IP présentes dans les blocklists
include snippets/blocklist-enforce.conf;
```

La première directive permet d'enregistrer dans un fichier dédié les requêtes provenant d'adresses IP présentes dans les blocklists.

La seconde directive inclut le *snippet* `blocklist-enforce.conf`, qui applique effectivement le blocage lorsque la variable `$blocklist_ip` indique que l'adresse IP du client est présente dans une liste.

Votre hôte virtuel peut donc être configuré de la manière suivante :

```nginx
server {
    listen 80;
    server_name example.com;

    # Journalise les requêtes bloquées par les blocklists
    access_log /var/log/nginx/blocklist-hits.log blocklist_hits if=$blocklist_ip;

    # Active le blocage des adresses IP présentes dans les blocklists
    include snippets/blocklist-enforce.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

> 💡 **Tip:** Le filtrage n'est appliqué qu'aux hôtes virtuels dans lesquels le *snippet* `blocklist-enforce.conf` est inclus. Vous pouvez donc choisir précisément les sites et applications auxquels vous souhaitez appliquer les Blocklists IP.

## Les listes intégrées

En plus des listes par URL, une source peut être **générée localement**. Les trois types se déclarent dans `sources:` :

```yaml
sources:
  - name: analyzer-auto
    type: analyzer
    enable: true
  - name: waf-challenge
    type: waf
    list: challenge
    enable: true
  - name: waf-block
    type: waf
    list: block
    action: drop_444
    enable: true
  - name: challenge-bans
    type: challenge
    action: deny_403
    enable: true
```

### Source `analyzer`

La liste est produite par les règles de l'[analyse des journaux](../logs/analysis.md), avec un fonctionnement proche de CrowdSec. Le seuil, la fenêtre de temps et la décision de bloquer se règlent **règle par règle**, pas sur la source :

- pour les règles intégrées, dans la fenêtre **Règles** de la page Analyse : seuil, fenêtre en minutes, case « Bloquer réellement » et durée ;
- pour les règles personnalisées (YAML), avec quatre champs :

```yaml
rules:
  - id: 101
    name: admin_probe
    # … champs de détection habituels …
    blocklist_threshold: 5               # absent : la règle ne participe jamais
    blocklist_window_minutes: 1440       # fenêtre de comptage, 1440 par défaut (24 h), 14 jours au plus
    blocklist_remediation: false         # false par défaut : détecte sans bloquer
    blocklist_remediation_minutes: null  # durée du blocage, absent : tant que le seuil est dépassé
```

!!! tip "Observer avant de bloquer"
    `blocklist_remediation` vaut `false` par défaut, volontairement. Tant qu'elle n'est pas passée à `true`, la règle **détecte** (compteur « détectées » de la page Blocklists IP, notification à chaque nouvelle IP qui franchit le seuil) mais ne bloque rien. Activer la source sur une installation en production ne bloque donc aucune adresse par surprise : observez d'abord ce que la détection produirait.

La durée de blocage (`blocklist_remediation_minutes`) est renouvelée tant que l'IP continue de déclencher la règle, et indépendante de la fenêtre de comptage.

La source `analyzer` est recalculée **chaque minute** (`analyzer_interval_cron`), sans téléchargement. Nginx n'est rechargé que si la liste change.

Pour garder les alertes d'un vhost sans qu'il alimente la liste, ajoutez `# nginx-control-analyze-no-remediation: on` dans son bloc `server`. Voir [Analyse des journaux](../logs/analysis.md#desactiver-la-remediation-des-regles-sur-un-hote-virtuel).

### Source `waf`

Les adresses viennent des listes du [WAF émulé](waf-emule.md) : `list: block` pour les adresses à refuser, `list: challenge` pour celles à soumettre au challenge. Prérequis : le WAF émulé activé, avec le mode **remédiation** sur au moins un vhost (les adresses en observation ne sont jamais listées). Si le WAF est injoignable, la dernière liste reçue est conservée.

### Source `challenge`

Elle reprend les adresses que le [challenge](challenge-http.md) a bloquées automatiquement après trop d'échecs. Les actions possibles sont `deny_403` et `drop_444` : ces adresses ont déjà échoué au challenge.

## Action par liste

`block_action` définit l'action par défaut : `deny_403` (réponse 403) ou `drop_444` (la connexion est fermée sans réponse, ce qui ne donne aucune information à un scanner). Chaque source peut la remplacer avec `action`, y compris par `challenge`, qui exige `challenge_enable: true`.

Une adresse présente dans plusieurs listes reçoit **l'action la plus sévère** : `444`, puis `403`, puis `challenge`. Un blocage l'emporte donc toujours sur un challenge.

## Liste blanche

La clé `whitelist` est un filet de sécurité **global**, appliqué après la fusion de toutes les sources : une adresse ou une plage listée ici n'est jamais bloquée, quelle que soit la source. Elle sert surtout à protéger vos propres plages privées d'un faux positif.

```yaml
whitelist:
  - "10.0.0.0/8"
  - "192.168.0.0/16"
  - "203.0.113.10"
```

## Le challenge comme remédiation

Pour qu'une liste applique un [challenge](challenge-http.md) plutôt qu'un refus :

1. mettre `challenge_enable: true` ;
2. démarrer le conteneur du challenge ;
3. dans chaque vhost protégé, après `blocklist-enforce.conf`, ajouter `include snippets/challenge-gate.conf;`.

Sans `challenge_enable`, les adresses « challenge » sont détectées et affichées, mais **rien n'est appliqué** dans Nginx.

## Journaliser les blocages

`hit_logging_enable` (désactivé par défaut) écrit un journal des blocages et alimente la mesure d'efficacité de la page, le résumé périodique et la recherche par liste.

| `hit_logging_method` | Fonctionnement |
|---|---|
| `dedicated` | Un journal global dédié (`blocklist-hits.log`), une ligne par requête bloquée, tous vhosts confondus. C'est précis |
| `approx` | Aucun journal supplémentaire : l'efficacité se limite à comparer le nombre d'IP bloquées au trafic global |

## La page Blocklists IP

La page affiche pour chaque source l'état (dernier succès ou erreur, nombre d'IP), un lien **Export** pour voir ou télécharger sa liste, le total d'adresses uniques, la configuration courante et les fichiers générés. Elle propose aussi :

- **Rafraîchir maintenant** ;
- une **recherche d'IP**, qui indique dans quelle(s) liste(s) une adresse figure ;
- l'**efficacité** des blocages sur 24 h, si la journalisation est active ;
- un **historique** filtrable des ajouts, retraits et détections en observation seule, exportable en CSV.

## Publier la liste à d'autres systèmes

Avec `public_enable: true`, la liste fusionnée est servie en texte brut (une adresse ou plage par ligne), sans session ni API :

| Adresse | Contenu |
|---|---|
| `/public/blocklist.txt` | La liste complète, accessible à tous si `public_token` est vide |
| `/public/<jeton>/blocklist.txt` | La liste complète, avec le jeton dans l'adresse |
| `/public/<jeton>/blocklist/<source>.txt` | Une source seule |

`public_sources` limite les sources publiées (`all` ou une liste de noms). Les sources en action `challenge` et la liste blanche sont exclues. Définissez toujours un `public_token` long et aléatoire (de 16 à 128 caractères) et exposez l'adresse en HTTPS. La limite est de 60 requêtes par minute et par IP. Un autre NGX Ops peut consommer cette liste comme une source `type: url`.

## Fonctionnement et sécurité

- Les deux fichiers générés sont `conf/blocklist-ips.conf` (la table des adresses, chargée par Nginx) et `snippets/blocklist-enforce.conf` (le blocage, à inclure vhost par vhost). Ils sont **créés vides dès le premier démarrage** : un vhost qui les inclut ne fait jamais échouer `nginx -t`.
- Ces fichiers sont générés localement : ils ne doivent pas être versionnés dans le dépôt Git et sont exclus du [déploiement Git](../git.md).
- Seules les lignes qui ressemblent strictement à une adresse IPv4 ou IPv6, avec ou sans CIDR, sont retenues. Tout le reste est ignoré : aucune injection de configuration n'est possible.
- Une source qui tombe en panne **ne retire pas ses adresses** : la dernière liste reçue avec succès reste active.
- `nginx -t` est exécuté avant chaque rechargement. En cas d'échec, les fichiers précédents sont restaurés. Un rechargement n'a lieu que si la table ou l'action a changé.
- Désactiver la fonction (`enable: false`) ou le challenge (`challenge_enable: false`) **vide** les fichiers générés sans les supprimer, puisque Nginx les inclut.

## Les clés de `blocklists.yml`

| Clé | Défaut | Rôle |
|---|---|---|
| `enable` | — | Active la fonction |
| `interval_cron` | `"0 */6 * * *"` | Fréquence de récupération des listes par URL (cron à 5 champs) |
| `analyzer_interval_cron` | `"* * * * *"` | Fréquence de la source `analyzer` |
| `block_action` | `deny_403` | Action par défaut : `deny_403` ou `drop_444` |
| `hit_logging_enable` | `false` | Journal des blocages |
| `hit_logging_method` | `dedicated` | `dedicated` ou `approx` |
| `challenge_enable` | `false` | Autorise l'action challenge |
| `challenge_engine` | `builtin` | `builtin` ou `anubis` |
| `challenge_upstream` | vide | Adresse du service : `nginx-challenge:8080` ou `anubis:8923` par défaut |
| `challenge_resolver` | `127.0.0.11` | Résolveur DNS utilisé par Nginx |
| `challenge_exempt_path_regex` | `^/[.]well-known/` | Chemins jamais soumis au challenge |
| `challenge_exempt_ua_regex` | vide | User-Agents jamais soumis au challenge |
| `public_enable`, `public_token`, `public_sources` | `false`, vide, `all` | Publication de la liste |
| `sources` | — | Les listes : `name` (lettres, chiffres, `_` et `-`, unique), `url` ou `type`, `action`, `enable` |
| `whitelist` | vide | Adresses et plages jamais bloquées |

Le fichier livré, `config/blocklists.yml`, contient ces clés avec des commentaires détaillés.
