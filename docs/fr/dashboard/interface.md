# Interface, menus et page Système

## Les pages du dashboard

| Groupe | Pages |
|---|---|
| Monitoring | **Overview** (requêtes, connexions, erreurs, trafic), **Virtual Hosts** (statistiques VTS par vhost), **Upstreams** (backends et temps de réponse) |
| Configuration | **Config files** (explorateur de `sites`, `conf`, `snippets`, `streams` avec coloration), **SSL Certificates**, **Live logs**, **VHost Generator** |
| Déploiement et sauvegardes | **Git Deployment**, **Backups** |
| Contrôle | **NGX Ops** (test, rechargement, état), **Events** (journal des actions) |
| Diagnostic | **Diagnostic**, **Monitoring** (supervision continue), **Schéma** (vue graphique des vhosts et de leurs cibles) |
| Intégrations | **REST API**, **Webhooks**, **CrowdSec**, **Blocklists IP**, **GoAccess** |
| Administration | **Users**, **Système** |

Certaines pages n'apparaissent que si la fonction correspondante est configurée : CrowdSec, GoAccess, WAF, API REST, Webhooks, Auto-config Docker, hôtes distants. Voir [Menus optionnels](#menus-optionnels).

## Thème et langue

- **Interface** : le sélecteur de l'en-tête bascule entre l'interface **Classique** (barre latérale) et le thème **Conductor** (menus déroulants en haut), en version **Clair** ou **Sombre**.
- **Couleur** : vert (par défaut) ou bleu. Elle ne change que l'identité visuelle (logo, badges, menu actif, boutons principaux). Les couleurs d'état restent les mêmes : vert pour le bon état, rouge pour une panne.
- **Langue** : l'interface est disponible en français et en anglais, avec un sélecteur dans l'en-tête.

Ces choix sont mémorisés **dans le navigateur** : ils ne sont pas partagés entre les utilisateurs ni entre vos navigateurs.

## Texte personnalisé dans l'en-tête

`BRANDING_HEADER_TEXT` affiche une chaîne libre entre le nom « NGX Ops » et les badges de version : nom d'un client, environnement (`STAGING`, `PROD-EU`)… Utile pour ne pas confondre plusieurs installations. Absente, rien n'est affiché.

```bash
BRANDING_HEADER_TEXT=Client ACME — Production
```

Les liens du pied de menu (documentation, site, dépôt, soutien) se règlent avec les variables `BRANDING_*`, fixées à la construction de l'image. Voir [Variables d'environnement](../environment.md).

## Menu repliable

Chaque section du menu (Monitoring, Configuration, Contrôle, Intégrations, Administration) se replie d'un clic sur son en-tête. L'état est mémorisé par navigateur et par section.

## Menus optionnels

Certains menus n'ont de sens que dans certaines installations. Ils se règlent avec une variable d'environnement, ou dans `config/menu.yml`. La variable l'emporte sur le fichier.

| Variable | Clé de `menu.yml` | Défaut | Comportement en `auto` |
|---|---|---|---|
| `MENU_WAF` | `waf_menu` | `auto` | Affiché si le tag de l'image Nginx se termine par `-waf` ou `-coraza` |
| `MENU_GODNS` | `godns_menu` | `show` | Pas de mode `auto` : `show` ou `hide` |
| `MENU_API` | `api_menu` | `auto` | Affiché si `API_TOKEN` est configuré |
| `MENU_WEBHOOKS` | `webhooks_menu` | `auto` | Affiché si `WEBHOOK_SECRET` est configuré |
| `MENU_DOCKER_AUTOCONFIG` | `docker_autoconfig_menu` | `auto` | Suit `enable` dans `docker-autoconfig.yml` |
| `MENU_AGENTS` | `agents_menu` | `auto` | Suit `enable` dans `agents.yml` |
| `MENU_GOACCESS` | `goaccess_menu` | `auto` | Affiché si des sources GoAccess sont configurées |

Les valeurs possibles sont `auto`, `show` et `hide`. D'autres entrées, affichées par défaut, peuvent aussi être masquées : `sync_menu`, `vhostgen_menu`, `graph_menu`, `deploy_menu`, `blocklists_menu`, `wafemu_menu`, `geomap_menu`, `digest_menu`, `cache_menu` et `notifications_menu`, avec les variables `MENU_SYNC`, `MENU_VHOSTGEN`, `MENU_GRAPH`, `MENU_DEPLOY`, `MENU_BLOCKLISTS`, `MENU_WAFEMU`, `MENU_GEOMAP`, `MENU_DIGEST`, `MENU_CACHE` et `MENU_NOTIFICATIONS`.

```yaml
# config/menu.yml
waf_menu: hide        # cette instance n'utilise pas d'image WAF
godns_menu: hide      # DNS dynamique jamais utilisé
api_menu: hide        # API REST jamais utilisée
```

Masquer un menu ne désactive pas la fonction : seul l'affichage change. Pour désactiver une fonction, utilisez son propre fichier de configuration.

## Page Système

La page **Système**, réservée aux administrateurs, liste tous les réglages du dashboard : valeur courante, valeur par défaut, endroit où les modifier et explication. Les secrets n'y apparaissent jamais en clair : seul l'état « configuré » ou « non configuré » est affiché.

Depuis cette page, vous pouvez :

- générer le jeton de l'API REST et le secret des webhooks, sans éditer `.env` : la valeur s'affiche **une seule fois** et seule son empreinte est conservée pour le jeton d'API ;
- modifier la visibilité des menus avec le bouton **Menu**, qui écrit `config/menu.yml` en conservant ses commentaires. Une variable `MENU_*` définie dans l'environnement verrouille la ligne correspondante ;
- consulter la version du dashboard et l'historique des changements avec le bouton **Changelog**, si `CHANGELOG_URL` est renseignée.
