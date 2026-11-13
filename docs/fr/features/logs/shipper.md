# Shipper et page Journaux

Le **shipper** lit les journaux d'accès Nginx et les envoie au [log store](log-store.md). Il fournit aussi une entrée HTTP locale où le WAF émulé, le challenge et CrowdSec déposent leurs décisions. C'est le **seul point de sortie** vers le log store : seul le shipper connaît l'URL distante et le jeton d'écriture.

```
journaux d'accès Nginx ──► shipper ──(HTTPS, jeton write, tampon disque durable)──► log store ◄── page Journaux (jeton read)
blocklist-hits.log ─────►    ▲
WAF émulé, challenge ─(HTTP local, jeton local)─┘
```

Le shipper est l'un des trois binaires de l'image `analyzer-agent-go`, avec l'analyseur et le WAF émulé.

## Mise en route depuis le dashboard

1. **Log store** : le déployer, puis créer un jeton `write` par serveur (avec son `instance_id`) et un jeton `read` pour le dashboard.
2. **Variables** dans le fichier `.env` du dashboard : `LOGSTORE_READ_TOKEN`, `LOGSINK_TOKEN`, et facultativement `SHIPPER_LOCAL_TOKEN` (`openssl rand -hex 24`).
3. **Configuration** : bouton **Configurer** de la page **Journaux** (administrateur), ou fichier `logstore.yml` :

    ```yaml
    enable: true
    url: https://logs.example.com
    shipper_enable: true
    shipper_host_data_path: /srv/ngx/shipper
    instance: web1
    ```

    `shipper_host_data_path` est obligatoire : c'est un chemin de l'**hôte** qui contient les positions de lecture et le tampon disque.
4. Page **Journaux** → **Démarrer / recréer** : NGX Ops récupère l'image, crée le conteneur `ngx-shipper` (durci, sans port publié) et affiche son état.
5. Pour envoyer les décisions du WAF émulé et du challenge, renseigner `shipper_url: http://ngx-shipper:9181` dans leurs fichiers de configuration, puis redémarrer leurs conteneurs.

Les jetons ne sont jamais renvoyés au navigateur (seulement « défini » ou « absent »). Dans le formulaire, un champ vide conserve la valeur actuelle. Les variables d'environnement l'emportent sur le fichier.

!!! info "Sans dashboard"
    Un service `ngx-shipper` peut aussi être déclaré directement dans le `docker-compose` (profil `logstore`) avec `LOGSINK_URL`, `LOGSINK_TOKEN` et `SHIPPER_LOCAL_TOKEN`. Choisir l'une **ou** l'autre méthode (même nom de conteneur). La page Journaux lit alors toujours le log store, mais le dashboard ne pilote pas ce conteneur.

## Garanties

* Chaque lecture est écrite durablement dans un tampon disque **avant** que la position de lecture n'avance : un crash est rattrapé au démarrage.
* Les envois sont idempotents : un rejeu est dédupliqué par le log store.
* Pas de perte ni de doublon lors d'un redémarrage, d'une rotation, d'une troncature (`copytruncate`) ou d'une panne du log store.
* Un fichier vu pour la première fois est lu à partir de sa **fin** : l'historique n'est pas réimporté.

!!! warning "Rotation des journaux"
    Le suivi ne se fait pas par inode. Une rotation par renommage vers un nom qui ne correspond plus au motif (`access.log`, `access.log.1`…) peut perdre les lignes écrites depuis le dernier passage (une seconde au plus). Préférer `copytruncate`, ou un nom qui correspond encore au motif.

Les décisions émises pendant un arrêt du shipper sont perdues, ce compromis est accepté. Les journaux d'accès, eux, sont rattrapés au redémarrage.

## Ce qui est envoyé

* Les journaux d'accès Nginx (avec la classification du User-Agent, et le pays si `shipper_country` est activé).
* Les requêtes refusées par les blocklists, lues dans `blocklist-hits.log`. Le shipper retrouve le nom de la liste auprès de l'analyseur.
* Les décisions locales de CrowdSec (`shipper_crowdsec`), sans la liste communautaire.
* Les décisions du WAF émulé et du challenge, reçues par l'entrée locale.

## Supervision

La page **Journaux** affiche l'état du shipper. Sans passer par les journaux Docker :

* `GET /healthz` (sans jeton) sert de sonde ;
* `GET /status` (en-tête `Authorization: Bearer <SHIPPER_LOCAL_TOKEN>`) donne les fichiers suivis, les positions, les lignes lues ou ignorées, les rotations, le tampon, les envois et les problèmes. Aucun secret n'y figure.

## Variables du shipper

| Variable | Défaut | Rôle |
| -------- | ------ | ---- |
| `LOGSINK_URL` | requis | URL du log store |
| `LOGSINK_TOKEN` | requis | Jeton `write` de l'instance |
| `LOGSINK_ALLOW_INSECURE` | `false` | Autorise `http://` (réseau Docker interne uniquement) |
| `LOGSINK_INSTANCE` | vide | Nom de l'instance |
| `LOGSINK_SPOOL_DIR` | `/data/spool` | Tampon disque (volume persistant) |
| `LOGSINK_SPOOL_MAX_MB` | `256` | Plafond du tampon ; les plus anciens sont abandonnés et comptés |
| `LOGSINK_SPOOL_MAX_HOURS` | `24` | Âge maximal dans le tampon |
| `LOGSINK_BATCH_SIZE` | `500` | Taille des lots |
| `LOGSHIP_DIR` | `/nginx/logs` | Dossier des journaux Nginx (lecture seule) |
| `LOGSHIP_PATTERN` | `access.log` et ses rotations | Fichiers suivis |
| `LOGSHIP_POLL_MS` | `1000` | Cadence de lecture |
| `LOGSHIP_BLOCKLIST` | `true` | Suit aussi `blocklist-hits.log` |
| `LOGSHIP_STATE_FILE` | `/data/offsets.json` | Positions de lecture |
| `LOGSHIP_LISTEN` | `127.0.0.1:9181` | API locale ; en conteneur, `0.0.0.0:9181` sur un réseau interne, jamais publié |
| `LOGSHIP_LOCAL_TOKEN` | vide | Jeton de l'API locale (24 caractères minimum) ; vide, seule `/healthz` est servie |
| `LOGSHIP_BOTCLASS` | `true` | Ajoute la classe de bot |
| `LOGSHIP_COUNTRY` | `false` | Ajoute le pays (base GeoIP) |

Quand le shipper est géré par le dashboard, ces variables sont renseignées à partir de `logstore.yml`.

## La page Journaux

La page **Journaux** du dashboard consulte le log store avec le jeton de lecture : recherche, statistiques de visites, sécurité, historique par IP. Elle nécessite que le log store soit activé dans `logstore.yml`. Les paramètres de recherche sont validés par liste blanche et aucune redirection n'est suivie.
