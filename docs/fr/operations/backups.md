# Sauvegardes

NGX Ops sauvegarde la configuration Nginx : `sites/`, `conf/`, `snippets/`, `streams/`, `ssl/` et les certificats Let's Encrypt (`certs/live/`). Une sauvegarde peut être faite à la demande depuis la page **Sauvegardes**, par une [tâche planifiée](scheduler.md), ou automatiquement avant une modification de configuration et avant un déploiement.

## Destinations

| Mode | ZIP local | Push Git | S3 |
| ---- | :-------: | :------: | :-: |
| Local uniquement | ✓ | | |
| Git uniquement | | ✓ | |
| Local + Git | ✓ | ✓ | |
| S3 uniquement | | | ✓ |
| Local + Git + S3 | ✓ | ✓ | ✓ |

Les ZIP locaux sont tournés automatiquement : `BACKUP_KEEP` fixe le nombre conservé (20 par défaut).

Le push Git utilise le dépôt configuré pour le [déploiement Git](../features/git.md), dans la branche dédiée aux sauvegardes (`backup` par défaut), avec une étiquette horodatée.

## Destination S3

Elle se configure dans **Configuration → Sauvegardes (S3, cibles automatiques)**, fichier `backup.yml`, sans redémarrage. Elle fonctionne avec AWS, MinIO, Scaleway, OVH et Ceph. La signature est intégrée, sans dépendance. HTTPS est obligatoire, sauf `s3_allow_insecure: true` (réseau privé ou test).

| Clé | Rôle |
| --- | ---- |
| `s3_enable` | Active la destination |
| `s3_endpoint`, `s3_region`, `s3_bucket` | Service, région et bucket |
| `s3_prefix` | Dossier du bucket (`ngx-ops/` par défaut) |
| `s3_path_style` | `true` pour MinIO, Ceph et la plupart des S3 compatibles ; `false` pour AWS en mode virtual-host |
| `s3_keep` | Sauvegardes conservées dans le bucket, par famille (30 ; `0` désactive la rotation) |
| `s3_timeout_s` | Délai des requêtes (60) |

**Identifiants** : renseignez de préférence `BACKUP_S3_ACCESS_KEY` et `BACKUP_S3_SECRET_KEY` dans l'environnement du conteneur ; ils l'emportent sur le fichier. Les droits minimaux sont `s3:PutObject`, `s3:ListBucket` et `s3:DeleteObject` sur le préfixe.

!!! warning "Préfixe dédié"
    La rotation distante supprime les anciens `.zip` et `*_ngxops.*` du préfixe. Utilisez un dossier réservé aux sauvegardes NGX Ops.

La carte **Destination S3** de la page Sauvegardes liste le contenu du bucket et teste la connexion.

!!! info "Restauration depuis S3"
    NGX Ops ne restaure pas depuis S3 : téléchargez l'archive avec vos outils S3.

### Fichiers de configuration NGX Ops

`s3_include_ngxops: true` envoie aussi une archive `<date>_<label>_ngxops.tar.gz` des fichiers `config/*.yml`. Les secrets (jetons, clés) en sont **exclus** par défaut.

`s3_include_secrets: true` les inclut, mais impose une phrase de passe (`S3_BACKUP_PASSPHRASE` ou le repli `BACKUP_PASSPHRASE`) : l'archive est alors chiffrée au format `.ngxb`.

## Phrases de passe

Une phrase par fonctionnalité, pour ne pas mélanger des services déployés séparément :

| Variable | Sert à |
| -------- | ------ |
| `HUB_BACKUP_PASSPHRASE` | Les sauvegardes envoyées au [Hub](../hub/backups.md) |
| `S3_BACKUP_PASSPHRASE` | Les archives S3 chiffrées |
| `BACKUP_PASSPHRASE` | Repli commun quand la variable spécifique est absente |

Il n'y a aucun croisement : la phrase du Hub ne sert jamais au S3, ni l'inverse.

!!! danger "Conservez les phrases hors de NGX Ops"
    Une archive chiffrée dont la phrase est perdue est irrécupérable.

## Ouvrir une archive chiffrée

Une archive `.ngxb` (format NGXB1, AES-256-GCM) se déchiffre avec l'outil `tools/ngxb-decrypt.js` du dashboard (Node 16 ou plus, sans dépendance) :

```bash
HUB_BACKUP_PASSPHRASE='ma phrase' node ngxb-decrypt.js sauvegarde.ngxb sortie.tar.gz --extract ./dossier
```

La phrase se lit dans `HUB_BACKUP_PASSPHRASE`, `S3_BACKUP_PASSPHRASE` ou `BACKUP_PASSPHRASE`, ou sur l'entrée standard : jamais en argument, pour ne pas apparaître dans `ps` ni l'historique du shell. Une mauvaise phrase ou une archive altérée provoque une erreur et rien n'est écrit. Pour les archives du Hub, le bouton **Ouvrir** le fait dans le navigateur.

## Sauvegarde automatique

Sans aucune des clés `auto_local`, `auto_git` et `auto_s3` dans `backup.yml`, le comportement historique s'applique : ZIP local, plus Git lors d'un déploiement Git. Dès qu'une de ces clés est présente, elles s'appliquent partout, et celles qui sont absentes valent : local `true`, Git `false`, S3 `false`.

Choisissez un seul type de destination (S3 seul, par exemple) pour éviter de stocker trois copies à chaque modification.

## Restauration

!!! warning "Avec Git configuré"
    Tant que Git est configuré, la restauration d'une sauvegarde locale est refusée, et le bouton disparaît : le dépôt est la source de vérité. Pour revenir en arrière, utilisez un `git revert` suivi d'un redéploiement.
