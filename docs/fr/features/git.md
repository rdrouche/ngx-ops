# Gestion de la configuration avec Git (GitOps)

**NGX Ops** permet d'utiliser un dépôt Git comme **source de vérité** pour les fichiers de configuration Nginx.

Les éléments suivants peuvent ainsi être versionnés dans le dépôt :

* `sites`
* `conf.d`
* `snippets`
* `streams`
* `ssl`

L'objectif est de ne plus considérer la configuration présente sur le serveur Nginx comme la seule référence, mais de conserver une version de référence dans Git.

Cette fonctionnalité permet notamment de :

* conserver l'historique des modifications ;
* identifier qui a effectué une modification ;
* revenir à une version précédente de la configuration ;
* travailler avec les outils habituels de Git ;
* préparer et valider les modifications avant leur déploiement.

> **Pourquoi cette fonctionnalité ?**
>
> Le fonctionnement GitOps est l'une des raisons qui ont motivé le développement de **NGX Ops**. L'objectif était de pouvoir gérer la configuration Nginx avec un dépôt Git et de disposer d'un historique des modifications, tout en conservant un contrôle sur le déploiement de la configuration.

## Prérequis

Il est nécessaire de disposer d'un dépôt Git accessible par **NGX Ops**.

Il est recommandé d'utiliser un dépôt **privé**, notamment parce que la configuration peut contenir les certificats SSL ainsi que leurs clés privées (`.pem` et `.key`).

Un token d'accès au dépôt Git est également nécessaire.

## Initialiser votre dépôt

La première étape consiste à initialiser le dépôt Git avec la configuration Nginx actuellement utilisée.

Pour cela, vous pouvez utiliser la fonctionnalité **Sauvegarde** de **NGX Ops** afin de récupérer les fichiers de configuration et de les envoyer (`push`) dans votre dépôt Git.

L'objectif est de partir de la configuration actuellement fonctionnelle avant de mettre en place le déploiement GitOps.

## Configuration de NGX Ops

Rendez-vous dans **ADMINISTRATION → Configuration**, puis sélectionnez l'onglet **Git (dépôt config)**.

Saisissez la configuration de votre dépôt puis cliquez sur **Enregistrer**.

Par exemple :

```yaml
repo_url: https://forge.domain.tld/organisation/nginx-reverse-proxy-config.git

token: **********

user_name: NginxControl
user_email: nginxcontrol@domain.tld
```

Rendez-vous ensuite dans **CONFIGURATION → Déploiement Git** afin de vérifier que la configuration du dépôt a bien été prise en compte.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-050-git.png" width="800" />

## Initialiser la branche Backup

Lors des opérations Git, notamment lors d'un **Pull** ou d'un **Déploiement**, **NGX Ops** sauvegarde la configuration actuellement utilisée par Nginx.

Cette sauvegarde est envoyée dans une branche **Backup** du dépôt Git.

Une étiquette (*tag*) est également créée afin de pouvoir identifier et retrouver une ancienne version de la configuration.

Avant d'utiliser le mécanisme de sauvegarde, la branche doit être initialisée.

Cliquez une seule fois sur **Initialiser la branche Backup**.

Cette opération crée la branche nécessaire aux sauvegardes automatiques des configurations précédentes.

## Utilisation

L'utilisation du GitOps est volontairement simple.

Après avoir effectué une modification de la configuration dans votre dépôt Git et envoyé celle-ci (`push`), rendez-vous dans **CONFIGURATION → Déploiement Git**.

Cliquez d'abord sur **Pull** afin de récupérer les modifications présentes dans le dépôt.

Une fois la nouvelle configuration récupérée, cliquez sur **Déployer** pour lancer son déploiement sur Nginx.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-051-git.png" width="800" />

### Vérification avant déploiement

Avant toute mise à jour de la configuration Nginx en production, **NGX Ops** effectue un test de la configuration dans un **conteneur éphémère**.

La configuration n'est appliquée à Nginx que si ce test est réussi.

Si le test échoue, la configuration actuellement utilisée par Nginx **n'est pas modifiée**.

Ce mécanisme permet ainsi de conserver une configuration fonctionnelle en production même lorsqu'une modification présente une erreur de configuration.

### Mêmes actions depuis un pipeline CI/CD

Pull, test, sauvegarde et déploiement complet sont déclenchables par l'API avec un **jeton de déploiement**, créé dans **Configuration → Éditeur → Jetons de déploiement (CI/CD)** (fichier `deploy-tokens.yml`).

Contrairement au jeton d'API administrateur, un jeton de déploiement n'ouvre que cinq routes : `POST /api/git/pull`, `POST /api/git/test`, `POST /api/git/deploy`, `GET /api/git/status` et `POST /api/backups`. Chaque jeton peut en plus limiter ses actions.

```yaml
tokens:
  - name: forgejo-ci
    token: "un-secret-aleatoire-d-au-moins-16-caracteres"
    enable: true
    actions: [test]   # test seul : ce pipeline ne peut jamais déployer
```

La réponse HTTP reflète le résultat (2xx en cas de succès, 422 pour un `nginx -t` invalide, 500 pour une erreur serveur) : un `curl -f` suffit à faire échouer l'étape.

```bash
curl -sS -f -X POST -H "Authorization: Bearer ${DEPLOY_TOKEN}" "${DASHBOARD_URL}/api/git/deploy"
```

## Git, source de vérité

Dès que Git est configuré, le dépôt fait référence et NGX Ops empêche ce qui le contredirait en silence : l'édition en ligne est désactivée, la création de fichiers aussi, et la restauration d'une sauvegarde locale est refusée. Pour revenir en arrière, utilisez un `git revert` puis un redéploiement. Pour les sauvegardes, voir [Sauvegardes](../operations/backups.md).
