# Installer NGX Ops

## Prérequis

Un serveur Linux avec Docker et Docker compose d'installé

> La documentation a été faite depuis un serveur Debian 13

## Préparation des dossiers

Sur votre serveur, créer un dossier pour les fichiers et dossiers de la stack.

> Cette documentation utilise le dossier `/containers/ngxops`

Créer le dossier : 

```bash
mkdir -p /containers/ngxops
cd /containers/ngxops
```

## Cloner les fichiers

Les fichiers et dossiers de la stack sont disponibles à cet emplacement : 
- https://forge.rdr-it.com/ngx-ops/compose

Utiliser la commande ci-dessous pour cloner le répertoire depuis le dépôt : 

```bash
bash <(wget -qO- https://forge.rdr-it.com/ngx-ops/compose/raw/branch/main/deploy.sh) ngx-ops
```

## Configuration de base

Commencer par copier le [`sample.env`](https://forge.rdr-it.com/ngx-ops/compose/src/branch/main/ngx-ops/sample.env) en le nommant `.env`, puis l'éditer. Aucun secret n'est obligatoire pour démarrer : voir [Variables d'environnement](environment.md).

```bash
cp sample.env .env
nano .env
```

Par défaut, le dashboard n'est pas publié, créer un fichier `compose.override.yml` avec le contenu suivant : 

```yaml
services:
  nginx-dashboard:
    ports:
      - "3000:3000"
```

## Démarrer les conteneurs

Télécharger les images et démarrer les conteneurs : 

```bash
docker compose up
```

> Les images sont téléchargées, puis les conteneurs démarrent.

> En l'absence du paramètre `-d`, vous voyez les journaux des conteneurs, ce qui permet de vérifier leur démarrage et de relever le **mot de passe du compte admin**, affiché une seule fois.
> 
> Une fois le mot de passe noté, appuyer sur la touche **d** détache l'affichage et laisse les conteneurs tourner en arrière-plan (versions récentes de Docker Compose). À défaut, `Ctrl+C` arrête les conteneurs : relancer alors `docker compose up -d`.

## Accéder au Dashboard

Depuis un navigateur, aller à l'adresse `http://ip:3000`, qui ouvre la page d'authentification.

- Identifiant : admin
- Mot de passe : celui affiché dans les journaux des conteneurs. Si vous l'avez perdu : `docker compose logs nginx-dashboard`

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-001-login.png" width="800" />

Une fois connecté, vous arrivez sur une page qui affiche les métriques des requêtes issues de Nginx VTS.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-002-overview.png" width="800" />

<hr />