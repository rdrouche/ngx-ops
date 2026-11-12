# NGX Ops

**Nginx reste le moteur. NGX Ops s'occupe du reste.**

[English](README.md) · [Documentation](https://docs.ngx-ops.net/) · [Site web](https://ngx-ops.net)

NGX Ops est une stack open source d'exploitation pour **reverse proxy Nginx** : tableau de bord, supervision, déploiement GitOps, SSL, logs, CrowdSec et WAF. Votre configuration reste du **Nginx standard**, dans des fichiers standards : aucun nouveau langage à apprendre, aucun enfermement. Si vous savez configurer Nginx, vous savez utiliser NGX Ops.

```text
nginx/config/
├── conf.d/      # contexte http { }
├── sites/       # hôtes virtuels (renommer en .conf.DISABLE pour désactiver)
├── snippets/    # fragments réutilisables
└── streams/     # TCP / UDP
```

## Fonctionnalités

* **Dashboard** : supervision temps réel (Nginx VTS), édition de la configuration native, `nginx -t` et rechargement depuis l'interface, générateur de vhost, comptes avec rôles administrateur, opérateur et lecteur, MFA (TOTP, clé de sécurité), API REST et webhooks.
* **GitOps** : pull, sauvegarde, validation dans un conteneur éphémère, déploiement, rechargement. Le déploiement peut être déclenché depuis un pipeline CI/CD avec des jetons limités.
* **SSL** : Let's Encrypt (HTTP-01 et DNS-01), import PEM/KEY, DNS dynamique avec GoDNS.
* **Logs** : logs en direct, carte, détection d'anomalies, statistiques GoAccess, log store centralisé facultatif (PostgreSQL/TimescaleDB).
* **Sécurité** : WAF émulé par l'analyse des logs, blocklists IP, intégration CrowdSec, challenge navigateur (moteur intégré ou Anubis), et images ModSecurity ou Coraza si vous avez besoin d'un vrai WAF.
* **Autoconfiguration Docker** : publiez vos conteneurs avec des labels, en local ou sur des hôtes distants par un agent (modes direct, relay ou tunnel).
* **Multi-instances** : un Hub en lecture seule donne une vue globale de plusieurs serveurs NGX Ops et centralise leurs sauvegardes.
* **Sauvegardes** : ZIP local, Git ou S3, archives chiffrées et tâches planifiées.

## Composants

Un seul numéro de version couvre toute la suite (voir [`VERSION.md`](VERSION.md)).

| Composant | Dossier | Rôle |
| --------- | ------- | ---- |
| Nginx et dashboard | `nginx-dashboard/` | Reverse proxy, interface web, API |
| Analyseur, WAF émulé, shipper | `nginx-analyzer-go/` | Analyse des logs, alertes, WAF, envoi des journaux (Go) |
| Challenge | `nginx-challenge/` | Challenge navigateur |
| Agent | `nginx-agent/` | Publie les conteneurs d'un hôte Docker distant |
| Hub | `nginx-hub/` | Vue globale multi-instances et sauvegardes |
| Log store | `nginx-logstore/` | Journaux centralisés (PostgreSQL/TimescaleDB) et API |
| Documentation | `ngx-ops-docs/` | Site de documentation (FR et EN) |
| Site web | `ngx-ops-website/` | Site du projet |

Les images sont publiées dans le registre `forge.rdr-it.com/ngx-ops/ngx-ops`. Utilisez un tag numérique en production : le tag `nightly` est une construction d'essai.

[NGX Ops Intelligence](https://intelligence.ngx-ops.net/), plateforme de renseignement sur les menaces, est un service SaaS. L'envoi d'alertes vers elle est désactivé par défaut.

## Démarrage rapide

Il faut un serveur Linux avec Docker et Docker Compose.

```bash
mkdir -p /containers/ngxops && cd /containers/ngxops
bash <(wget -qO- https://forge.rdr-it.com/ngx-ops/compose/raw/branch/main/deploy.sh) ngx-ops
cp sample.env .env
docker compose up
```

Lancez le premier démarrage **sans `-d`** : le mot de passe administrateur généré s'affiche dans la sortie. Notez-le, arrêtez avec `Ctrl+C`, puis lancez `docker compose up -d`. Le guide complet est dans la [documentation d'installation](https://docs.ngx-ops.net/installation/).

## Documentation

* [Documentation](https://docs.ngx-ops.net/) : installation, dashboard, fonctionnalités, Hub, exploitation.
* [`CHANGELOG.md`](CHANGELOG.md) : historique des changements.
* Chaque composant a son propre `README.md` et son `CHANGELOG.md`.

## Contribuer

Les tickets et suggestions sont les bienvenus dans le suivi des tickets du dépôt. Ouvrez un ticket avant une modification importante, et gardez un sujet par modification. Le code est modulaire : une nouvelle fonctionnalité doit s'ajouter sans modifier le comportement existant.

## Sécurité

Ne signalez pas une vulnérabilité dans un ticket public. Contactez le mainteneur en privé : [contact à définir].

## Licence

[Licence à définir : ajouter un fichier `LICENSE` à la racine du dépôt.]

## Auteur

Créé par [RDR-IT](https://rdr-it.com).
