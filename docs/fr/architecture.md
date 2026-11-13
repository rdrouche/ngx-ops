# Architecture de la suite

NGX Ops est une suite de composants qui s'organisent autour d'un Nginx classique. Seul le couple **Nginx + dashboard** est nécessaire : tous les autres composants sont facultatifs et chacun reste utilisable sans les autres.

## Les composants

| Composant | Rôle | Où il tourne |
|---|---|---|
| **Nginx** | Le reverse proxy, avec sa configuration native (`conf.d`, `sites`, `snippets`, `streams`) | Compose principal |
| **Dashboard** | Interface, API REST, webhooks, pilotage de Nginx et des conteneurs associés | Compose principal |
| **Analyseur** | Analyse les journaux d'accès, génère des alertes, alimente les blocklists. Écrit en Go | Conteneur créé et géré par le dashboard |
| **WAF émulé** | Rejoue les journaux dans un moteur de règles, sans jamais bloquer directement | Conteneur géré par le dashboard |
| **Challenge** | Défi navigateur (preuve de travail) pour les IP signalées | Conteneur géré par le dashboard |
| **Shipper** | Envoie les journaux vers le log store | Conteneur géré par le dashboard |
| **Agent** | Pilote un serveur Nginx ou Docker distant depuis le dashboard | Sur chaque serveur distant |
| **Hub** | Vue globale, en lecture seule, de plusieurs dashboards ; reçoit leurs sauvegardes | Compose dédié |
| **Log store** | Base de journaux (PostgreSQL et TimescaleDB) avec son API | Compose dédié |
| **Intelligence** | Service central SaaS qui reçoit les alertes, calcule une réputation par IP et publie des listes | Service hébergé |
| **Redis** | Conserve les statistiques en cours après un redémarrage | Compose principal, profil `redis` |

L'analyseur, le WAF émulé et le shipper sont trois programmes d'une même image. Le challenge, certbot, la mise à jour GeoIP, les pages d'erreur et GoAccess sont créés à la demande par le dashboard via le socket Docker : ils ne figurent pas dans le fichier compose.

## Vue d'ensemble

```text
                        ┌──────────── serveur principal ────────────┐
 visiteurs ──80/443──▶  │  Nginx ◀── fichiers de configuration      │
                        │    │            ▲                          │
                        │    │ journaux   │ écriture, test, reload   │
                        │    ▼            │                          │
                        │  Analyseur ──▶ Dashboard ──socket Docker──▶ conteneurs gérés
                        │  WAF émulé       │   ▲                     │
                        │  Challenge       │   │                     │
                        │  Shipper         │   │                     │
                        └──────────────────┼───┼─────────────────────┘
                                           │   │
        Agent (hôte distant) ──manifeste──▶│   │◀── Hub (lecture seule, interroge le dashboard)
                                           │
              Shipper ──lots gzip, jeton write──▶ Log store ◀── jeton read ── Dashboard, Hub
                                           │
                    Dashboard ──alertes (option)──▶ Intelligence
```

## Qui parle à qui

| Flux | Sens | Authentification |
|---|---|---|
| Dashboard → Nginx | Écrit la configuration, lance `nginx -t` et le rechargement, lit les statistiques VTS | Socket Docker, réseau interne |
| Dashboard → conteneurs gérés | Création, arrêt, mise à jour d'image | Socket Docker |
| Dashboard ↔ analyseur, WAF, challenge | API HTTP interne | Jeton interne géré par le dashboard |
| Shipper → Log store | Envoi par lots compressés, rejouables sans doublon | Jeton `write`, TLS |
| Dashboard et Hub → Log store | Lecture, recherche, statistiques | Jeton `read` |
| Producteurs (WAF, challenge) → Shipper | Envoi des décisions en HTTP local | Jeton local partagé |
| Agent → Dashboard | Envoi périodique du manifeste de l'hôte distant | Jeton propre à chaque agent, HTTPS |
| Hub → Dashboard | Le Hub **interroge** le dashboard (pull) ; l'inverse n'existe pas | Jeton `X-Hub-Token`, le dashboard ne conserve que son empreinte SHA-256 |
| Dashboard → Hub | Envoi des sauvegardes, uniquement si ce mode est activé | `HUB_PUSH_TOKEN` |
| Dashboard → Intelligence | Envoi des alertes d'analyse, désactivé par défaut | Mode anonyme, ou mode identifié avec un jeton |

Les secrets ne sont jamais envoyés au navigateur : le dashboard relaie les appels vers le log store avec le jeton de lecture, côté serveur.

## Ce qui se passe quand un composant s'arrête

| Composant arrêté | Conséquence |
|---|---|
| Log store | Le shipper garde les lots dans un tampon sur disque (plafonné à 256 Mo ou 24 h) et les renvoie au retour du service, sans doublon |
| Shipper | Les décisions émises par le WAF et le challenge pendant l'arrêt sont perdues ; la lecture des journaux d'accès reprend là où elle s'était arrêtée |
| Hub | Aucun effet sur les dashboards |
| Intelligence | Aucun effet sur Nginx : chaque instance reste autonome |
| Redis | Les statistiques en cours d'agrégation sont perdues au redémarrage de l'analyseur ou du challenge, comme sans Redis |
| Dashboard | Nginx continue de servir le trafic avec la dernière configuration chargée |

## Choisir ce que l'on déploie

| Besoin | Composants |
|---|---|
| Un reverse proxy avec interface | Nginx et dashboard |
| Détecter et bloquer les comportements abusifs | + analyseur, blocklists, challenge, WAF émulé (activés depuis le dashboard) |
| Piloter des serveurs distants | + agent sur chaque serveur |
| Superviser plusieurs installations | + Hub |
| Conserver et interroger les journaux dans la durée | + log store (le shipper est géré par le dashboard) |
| Garder les statistiques après un redémarrage | + Redis |

## Une seule version pour toute la suite

Tous les composants portent le même numéro de version. Voir [Versions et mise à jour](versions.md).
