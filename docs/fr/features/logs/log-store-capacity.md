# Capacité et performances du log store

Ces chiffres proviennent d'un banc de charge synthétique. Ils donnent des **ordres de grandeur** : ils dépendent de votre matériel et de votre trafic. Pour mesurer votre propre installation, un kit en lecture seule est fourni (voir plus bas).

## Résultats de référence

Mesures sur un poste de développement (WSL2, 8 cœurs, 16 Go), TimescaleDB, **2 millions d'événements sur 14 jours** :

| Mesure | Résultat |
| ------ | -------- |
| Ingestion | environ 38 000 événements par seconde (lots de 2 000, p95 de 254 ms, aucun rejet) |
| Trafic visé | quelques dizaines d'événements par seconde : une marge d'environ ×1000 |
| Disque avant compression | environ 430 octets par événement, index compris |
| Disque après compression | environ 100 octets par événement (compression ×10) |
| Mémoire | log store environ 11 Mo, PostgreSQL environ 1 Go (cache) après la charge |

Temps de réponse typiques (médiane) :

| Requête | Durée |
| ------- | ----- |
| Recherche d'événements | quelques millisecondes |
| Tops, sécurité sur 24 h, campagnes sur 24 h | 60 à 250 ms |
| Fiche IP | 60 à 380 ms |
| Statistiques de visites sur 7 jours | 3,6 à 4,6 s |
| Statistiques de visites sur 14 jours | 8 à 10,5 s |
| Statistiques par IP sur 7 jours | 5,3 à 5,8 s |

!!! warning "Statistiques longues"
    Les statistiques de visites et par IP sont les requêtes les plus coûteuses : elles comptent des valeurs distinctes sur les données brutes. Le délai maximal d'une requête est de 15 secondes (`LOGSTORE_QUERY_TIMEOUT_SECONDS`) ; sur un très gros volume, préférer des périodes courtes.

La compression ne change pas la durée des requêtes lentes.

## Estimer l'espace disque

Avec environ 100 octets par événement après compression, 50 événements par seconde représentent environ 4,3 millions d'événements par jour, soit environ 1,9 Go par jour avant compression et 430 Mo après. Les journaux bruts sont conservés 7 à 30 jours, les cumuls beaucoup plus longtemps mais pour un volume très inférieur. Ce calcul est une estimation à confirmer avec une mesure sur votre trafic.

## Mesurer votre installation

Le dossier `bench/` du log store contient deux outils indépendants :

| Outil | Où l'exécuter | Rôle |
| ----- | ------------- | ---- |
| `run.sh` | Poste de développement (Docker, Node 18 ou plus) | Pile jetable, ingestion synthétique, latence des requêtes de l'API |
| `measure-prod.sh` | Hôte de production | Mesure en lecture seule : volume par jour, débit, tailles, compression, ressources |

```bash
./measure-prod.sh <conteneur-db> [<conteneur-logstore> [<conteneur-shipper>]] > mesure-$(date +%Y%m%d).txt
```

Le kit de production n'écrit rien, n'utilise aucun jeton et n'accède pas au réseau. Le fichier produit ne contient ni IP ni chemin, seulement des volumes, des durées et des tailles.
