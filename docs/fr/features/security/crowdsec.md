# CrowdSec

**NGX Ops** permet de s'interfacer avec [**CrowdSec**](../../appendices/deploy-crowdsec-docker.md) afin de disposer directement dans l'interface des informations et des fonctionnalités liées à CrowdSec.

L'intégration peut être réalisée à **trois niveaux**, selon les besoins :

* **Prometheus** : permet de récupérer les statistiques et métriques de CrowdSec, avec notamment un affichage équivalent à la commande `cscli metrics`.
* **Bouncer** : permet à NGX Ops d'interroger l'API locale de CrowdSec afin de consulter les décisions, notamment les adresses IP actuellement bloquées.
* **Machine** : permet à NGX Ops d'interagir avec l'API CrowdSec et notamment de créer ou supprimer des décisions depuis l'interface.

Ces trois intégrations peuvent être utilisées indépendamment les unes des autres.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-032-crowdsec.png" width="800" />

> **À noter :** l'intégration CrowdSec apparaît dans le menu de NGX Ops uniquement lorsqu'une configuration CrowdSec est définie.

## Prérequis

NGX Ops doit pouvoir communiquer avec CrowdSec.

Lorsque CrowdSec et NGX Ops sont exécutés dans des conteneurs Docker sur le même hôte, le conteneur NGX Ops doit notamment être connecté au réseau Docker utilisé par CrowdSec.

Par exemple, si le réseau CrowdSec est un réseau Docker externe nommé `crowdsec-net`, créer un fichier `compose.override.yml` :

```yaml
services:
  ngx-ops-dashboard:   # nom du service NGX Ops dans votre compose
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    external: true
```

Cette configuration permet au conteneur NGX Ops de joindre directement le conteneur CrowdSec sur son réseau Docker.

---

## Intégration avec Prometheus

La première intégration permet à NGX Ops de récupérer les **métriques exposées par CrowdSec**.

Elle permet notamment d'obtenir depuis NGX Ops des informations similaires à celles retournées par :

```bash
cscli metrics
```

### Configuration

Aller dans : **ADMINISTRATION → Configuration → CrowdSec**

Dans la configuration, renseigner l'URL de l'endpoint Prometheus de CrowdSec :

```yaml
prometheus_url: http://10.199.0.5:6060/
```

Adapter l'adresse IP à votre environnement.

Cliquer ensuite sur **Sauvegarder**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-033-crowdsec.png" width="800" />

Actualiser ensuite **NGX Ops** avec la touche **F5** afin de recharger la configuration.

L'intégration CrowdSec est alors disponible dans le menu : **INTEGRATION → CrowdSec**

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-034-crowdsec.png" width="800" />

Cette première intégration est suffisante si vous souhaitez uniquement disposer des **statistiques CrowdSec** dans NGX Ops.

---

## Intégration en tant que Bouncer pour accéder à l'API

La deuxième intégration permet à NGX Ops d'interroger l'API locale de CrowdSec afin notamment de récupérer les **décisions** prises par CrowdSec.

Pour cela, nous allons créer un Bouncer dédié à NGX Ops afin d'obtenir une clé d'API.

Depuis le conteneur CrowdSec, exécuter :

```bash
docker compose exec crowdsec cscli bouncers add ngx-ops
```

CrowdSec retourne alors une clé d'API.

Retourner ensuite dans : **ADMINISTRATION → Configuration → CrowdSec**

et ajouter les informations suivantes :

```yaml
url: http://10.199.0.5:8080/
api_key: "****************"
local_only: true
```

Adapter l'URL à votre environnement et remplacer la valeur de `api_key` par la clé retournée par CrowdSec.

Cliquer sur **Sauvegarder**, puis recharger **NGX Ops** avec la touche **F5**.

Les décisions CrowdSec sont maintenant accessibles depuis la page **CrowdSec** de NGX Ops.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-035-crowdsec.png" width="800" />

> **À noter :** l'API utilisée ici retourne uniquement les **100 premières décisions**.

Cette intégration donne à NGX Ops une visibilité sur les décisions prises par CrowdSec, mais ne permet pas encore à NGX Ops de modifier ces décisions.

---

## Intégration en tant que Machine pour agir sur l'API

La troisième intégration permet d'aller plus loin.

NGX Ops peut être déclaré comme une **Machine CrowdSec** afin de pouvoir interagir avec l'API et notamment **ajouter ou supprimer des décisions**.

Cette intégration est particulièrement intéressante lorsqu'une adresse IP détectée par les règles d'analyse de NGX Ops doit être bloquée directement dans CrowdSec.

### Créer la Machine CrowdSec

Depuis le conteneur CrowdSec, exécuter :

```bash
docker compose exec crowdsec cscli machines add ngx-ops --auto --file /etc/crowdsec/lapi_api_cred_ngx_ops.yaml
```

Cette commande crée les identifiants permettant à NGX Ops de s'authentifier auprès de l'API CrowdSec en tant que Machine.

Le fichier contenant les identifiants est :

```text
/etc/crowdsec/lapi_api_cred_ngx_ops.yaml
```

Dans notre exemple, ce fichier correspond sur l'hôte au chemin :

```text
./crowdsec/config/lapi_api_cred_ngx_ops.yaml
```

Ouvrir ce fichier et récupérer le mot de passe généré pour la Machine `ngx-ops`.

### Configurer NGX Ops

Retourner dans : **ADMINISTRATION → Configuration → CrowdSec**

et ajouter les informations suivantes :

```yaml
machine_id: ngx-ops
machine_password: "*******"
```

Cliquer sur **Sauvegarder**, puis recharger **NGX Ops** avec la touche **F5**.

NGX Ops dispose maintenant des droits nécessaires pour interagir avec les décisions CrowdSec.

Il devient notamment possible de **bloquer une adresse IP directement depuis NGX Ops**, en créant une décision CrowdSec.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-036-crowdsec.png" width="800" />

## Les trois niveaux d'intégration

Pour résumer :

| Intégration    | Fonction                   | Droits             |
| -------------- | -------------------------- | ------------------ |
| **Prometheus** | Statistiques et métriques  | Lecture            |
| **Bouncer**    | Consultation des décisions | Lecture            |
| **Machine**    | Gestion des décisions      | Lecture / écriture |

La configuration dépend donc de ce que vous souhaitez faire avec CrowdSec dans NGX Ops.

Si vous souhaitez uniquement consulter les métriques, **Prometheus suffit**.

Pour afficher les IP bannies et les décisions CrowdSec, ajoutez l'intégration **Bouncer**.

Enfin, si vous souhaitez permettre à NGX Ops de **créer ou supprimer des décisions CrowdSec**, l'intégration **Machine** est nécessaire.

---

## Variables d'environnement équivalentes

Chaque clé de `crowdsec.yml` a une variable Docker de repli (`CROWDSEC_PROMETHEUS_URL`, `CROWDSEC_URL`, `CROWDSEC_API_KEY`, `CROWDSEC_LOCAL_ONLY`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD`). Une clé renseignée dans le fichier l'emporte sur la variable. Les secrets (`api_key`, `machine_password`) ne sont jamais réaffichés une fois enregistrés.

Pour vider un champ, voir [Variables d'environnement](../../environment.md).

## Limites connues

* L'API CrowdSec n'expose pas la liste des Bouncers ni des Machines enregistrés : NGX Ops ne l'affiche pas. Utiliser `cscli bouncers list` ou `cscli machines list` sur l'hôte CrowdSec.
* `local_only: true` masque les décisions de la liste communautaire (CAPI) et ne garde que les décisions locales.
