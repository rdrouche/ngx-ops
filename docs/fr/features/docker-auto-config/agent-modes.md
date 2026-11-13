# Agents distants : modes et options

Cette page détaille le fonctionnement de l'agent installé sur un hôte Docker distant. Pour l'installation et l'approbation, voir [Autoconfiguration avec Docker sur hôte distant](remote-host.md).

L'agent lit les labels `nginx-control.*` des conteneurs de son hôte, construit un manifeste et le pousse périodiquement à NGX Ops avec un jeton. La cible d'un label (`target`, ou son alias `proxy_pass`) est une adresse **joignable depuis l'hôte qui la sert**, jamais un nom de conteneur partagé avec Nginx.

Un conteneur sans `nginx-control.enable=true`, sans `server_name` ou sans au moins une location valide est ignoré. NGX Ops revalide de toute façon l'intégralité du manifeste.

## Choisir un mode

| Mode | Nginx joint… | Connexion entrante sur l'hôte distant | Streaming |
| ---- | ------------ | ------------------------------------- | --------- |
| `direct` (défaut) | directement la cible de chaque location | Un port par service | Oui |
| `relay` | un port fixe de l'agent | Un ou deux ports fixes | Oui, WebSocket et SSE compris |
| `tunnel` | NGX Ops, qui relaie par un tunnel sortant | Aucune | Non |

## Mode tunnel

Si au moins un vhost déclare `mode: tunnel`, l'agent ouvre une connexion WebSocket **sortante** vers NGX Ops (avec le même jeton) et la maintient, avec reconnexion automatique. NGX Ops relaie chaque requête du vhost dans ce tunnel ; l'agent la route vers la cible de la location par préfixe de chemin le plus long.

Il convient aux hôtes **sans port entrant**, derrière un NAT par exemple.

Limites :

* une seule requête à la fois par connexion, corps entièrement tamponnés ;
* pas de WebSocket ni de SSE à travers le tunnel (le mode `relay` les gère) ;
* une seule connexion de tunnel active par agent ;
* `--insecure-skip-verify` désactive la vérification TLS : réservé aux tests.

## Mode relay

L'hôte distant **peut** recevoir des connexions, mais on évite d'ouvrir un port par service. L'agent ouvre **un port HTTP et/ou un port HTTPS fixes** et route vers la bonne cible selon le nom d'hôte et le chemin. La connexion est directe, avec streaming complet : NGX Ops n'est plus dans le chemin des requêtes.

```yaml
labels:
  nginx-control.enable: "true"
  nginx-control.vhost.server_name: "app.example.com"
  nginx-control.vhost.mode: "relay"
  nginx-control.vhost.relay_scheme: "https"   # http ou https : relais utilisé par ce vhost
  nginx-control.vhost.location01: "/"
  nginx-control.vhost.location01.target: "http://127.0.0.1:8080"
```

Côté agent :

```bash
./nginx-control-agent --dashboard-url https://dashboard.example.com \
  --relay-http-listen :8080 --relay-http-advertise http://203.0.113.44:8080 \
  --relay-https-listen :8443 --relay-https-advertise https://203.0.113.44:8443
```

Un seul des deux relais suffit si vous n'avez pas besoin de les distinguer. Sans `--relay-https-cert` et `--relay-https-key`, le relais HTTPS utilise un certificat auto-signé généré en mémoire ; le vhost généré ajoute alors `proxy_ssl_verify off;`. Fournir un vrai certificat permet de s'en passer.

### `listen` et `advertise`

Les deux répondent à des questions différentes :

* `--relay-*-listen` : sur quelle interface et quel port l'agent ouvre-t-il son socket ? C'est presque toujours générique (`:8080`).
* `--relay-*-advertise` : à quelle adresse **Nginx** doit-il joindre l'agent ? Une adresse **complète**, avec le schéma (`http://10.20.0.5:8080`), jamais un simple numéro de port, que l'agent refuse au démarrage.

| Situation | `listen` | `advertise` |
| --------- | -------- | ----------- |
| Docker republie le port sous un autre numéro (`8080:19000`) | `:8080` | `http://vps.example.com:19000` |
| Plusieurs interfaces, une seule joignable depuis Nginx | `:8080` | `http://10.20.0.5:8080` |
| Un répartiteur de charge est intercalé | `:8080` | l'adresse publique du répartiteur |
| Déploiement simple, une IP publique | `:8080` | `http://<cette IP>:8080` |

### Schémas à chaque saut

Les trois sauts choisissent leur schéma indépendamment : client → Nginx (HTTPS habituel), Nginx → agent (`relay_scheme`), agent → service (le schéma de `target`). Par exemple, un relais en HTTP vers un service qui exige HTTPS avec un certificat auto-signé :

```yaml
labels:
  nginx-control.vhost.mode: "relay"
  nginx-control.vhost.relay_scheme: "http"
  nginx-control.vhost.location01.target: "https://127.0.0.1:9443"
```

Par défaut, l'agent **vérifie** le certificat d'un service en `https://`. Pour un certificat auto-signé, activer `--relay-backend-insecure-skip-verify` (variable `RELAY_BACKEND_INSECURE_SKIP_VERIFY=true`). Ce réglage ne concerne que le dernier saut, agent vers service.

## Snippets de location en relay et tunnel

Le routage par chemin se faisant côté agent, le vhost Nginx généré n'a qu'un `location /`. Une location qui porte au moins un snippet (`nginx-control.vhost.locationNN.snippetMM`) reçoit en plus son propre bloc `location <chemin>`, avec le même `proxy_pass` et les mêmes en-têtes, suivi des `include snippets/...`. Les snippets d'une location `/` sont ajoutés dans `location /`. Les locations sans snippet ne génèrent aucun bloc.

## Plusieurs NGX Ops (DMZ et LAN)

Un même agent peut publier vers plusieurs NGX Ops indépendants, par exemple un frontal en DMZ et un dashboard interne. Chaque NGX Ops approuve l'agent séparément et lui donne son propre jeton.

`--targets-file` (ou `TARGETS_FILE`) remplace `--dashboard-url`, `--state-file` et `--token` par un fichier JSON :

```json
[
  { "name": "dmz", "dashboardUrl": "https://dmz.example.com",  "stateFile": "/data/dmz-state.json", "tokenFile": "/data/dmz-token" },
  { "name": "lan", "dashboardUrl": "https://lan.internal:3000", "stateFile": "/data/lan-state.json", "tokenFile": "/data/lan-token" }
]
```

Fournir les deux formes en même temps est une erreur au démarrage. Par défaut, un conteneur est publié vers **toutes** les cibles ; pour le restreindre :

```text
nginx-control.publish=dmz,lan
```

Les relais du mode `relay` et leur adresse d'annonce restent **partagés** entre toutes les cibles. Si DMZ et LAN n'atteignent pas l'agent par la même adresse, lancez deux processus d'agent.

## Options de l'agent

Chaque option existe en variable d'environnement (utile en conteneur) ; l'option en ligne de commande prime.

| Option | Rôle | Défaut |
| ------ | ---- | ------ |
| `--dashboard-url` | URL de NGX Ops (sauf avec `--targets-file`) | — |
| `--targets-file` | Plusieurs cibles | vide |
| `--hostname` | Nom proposé à l'enrôlement | nom d'hôte système |
| `--state-file` | Fichier local (identifiant et jeton) | `./nginx-control-agent-state.json` |
| `--token` / `--token-file` | Jeton direct, ou fichier relu à chaque cycle | — |
| `--docker-socket` | Socket Docker local | `/var/run/docker.sock` |
| `--poll-interval` | Intervalle entre deux envois | `30s` |
| `--tunnel` | Active le client tunnel si besoin | `true` |
| `--relay-http-listen` / `--relay-http-advertise` | Relais HTTP | désactivé |
| `--relay-https-listen` / `--relay-https-advertise` | Relais HTTPS | désactivé |
| `--relay-https-cert` / `--relay-https-key` | Certificat du relais HTTPS | auto-signé |
| `--relay-backend-insecure-skip-verify` | Ne pas vérifier le certificat d'un service HTTPS | `false` |

### Jeton : fichier ou variable

* `TOKEN_FILE` (choix par défaut) : le jeton ne passe pas par l'environnement et sa rotation ne demande **aucun redémarrage**.
* `TOKEN` : pratique avec un coffre à secrets qui injecte des variables, mais visible par tout ce qui lit l'environnement du conteneur ; un changement demande de recréer le conteneur. Si les deux sont renseignés, `TOKEN` l'emporte.

## Métriques de l'hôte

Sous Linux, l'agent joint à chaque envoi l'utilisation CPU et mémoire, la durée de fonctionnement et le débit réseau de l'hôte, affichés sur la page **Hôtes distants**. Sur un autre système, ces informations sont simplement omises.
