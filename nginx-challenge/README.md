# nginx-challenge

Petit service sans état (Go, bibliothèque standard uniquement) qui vérifie qu'un
visiteur est un navigateur capable d'exécuter du JavaScript, puis lui délivre un
cookie signé. Il sert de **remédiation « challenge »** aux IP que l'Analyse a
repérées (voir le README principal, section « Remédiation par challenge »).

## Fonctionnement

1. nginx appelle `/check` (sous-requête `auth_request`) pour chaque requête d'une
   IP de la liste « challenge » ; les autres IP ne sont jamais concernées.
2. Sans cookie valide, le visiteur est redirigé vers `/.nc-challenge/go<URL d'origine>`.
3. La page demande un défi (`/.nc-challenge/api/start`), le navigateur cherche une
   preuve de travail SHA-256 (quelques centaines de ms avec 16 bits), puis envoie la
   solution (`/.nc-challenge/api/verify`).
4. Le service pose le cookie `nc_chal` (HttpOnly, Secure, SameSite=Lax), lié à
   l'IP (/64 en IPv6) et au nom d'hôte, signé HMAC-SHA-256, valable 24 h par défaut,
   puis renvoie vers l'URL d'origine (chemin relatif uniquement : pas de redirection ouverte).

Garde-fous : jeton de défi lié à l'IP et à l'hôte, expirant (5 min), à usage unique ;
quota par IP sur `/api/*` ; corps limité à 2 Ko ; refus des requêtes inter-sites ;
CSP stricte sur la page.

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `NC_SECRET` / `NC_SECRET_FILE` | tiré au hasard au démarrage | Secret de signature (≥ 32 caractères). **À définir** pour que les cookies survivent à un redémarrage. |
| `NC_BIND` | `:8080` | Adresse d'écoute |
| `NC_DIFFICULTY_BITS` | `16` | Difficulté de la preuve de travail (8–64 ; +1 bit = ×2 de travail ; au-delà de ~30 bits un navigateur n'aboutit plus en un temps raisonnable) |
| `NC_COOKIE_HOURS` | `24` | Durée du cookie (1–720) |
| `NC_TOKEN_SECONDS` | `300` | Durée de validité d'un défi (30–900) |
| `NC_COOKIE_NAME` | `nc_chal` | Nom du cookie |
| `NC_BIND_IP` | `true` | Lier le cookie à l'IP (recommandé) |
| `NC_COOKIE_SECURE` | `true` | Attribut `Secure` (HTTPS) |
| `NC_RATE_PER_MIN` | `30` | Appels `/api/*` par IP et par minute |
| `NC_GOODBOTS` | `true` | Autoriser les robots d'indexation vérifiés sur les vhosts « sauf bons robots » |
| `NC_GOODBOTS_EXTRA` | — | Robots supplémentaires : `nom\|regex-UA\|.suffixe1,.suffixe2;nom2\|…` |
| `NC_AUTOBLOCK` | `false` | Bloquer automatiquement les IP qui échouent systématiquement (voir ci-dessous) |
| `NC_AUTOBLOCK_THRESHOLD` | `30` | Échecs déclenchant le blocage (3–100000) |
| `NC_AUTOBLOCK_WINDOW_MIN` | `60` | Fenêtre de comptage des échecs, en minutes (1–1440) |
| `NC_AUTOBLOCK_HOURS` | `24` | Durée du blocage (1–720 h) |
| `NC_OFFENDERS_HOURS` | `24` | Historique par IP conservé en mémoire pour l'analyse (1–168 h) |

Tous ces réglages ont un `ARG` dans le `Dockerfile` (`--build-arg`) et se surchargent à l'exécution.
`NC_SECRET` n'a volontairement pas d'`ARG` (un secret de build reste lisible dans l'image).

## Laisser passer les bons robots (indexation)

Sur un vhost qui inclut `challenge-all-allowbots.conf`, tout le monde est challengé **sauf** les robots
d'indexation dont l'adresse est confirmée par DNS inverse (IP → nom → IP, avec un nom du domaine officiel) :
Googlebot, Bingbot, Applebot, Yandex, Baidu, plus vos règles `NC_GOODBOTS_EXTRA`. L'user-agent seul ne suffit
jamais (il se falsifie). Résultats en cache (24 h / 15 min), recherches DNS limitées (2 s, 16 en parallèle).
Les robots qui ne publient pas de DNS inverse (DuckDuckBot, facebookexternalhit…) ne sont pas reconnus :
exemptez-les par adresse côté nginx si nécessaire.

## IP en échec et blocage automatique (v12.73.0)

Le service suit, **en mémoire** (jamais écrit sur disque, borné à 20 000 IP, effacé au redémarrage), les IP qui n'arrivent pas
à passer le challenge. Une *tentative en échec* = redirection vers la vérification (401 du contrôle), solution fausse/expirée
ou limitation de débit. Une IP qui a résolu le challenge au moins une fois n'est **jamais** bloquée (réseaux partagés / NAT) ;
les bons robots vérifiés ne sont pas comptés.

Avec `NC_AUTOBLOCK=true`, une IP qui cumule `NC_AUTOBLOCK_THRESHOLD` échecs dans `NC_AUTOBLOCK_WINDOW_MIN` minutes sans
jamais résoudre est bloquée `NC_AUTOBLOCK_HOURS` heures : `/check` répond **403** immédiatement. Routes internes (refusent
toute requête portant `X-Real-IP`) : `GET /offenders?hours=&min=&limit=&neverSolved=`, `GET /bans` (`?since=<seq>` pour
l'historique des déclenchements), `GET /blocklist` (texte, une IP par ligne), `POST /unban?ip=`.

## Sécurité

- **Ne publiez pas le port 8080** : seul nginx doit l'atteindre (réseau Docker interne).
  Le service fait confiance à `X-Real-IP` et `Host`, que nginx écrase à chaque requête.
- Une preuve de travail arrête les robots qui n'exécutent pas de JavaScript ; elle ne
  bloque pas un attaquant qui pilote un vrai navigateur. C'est un filtre de coût, pas un mur.

## Développement

```
go vet ./... && go test -race ./...
```
