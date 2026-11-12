# Brancher les producteurs sur le log store (via le shipper)

> Statut : le **shipper** (access logs) est livré dans `nginx-analyzer-go` (binaire `shipper`, ticket #6).
> Producteurs : **WAF émulé**, **challenge** (client `internal/decisions`), **blocklist** (journal lu par le shipper), **analyseur** (alertes, #110) et **CrowdSec** (nouvelles décisions locales, poussées par le dashboard, #110) sont branchés ; ce document en fixe le contrat.

## Principe
Un seul point de sortie vers le log store : le **shipper**.

```
nginx ─ access logs ──► shipper ──(HTTPS, jeton write, tampon disque durable)──► log store
WAF / blocklist / challenge / CrowdSec ──(HTTP local, jeton local)──► shipper
```

- Les producteurs ne connaissent ni l'URL distante ni le jeton `write` : seulement l'adresse locale du
  shipper et un jeton local (`LOGSHIP_LOCAL_TOKEN`).
- L'analyseur n'envoie **plus** de lignes d'accès (le shipper les lit lui-même dans les fichiers).
- Le shipper expose son état en HTTP (`/status`, `/healthz`) : pas besoin des journaux Docker.
- Compromis assumé : si le shipper est arrêté, les décisions émises pendant ce temps sont perdues.

## Envoyer des décisions
`POST http://<shipper>:9181/v1/events`, `Authorization: Bearer <LOGSHIP_LOCAL_TOKEN>`, corps NDJSON de
`wire.Event` (voir `pkg/wire`). `202` seulement une fois les événements écrits durablement ; `400` si tout est
refusé ; `413` au-delà de 5000 événements / 4 Mio / 64 Kio par ligne ; `503` si le tampon est indisponible
(réessayer). La source `access` est refusée.

```sh
curl -sS -X POST http://shipper:9181/v1/events \
  -H "Authorization: Bearer $LOGSHIP_LOCAL_TOKEN" -H 'Content-Type: application/x-ndjson' \
  --data-binary $'{"source":"waf","action":"logged","site":"a.example","ip":"198.51.100.1","path":"/x","rule":"942100"}\n'
```

## Correspondance des sources
| Producteur | `source` | `action` | `rule` | `extra` |
|---|---|---|---|---|
| ligne d'accès nginx (shipper) | `access` | `allowed` (toujours : l'access log ne dit pas ce que nginx a refusé en amont ; le statut HTTP est conservé) | — | — |
| WAF émulé (hit) | `waf` | `logged` (détection seule) | id de la règle de plus fort score | `score`, `mode`, `possibly_succeeded`, `rules` (≤ 20 identifiants), `categories` |
| analyseur (alertes du détecteur, #110) | `analysis` | `logged` | type d'alerte (`bruteforce`, `scan`, `flood`, `scraping`, `volumetric`, `data_volume`, `country_traffic`, `custom:<nom>`) | `severity`, `summary` (≤ 300 car.), `alert_id`, chiffres clés ; un événement par alerte créée |
| challenge HTTP | `challenge` | `allowed` (`solved`) / `challenged` (`failed`, `redirected`) / `blocked` (`rate_limited`, `auto_ban`) | `solved`, `failed`, `redirected`, `rate_limited`, `auto_ban` | `solved` : `bits` ; `failed` : `reason` ; `rate_limited` : `stage` ; `auto_ban` : `attempts`, `window_min`, `until`, `redirected`, `failed`, `rate_limited` |
| blocklist (journal `blocklist-hits.log`, lu par le shipper) | `blocklist` | `blocked` | nom de la liste (première par ordre alphabétique) si le shipper joint l'analyseur (`LOGSHIP_ANALYZER_URL`), sinon vide | `lists` : toutes les listes qui contiennent l'IP (≤ 10), seulement si plusieurs |
| CrowdSec (nouvelle décision locale, #110) | `crowdsec` | `blocked` (`ban`) / `challenged` (`captcha`) / `logged` (autre) | scénario | `type`, `origin`, `decision_id`, `duration` ; portée non-IP : `scope` + `value` (pas d'`ip`) |

Les `extra` du WAF et du challenge sont figés ; limite : 4 Kio, JSON. Le challenge n'émet que des décisions (pas les requêtes passées par cookie ou robot vérifié, déjà dans le journal d'accès) et n'a pas de chemin (le sous-appel `auth_request` ne le transmet pas).

**CrowdSec** (#110) : ses décisions sont un état (bannissements), pas des événements par requête. Le **dashboard** interroge le LAPI (`/v1/decisions`, clé de bouncer, lecture seule) toutes les 60 s et dépose sur l'API locale du shipper **un événement par nouvelle décision** (id jamais vu ; l'état, le plus grand id traité, est dans `config/.crowdsec-ship-state.json`, avancé seulement après un envoi réussi). Premier passage : seulement les décisions de moins d'1 h. Les décisions de la communauté (`CAPI`, `lists`) et simulées sont ignorées. Actif si `shipper_enable` et `shipper_crowdsec` (défaut `true`) dans `logstore.yml` et si CrowdSec est configuré ; les requêtes bloquées par CrowdSec au niveau bouncer ne sont pas des événements (elles restent dans le journal d'accès).

## Protocole du tampon (`pkg/logsink`)
Utilisé par le shipper (copie dans `nginx-analyzer-go/internal/logsink`, à garder synchronisée).
`Commit(events, meta)` écrit durablement (fsync) une unité de tampon puis rend la main ; `meta` (une ligne)
est conservée avec l'unité et relue par `PendingMeta()` au redémarrage (position de lecture). L'unité est
envoyée en sous-lots de `BatchSize` avec des clés `Idempotency-Key` déterministes (`<id>.<n>`) : un rejeu
retombe sur les mêmes clés et le serveur déduplique. Statuts : 2xx supprime ; 429 `Retry-After` ; 401/403
suspend (nouvel essai toutes les 10 min) ; 413 coupe le sous-lot (clés dérivées) ; autre 4xx abandonne ;
3xx refusé (jamais suivi) ; 5xx/réseau backoff exponentiel.

## Mode distant (étape 4)
`LOGSINK_URL` du shipper peut pointer vers un log store sur un autre serveur : TLS obligatoire (`http://`
seulement avec `LOGSINK_ALLOW_INSECURE`, réseau interne), un jeton `write` par instance. Aucune redirection
n'est suivie (le jeton ne part jamais ailleurs). Si l'URL est saisie dans une interface (dashboard), la
valider contre le SSRF avant de l'enregistrer : schéma https, hôte résolu non privé sauf liste d'hôtes
autorisés explicite.
