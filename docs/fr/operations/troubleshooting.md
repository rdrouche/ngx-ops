# Dépannage

Cette page liste des symptômes courants, leur cause probable et l'action à mener. Elle se limite à des cas documentés dans le comportement de NGX Ops.

## Installation et dashboard

| Symptôme | Cause | Action |
| -------- | ----- | ------ |
| La page CrowdSec reste vide ou « non disponible » | Le conteneur NGX Ops ne joint pas CrowdSec | Connecter le conteneur au réseau Docker de CrowdSec (voir [CrowdSec](../features/security/crowdsec.md)) |
| Les statistiques du challenge sont vides | Le dashboard ne joint pas le conteneur du challenge | Les placer sur le même réseau Docker ; l'image du challenge doit être à jour |
| Le premier clone Git échoue | Un dossier temporaire interrompu reste dans l'espace de travail Git | NGX Ops nettoie les dossiers connus ; sinon il nomme ce qui reste, à supprimer manuellement |
| L'édition en ligne ou la restauration locale est refusée | Git est configuré : le dépôt est la source de vérité | Modifier le dépôt puis déployer ; `git revert` pour revenir en arrière |
| Les réglages `challenge_*` ne sont pas pris en compte | La configuration Nginx n'a pas été régénérée | Utiliser **Régénérer et recharger Nginx** depuis la page Challenge HTTP |
| Les webhooks disparaissent après un redémarrage | Ils ne sont conservés qu'en mémoire | Les recréer, voir [API REST et webhooks](../dashboard/api.md) |

## Sauvegardes

| Symptôme | Cause | Action |
| -------- | ----- | ------ |
| Des archives S3 disparaissent | La rotation supprime les anciens `.zip` du préfixe | Utiliser un préfixe dédié ; ajuster `s3_keep` |
| Archive `.ngxb` illisible | Mauvaise phrase de passe ou archive altérée | Vérifier la variable de phrase (`HUB_`, `S3_` ou `BACKUP_`) ; aucune récupération sans elle |
| Trois copies à chaque modification | `auto_local`, `auto_git` et `auto_s3` sont tous actifs | Choisir une seule destination automatique |

## Journalisation

| Symptôme | Cause | Action |
| -------- | ----- | ------ |
| Le log store refuse de démarrer | Mode `pseudonymized` sans `LOGSTORE_PSEUDO_KEY`, ou `LOGSTORE_REQUIRE_TIMESCALE=true` sans TimescaleDB | Fournir la clé (32 caractères minimum) ou une base TimescaleDB |
| Le shipper n'envoie plus | Jeton `write` refusé, ou log store injoignable | Voir `GET /status` du shipper ; les journaux d'accès sont rattrapés au retour, le tampon est plafonné |
| Des lignes d'accès manquent après une rotation | Rotation par renommage vers un nom hors motif | Utiliser `copytruncate`, ou un nom qui correspond au motif |
| Des décisions manquent | Le shipper était arrêté : elles ne sont pas rejouées | Comportement accepté ; garder le shipper démarré |
| Une statistique expire | Période trop longue sur un gros volume (délai de 15 s) | Réduire la période, voir [Capacité du log store](../features/logs/log-store-capacity.md) |

## Hub

| Symptôme | Cause | Action |
| -------- | ----- | ------ |
| Instance « Hors ligne » | 3 échecs consécutifs de collecte | Vérifier l'URL HTTPS, le certificat, `HUB_TOKEN_SHA256` côté dashboard |
| Instance refusée sur un réseau privé | Protection contre les requêtes vers l'interne | Régler `security.allow_private_networks` ou `allowed_cidrs` |
| Jetons et MFA illisibles après une restauration | `HUB_SECRET_KEY` perdue ou différente | Restaurer la clé d'origine avec `/data` |
| Mot de passe `admin` perdu | — | `docker compose exec hub node bin/hub-admin.js set-password admin --must-change` |
| L'archive ne s'ouvre pas dans le navigateur | HTTPS (ou `localhost`) requis, ou mauvaise phrase | Passer en HTTPS ; utiliser `ngxb-decrypt.js` en secours |

## Agents distants

| Symptôme | Cause | Action |
| -------- | ----- | ------ |
| L'agent ne démarre pas | `--relay-*-advertise` est un simple numéro de port | Donner l'adresse complète, par exemple `http://10.0.5.9:8080` |
| Erreur 502 en mode relay vers un service HTTPS | Certificat auto-signé refusé par l'agent | Activer `RELAY_BACKEND_INSECURE_SKIP_VERIFY=true` |
| Le jeton n'est plus affiché | Il ne l'est qu'une fois | Régénérer le jeton depuis la page Hôtes distants |
| WebSocket ou SSE ne passe pas | Mode tunnel : non pris en charge | Passer le vhost en mode `relay` |

Pour comprendre l'état d'un hôte virtuel, la page [Diagnostic](../features/diagnostics.md) teste ses backends et affiche sa configuration. L'état de chaque composant est visible via [Santé et Redis](../dashboard/health.md).
