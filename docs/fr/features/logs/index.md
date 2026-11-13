# Les logs dans NGX Ops

Les logs généré par Nginx sont un élément centrale de **NGX Ops**, car ils sont au coeurs de différentes fonctionnalités 

- Affichage des logs en directe, qui vous permettent de suivre les requetes sur vos hôtes virtuels
- Analyse
- WAF
- Résumé périodique
- Carte
- Analyse des Blocklists IP

Pour exploiter pleinement ces logs, il est nécessaire de configurer le serice [**Nginx Analyzer**](../nginx-analyzer.md).

## Centraliser les journaux

Pour conserver les journaux, les rechercher et les corréler sur plusieurs serveurs, NGX Ops peut les envoyer à un [log store](log-store.md) par un [shipper](shipper.md). Les ordres de grandeur sont donnés dans [Capacité du log store](log-store-capacity.md), et la consultation multi-instances dans le [Hub](../../hub/index.md).
