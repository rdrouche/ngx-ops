# Tâches planifiées (Scheduler)

La page **Scheduler** exécute des actions à heure fixe. Les tâches sont stockées dans la base du dashboard et se gèrent depuis l'interface.

## Créer une tâche

**Nouvelle tâche** : choisir l'action, la planification, les options propres à l'action, l'activation et l'envoi d'un e-mail à la fin.

La planification est visuelle (toutes les X minutes ou heures, tous les jours, certains jours de la semaine, jour du mois) ou en **cron** pour le mode avancé. Un aperçu affiche les cinq prochaines exécutions, dans le fuseau horaire du serveur (variable `TZ`).

## Les actions

| Action | Effet |
| ------ | ----- |
| Recharger Nginx | `nginx -t` puis `nginx -s reload`, sans interruption. Annulé si la configuration est invalide |
| Redémarrer le conteneur Nginx | Redémarre le conteneur, après le même test préalable. Utile pour ce qu'un rechargement ne corrige pas |
| Redémarrer l'analyzer | Redémarre le conteneur de l'analyseur et attend que son API réponde. L'historique et la baseline sont conservés |
| Résumé périodique | Génère le résumé (trafic, robots, CrowdSec, WAF, certificats), visible dans la page Résumé et envoyable par e-mail |
| Sauvegarde | ZIP local, Git, S3 ou une combinaison |
| Sauvegarde vers le Hub | Envoie la configuration Nginx, les fichiers de configuration NGX Ops et les variables d'environnement (secrets masqués) au [Hub](../hub/backups.md) |
| Redémarrer GoAccess | Redémarre les conteneurs GoAccess choisis (tous les actifs si aucun n'est sélectionné) |
| Redémarrer des conteneurs gérés | Redémarre les conteneurs choisis (analyzer, WAF, shipper, challenge, certbot…) l'un après l'autre. Un conteneur absent ou désactivé est ignoré, jamais créé |
| Mettre à jour des conteneurs gérés | Télécharge la dernière image et recrée le conteneur si elle a changé (brève coupure) |
| Vérifier les mises à jour des conteneurs | Signale, dans le centre de notifications, les conteneurs dont une version plus récente existe, sans rien modifier |
| Synchroniser les certificats | Synchronise les certificats avec d'autres NGX Ops : un nœud obtient le certificat Let's Encrypt, les autres l'installent. Un `nginx -t` précède chaque rechargement, avec retour arrière en cas d'échec |

!!! tip "Cohérence du résumé"
    Pour le résumé périodique, la planification décide **quand** il se déclenche et la période couverte **quelle fenêtre** il résume. Hebdomadaire : lundi à 7 h avec 168 heures. Quotidien : tous les jours à 7 h avec 24 heures. Sinon une partie de la période manque ou est répétée.

## Gérer les tâches

La liste affiche pour chaque tâche la prochaine exécution et le dernier résultat. Vous pouvez l'activer ou la désactiver, **l'exécuter maintenant**, la modifier, la supprimer et consulter son historique (50 dernières exécutions).

Les boutons **Exporter** et **Importer** échangent un fichier `scheduled-tasks.json`, avec fusion ou remplacement.

## Droits

La lecture demande le droit de consulter les configurations. La création, la modification, l'exécution et l'import demandent le droit de contrôle de Nginx. Voir [Utilisateurs et rôles](../dashboard/users.md).

!!! info "Ancien fichier scheduler.yml"
    Les tâches ne sont plus dans un fichier YAML. S'il existe un `scheduler.yml` d'une ancienne installation, il est importé une seule fois au premier démarrage, puis ignoré.
