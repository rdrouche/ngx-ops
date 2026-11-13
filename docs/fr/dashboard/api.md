# API REST et webhooks

## L'API REST

Tout ce que fait l'interface passe par l'API REST du dashboard, en JSON. La page **REST API** (réservée aux administrateurs) en est la documentation interactive : routes classées par catégorie, avec un bouton pour les essayer en direct.

### S'authentifier

| Méthode | Usage |
|---|---|
| Session (cookie) | Celle de l'interface, avec les droits du rôle de l'utilisateur |
| Jeton Bearer | `Authorization: Bearer <API_TOKEN>`, pour les scripts et l'automatisation |

```bash
curl -s -H "Authorization: Bearer $API_TOKEN" https://dashboard.example.com/api/health
```

- Le jeton `API_TOKEN` reste **désactivé** tant qu'il est vide, qu'il commence par `changeme` ou qu'il fait moins de 16 caractères. Générez-le avec `openssl rand -hex 32`, ou depuis la page **Système**.
- Un jeton valide s'authentifie avec les droits de **`admin`**. Il n'est pas soumis au MFA.
- Les routes d'écriture et d'administration sont donc à réserver à des scripts de confiance, sur un réseau maîtrisé.
- `CORS_ORIGIN` reste vide tant qu'aucun front externe n'appelle l'API : seule la même origine est alors acceptée.

Pour automatiser un déploiement depuis une CI, préférez un **jeton de déploiement** limité aux routes Git et sauvegardes : voir [GitOps](../features/git.md).

## Les webhooks

Les webhooks envoient une requête HTTP à une adresse de votre choix chaque fois qu'un événement du [journal](notifications.md#le-journal-des-evenements) est enregistré. La page **Webhooks** et les routes `/api/webhooks` sont réservées aux administrateurs.

### Créer un webhook

```bash
curl -s -X POST https://dashboard.example.com/api/webhooks \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example.com/ngx","events":["backup.manual","certbot_issue"],"description":"Alertes sauvegardes"}'
```

| Champ | Rôle |
|---|---|
| `url` | Adresse de destination, obligatoire |
| `events` | Types d'événements à envoyer. `["*"]` (valeur par défaut) envoie tout |
| `description` | Libellé libre |
| `active` | `false` suspend l'envoi sans supprimer le webhook (modification) |

Le bouton de test, ou `POST /api/webhooks/<id>/test`, envoie un événement `webhook.test`.

### Ce que reçoit le destinataire

Une requête `POST` en JSON :

```json
{
  "event": "backup.manual",
  "timestamp": "2026-11-12T15:00:00.000Z",
  "data": { }
}
```

L'en-tête `X-Nginx-Dashboard-Secret` contient le **secret** `WEBHOOK_SECRET`. Le destinataire compare cette valeur à celle qu'il connaît et rejette les requêtes qui ne la présentent pas. Ce n'est pas une signature calculée sur le contenu : utilisez HTTPS pour que le secret ne circule pas en clair.

### Les limites à connaître

- **Pas de réseaux privés.** L'adresse de destination est refusée si elle pointe vers une adresse locale ou privée (réseaux privés, boucle locale, adresse de métadonnées d'un fournisseur de cloud). Le contrôle est refait à chaque envoi, pour résister à un changement de résolution DNS. Un webhook ne peut donc pas viser un service interne.
- **Pas de nouvel essai.** Un destinataire injoignable est ignoré, avec un délai de 10 secondes, et n'empêche jamais l'action qui a déclenché l'événement.
- **Conservés en mémoire.** La liste des webhooks n'est pas enregistrée sur disque : elle est vidée au redémarrage du conteneur du dashboard. Recréez-les après un redémarrage, par l'interface ou par l'API.
- Sans `WEBHOOK_SECRET` configuré, le menu Webhooks est masqué par défaut. Voir [Menus optionnels](interface.md#menus-optionnels).
