# Authentification en deux étapes (MFA)

Chaque utilisateur peut activer un second facteur depuis le bouclier de l'en-tête, **Sécurité du compte**. Sans MFA configuré, la connexion reste inchangée.

## Les facteurs disponibles

| Facteur | Détail |
|---|---|
| **Application d'authentification** | Code à usage unique (TOTP) : on scanne un QR code avec l'application |
| **Clé de sécurité** | WebAuthn : YubiKey, passkey |
| **Codes de secours** | 10 codes à usage unique, à conserver hors de l'appareil habituel |

On peut activer l'application et la clé de sécurité ensemble.

## Perte du téléphone ou de la clé

- Utiliser un **code de secours** pour se connecter, puis reconfigurer le second facteur.
- Ou demander à un administrateur de **réinitialiser le compte** (route `POST /api/mfa/admin/reset`). L'événement est inscrit dans le journal.

## Les clés de sécurité et HTTPS

WebAuthn exige **HTTPS**. Les clés enregistrées sont liées au domaine : si vous changez de nom de domaine, il faudra les enregistrer à nouveau.

Derrière un reverse proxy qui réécrit l'en-tête `Host`, indiquez le domaine à la main :

| Variable | Exemple | Rôle |
|---|---|---|
| `MFA_RP_ID` | `ops.example.com` | Domaine WebAuthn, sans port |
| `MFA_ORIGIN` | `https://ops.example.com` | Origines autorisées, séparées par des virgules |

Vides, ces valeurs sont déduites de la requête.

## Stockage et limites

- Les données sont dans `config/mfa.json`, avec des droits restreints au propriétaire. Ce fichier fait partie des données à sauvegarder.
- Le MFA ne concerne que la connexion à l'interface. Les **jetons d'API** Bearer n'y sont pas soumis.
- Les événements de connexion MFA (`auth.mfa.ok`, `auth.mfa.failed`, `auth.mfa.enabled`, `auth.mfa.disabled`, `auth.mfa.reset`) apparaissent dans le journal des événements.
