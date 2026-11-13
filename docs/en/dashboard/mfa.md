# Two-step authentication (MFA)

Each user can enable a second factor from the shield in the header, **Account security**. Without MFA configured, login is unchanged.

## Available factors

| Factor | Detail |
|---|---|
| **Authenticator app** | One-time code (TOTP): scan a QR code with the app |
| **Security key** | WebAuthn: YubiKey, passkey |
| **Recovery codes** | 10 one-time codes, to keep away from your usual device |

The app and the security key can be enabled together.

## Lost phone or key

- Use a **recovery code** to sign in, then set up the second factor again.
- Or ask an administrator to **reset the account** (route `POST /api/mfa/admin/reset`). The event is written to the log.

## Security keys and HTTPS

WebAuthn requires **HTTPS**. Registered keys are bound to the domain: if you change the domain name, you will have to register them again.

Behind a reverse proxy that rewrites the `Host` header, set the domain by hand:

| Variable | Example | Role |
|---|---|---|
| `MFA_RP_ID` | `ops.example.com` | WebAuthn domain, without port |
| `MFA_ORIGIN` | `https://ops.example.com` | Allowed origins, comma-separated |

When empty, these values are derived from the request.

## Storage and limits

- Data is in `config/mfa.json`, with permissions restricted to the owner. This file is part of the data to back up.
- MFA only covers login to the interface. Bearer **API tokens** are not subject to it.
- MFA login events (`auth.mfa.ok`, `auth.mfa.failed`, `auth.mfa.enabled`, `auth.mfa.disabled`, `auth.mfa.reset`) appear in the event log.
