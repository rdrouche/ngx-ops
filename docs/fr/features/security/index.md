# Sécurité

NGX Ops ajoute à Nginx plusieurs couches de protection. Elles sont **indépendantes** et s'activent une par une : on peut n'utiliser que les listes de blocage, ou tout combiner.

| Couche | Rôle | Agit |
|---|---|---|
| [Analyse des journaux](../logs/analysis.md) | Détecte force brute, scans, floods, scraping et anomalies de trafic, avec des règles intégrées et les vôtres | Après la requête |
| [WAF émulé](waf-emule.md) | Rejoue les journaux dans un moteur de règles (Coraza et OWASP CRS) pour repérer les attaques applicatives | Après la requête |
| [Blocklists IP](blocklist-ips.md) | Applique dans Nginx des listes d'IP externes, ou produites par l'analyse et le WAF émulé | Avant la requête, pour les IP listées |
| [Challenge HTTP](challenge-http.md) | Demande au visiteur une preuve de travail dans son navigateur | Avant la requête |
| [CrowdSec](crowdsec.md) | Affiche les décisions du moteur CrowdSec et permet de bannir ou débannir | Selon l'installation CrowdSec |
| [Intelligence](intelligence.md) | Partage les alertes avec une plateforme centrale et récupère des listes de réputation | Alimente les listes |
| [WAF Nginx](../../appendices/nginx-waf.md) | ModSecurity ou Coraza intégrés à Nginx, en ligne | Pendant la requête |

## Comment les couches s'enchaînent

```text
journaux Nginx ─▶ Analyseur ──alertes──▶ liste « analyzer » ─┐
              └─▶ WAF émulé ─scores───▶ listes waf-challenge, waf-block ─┤
                                                             ├─▶ Blocklists IP ─▶ Nginx : refus 403, abandon 444, ou challenge
listes externes, listes Intelligence ────────────────────────┘
```

1. L'analyse et le WAF émulé **lisent les journaux** et détectent un comportement.
2. Selon la remédiation choisie, l'IP est ajoutée à une liste.
3. **Blocklists IP** publie les listes dans une configuration Nginx. L'action est un refus `403`, un abandon de connexion `444`, ou un [challenge](challenge-http.md).

L'analyse et le WAF émulé travaillent **après coup** : ils ne bloquent pas la requête qu'ils détectent, ils protègent les requêtes suivantes de la même adresse. Pour bloquer pendant la requête, il faut un WAF dans Nginx, voir l'annexe [Utiliser une version WAF de Nginx](../../appendices/nginx-waf.md).

## Protéger un vhost sélectivement

Des commentaires dans le bloc `server` d'un vhost permettent de couper ou d'ajuster ces protections vhost par vhost : analyse désactivée, règles ignorées, remédiation désactivée, diagnostic coupé. Voir [Analyse des journaux](../logs/analysis.md#personnaliser-lapplication-des-regles-par-hote-virtuel).

## Audit des vhosts

La page **Diagnostic** audite la configuration de chaque vhost (en-têtes de sécurité, configuration statique, analyse en direct des en-têtes de réponse). Voir [Diagnostic](../diagnostics.md).
