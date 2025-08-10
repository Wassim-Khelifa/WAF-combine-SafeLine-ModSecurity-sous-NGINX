# Projet WAF combiné SafeLine + ModSecurity sous NGINX

Ce projet vise à déployer un système WAF robuste en combinant deux technologies complémentaires :  
- **ModSecurity** avec les règles OWASP CRS, pour le filtrage classique des attaques (XSS, injection SQL, path traversal, etc.)  
- **SafeLine**, pour une analyse comportementale avancée et une réponse en temps réel.

### Fonctionnement général

- NGINX joue le rôle de reverse proxy, interceptant tout le trafic HTTP/HTTPS.  
- Les requêtes passent ensuite par SafeLine et ModSecurity pour une analyse et un filtrage complets.

### Ce que j’ai réalisé

- Installation et configuration manuelles complètes de NGINX, ModSecurity, OWASP CRS, et SafeLine intégrée.  
- Validation du système par des tests d’attaques courantes (XSS, injection SQL, path traversal, etc.).

### Étape en cours

- Automatisation via script shell de l’installation et intégration de **SafeLine** (le reste est déjà automatisé).

---

## Organisation du dépôt

- `docs/` : captures d’écran et notes des étapes manuelles  
- `scripts/install_modsecurity.sh` : script d’installation et configuration ModSecurity + NGINX + OWASP CRS  
- `scripts/install_safeline.sh` (à venir) : automatisation de l’intégration SafeLine  
- `scripts/test_attacks.sh` : tests d’attaques automatisés pour valider la protection  

---

Pour toute question, je reste disponible.
