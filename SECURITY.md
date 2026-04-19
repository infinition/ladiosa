# Politique de sécurité — LA DIOSA

## Signaler une vulnérabilité

Merci de ne **pas** ouvrir d'issue publique. Écrivez à `security@ladiosa.fr`
(ou via le fichier [/.well-known/security.txt](public/.well-known/security.txt)).
Nous répondons sous 7 jours et corrigeons les failles critiques sous 30 jours.

## Surface exposée

- **Public** : pages HTML, `/rss/*`, `/sitemap.xml`, `/api/recipes`, `/api/articles`, `/api/articles/:slug`, `/api/articles/:id/comments` (POST rate-limité), `/api/config/public`, `/healthz`.
- **Authentifié (cookies httpOnly + CSRF)** : toutes les routes `/api/admin/*`, `/api/upload`, `/api/import-recipe`, `/api/config` (écriture), `/api/auth/password`, `/api/auth/logout`, `/api/auth/logout-all`.
- **Setup** : `/api/auth/setup` n'est accessible que tant qu'aucun mot de passe n'existe ; peut en plus être verrouillé par `SETUP_TOKEN` en env (comparé en constant-time via SHA-256).

## Authentification — modèle SOTA

### Cookies émis au login

| Cookie | Contenu | Flags | Durée | Rôle |
|---|---|---|---|---|
| `ladiosa_auth` | JWT HS256 (access token) | `HttpOnly`, `Secure`, `SameSite=Lax` | 30 min | Authentification des requêtes API |
| `ladiosa_refresh` | Token opaque 32 bytes | `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/auth` | 7 j | Rotation du token d'accès |
| `ladiosa_csrf` | Token aléatoire 32 bytes | `Secure`, `SameSite=Lax` (lisible JS) | 30 min | Double-submit CSRF |
| `ladiosa_logged_in` | `1` | `Secure`, `SameSite=Lax` (lisible JS) | 30 min | Flag UI pour l'état connecté |

- **Pas de JWT en `localStorage`.** Le token d'accès vit uniquement dans un cookie `HttpOnly`, inaccessible à tout JS (même via XSS).
- **CSRF double-submit** : pour toute méthode mutante (`POST`/`PUT`/`PATCH`/`DELETE`) via cookie, le serveur exige un header `X-CSRF-Token` qui doit **strictement correspondre** au cookie `ladiosa_csrf` (comparaison `timingSafeEqual`). Un attaquant ne peut pas forger le header depuis une autre origine.
- **Refresh token rotation** : chaque `/api/auth/refresh` invalide le précédent refresh token et en émet un nouveau (single-use, stocké server-side comme hash SHA-256). Détecte la réutilisation.
- **Bearer supporté** pour usage programmatique (CLI, scripts) : header `Authorization: Bearer <jwt>`. Exempt de CSRF (pas de cookie ambient).

### Protection brute-force

- `express-rate-limit` : **10 tentatives / 15 min** sur `/api/auth/*` (IP).
- **Progressive backoff** côté login : après 5 échecs dans une fenêtre glissante de 30 min, verrouillage exponentiel `30 s → 1 min → 2 min → … → 15 min` (cap).
  - Clé de verrou : `ip | sha1(userAgent)[0:8]` — isolation par navigateur.
  - Retourne `429` avec `Retry-After` tant que le verrou est actif.
- **Timing constant-time sur login** : `DUMMY_HASH` bcrypt généré au démarrage (cost 12). Les logins avec utilisateur inexistant exécutent un `bcrypt.compare` factice → pas de leak par timing sur l'existence du compte admin.

### Audit log & sessions

- Ring buffer **500 événements** en mémoire (`login.ok`, `login.fail`, `login.locked`, `refresh.ok`, `refresh.replay`, `logout`, `password.change`, `setup`).
  - Chaque événement logge : timestamp, action, ip, UA tronqué, role.
  - Lisible via `GET /api/admin/audit-log` (authentifié).
- `GET /api/admin/sessions` : liste les refresh tokens actifs (role, UA, expiration). Permet à l'admin de voir ses sessions ouvertes.
- `POST /api/auth/logout-all` : révoque **tous** les refresh tokens → déconnecte tous les navigateurs.

## Autres mesures en place

| Catégorie | Mitigation |
|---|---|
| Headers | `helmet` — CSP stricte, `X-Frame-Options: DENY`, HSTS (1 an, includeSubDomains, preload), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` minimal |
| Password hash | `bcrypt` cost 12, minimum 12 caractères au setup/changement |
| JWT | HS256, secret 512 bits généré automatiquement au 1ᵉʳ démarrage dans `config.json` (permissions 0600) |
| CORS | Liste blanche via `ALLOWED_ORIGINS`, `credentials: true`, `allowedHeaders` explicite (`Content-Type`, `Authorization`, `X-CSRF-Token`, `X-Setup-Token`) |
| Uploads | Extension + mimetype whitelist (SVG **bloqué**), nom généré (`crypto.randomBytes`), taille 20 MB max, 1 fichier/requête, 30 req/min |
| Path traversal | `path.resolve` + `isPathWithin(MEDIA_DIR)` sur toutes les I/O (upload, delete, rename) |
| XSS | DOMPurify côté client sur le rendu Markdown (`window.renderMarkdown`), `sanitize-html` côté serveur sur les entrées, `escapeHtml` et `escapeXml` sur RSS/OG/JSON-LD |
| SSRF | `/api/import-recipe` : DNS lookup préalable + blocage des plages privées IPv4/IPv6 (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7, fe80::/10), redirections ≤ 3, timeout 12 s, content-length 8 MB |
| Commentaires | Modération obligatoire, rate-limit IP + honeypot, taille 2000 chars max, IP hashée (pas de PII en clair) |
| Secrets | `config.json` (hash + JWT secret) stocké hors de l'image, dans le volume bind-mount `/volume1/docker/ladiosa/data/`, permissions 0600, jamais exposé par `express.static` |
| Static | `express.static` limité à `/assets`, `/public`, `/recipes/medias` — le code source et les JSON de données ne sont **jamais** servis |
| Container | Image non-root (`uid 1001`), `read_only`, `cap_drop: ALL`, `no-new-privileges`, `tini` PID 1, healthcheck HTTP, tmpfs `/tmp` |

## Modèle de menace — résidus connus

- **XSS résiduel** : même si le token est en cookie `HttpOnly`, un XSS peut toujours déclencher des actions authentifiées depuis le navigateur de la victime (le cookie est envoyé automatiquement, et JS peut lire le cookie CSRF pour forger la requête). **La CSP stricte + DOMPurify + `sanitize-html` restent la première ligne**. Le cookie `HttpOnly` empêche seulement l'exfiltration du token, pas son abus in-session.
- **`/tulum` = sécurité par obscurité** : ce n'est **pas** une mesure de sécurité, seulement un camouflage. La vraie protection est le mot de passe + rate-limit + backoff. Utilisez un mot de passe fort (≥ 16 caractères, gestionnaire).
- **Pas de 2FA** : à envisager si le site devient une cible. Un TOTP (`otplib`) serait trivial à ajouter sur le flow de login.
- **Pas de WAF applicatif** : le reverse-proxy DSM fournit une première couche. Pour aller plus loin, Cloudflare en front (plan gratuit suffit).
- **Audit log en mémoire** : perdu au redémarrage. Pour un vrai suivi forensic, brancher un transport fichier (append-only) ou syslog.
- **Refresh store en mémoire** : tous les utilisateurs sont déconnectés au redémarrage. Acceptable pour un site mono-admin ; à migrer vers Redis/SQLite si plusieurs comptes.
- **Absence de tests automatisés** : à ajouter (vitest/supertest) — au minimum les flows auth + CSRF.

## Bonnes pratiques de déploiement

1. **Toujours** servir en HTTPS (reverse proxy DSM + Let's Encrypt). Les cookies `Secure` ne fonctionnent que sur HTTPS.
2. Ne **jamais** exposer directement le port 1106 sur Internet — il ne doit écouter que sur `127.0.0.1` (déjà le cas dans `docker-compose.yml`).
3. Backups réguliers de `/volume1/docker/ladiosa/data/` (Hyper Backup Synology, chiffré).
4. Garder Docker, Node et les images à jour (Dependabot activé, workflow GH Actions reconstruit à chaque push, Trivy scan CRITICAL/HIGH).
5. Rotation du mot de passe admin : utiliser `/api/auth/password` (authentifié) — **ne modifiez pas** `config.json` à la main.
6. Si `config.json` fuit : régénérez un nouveau JWT secret (supprimez `auth.jwtSecret` du fichier, redémarrez), changez le mot de passe, puis `POST /api/auth/logout-all` pour purger tous les refresh tokens.

## Fichiers sensibles

Le dossier `data/` (ou `recipes/` en dev) contient :

- `config.json` → **hash bcrypt + JWT secret** (ne jamais commiter, `.gitignore` le protège)
- `recipes.json`, `articles.json`, `comments.json` → contenu du site
- `medias/` → fichiers uploadés

Tous ces fichiers doivent vivre uniquement sur le volume Synology, **jamais dans Git ni dans l'image Docker**.
