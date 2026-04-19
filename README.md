# LA DIOSA — squelette du site

Code source du site **[ladiosa.fr](https://ladiosa.fr)** : blog culinaire et catalogue de recettes personnel.

> Ce dépôt n'est **pas un produit générique** : il contient uniquement la structure technique (serveur + front) du site. Aucune recette, aucun article, aucun média, aucun secret n'est versionné ici — tout le contenu vit sur le serveur de production.

## Stack

- **Backend** : Node.js 20 + Express — API REST, RSS, sitemap, OG-share, modération de commentaires.
- **Frontend** : une page `index.html` vanilla JS (SPA hash-based), rendu Markdown sécurisé via DOMPurify, PWA installable.
- **Persistance** : fichiers JSON + dossier `medias/` sur un volume bind-mount (pas de base de données).
- **Déploiement** : image Docker publiée sur `ghcr.io`, tournée sur un Synology derrière le reverse-proxy DSM (HTTPS Let's Encrypt).

## Arborescence (à la racine)

```
├─ server.js            serveur Express durci
├─ index.html           SPA (front complet, chargé tel quel)
├─ assets/icons/        logos et favicons
├─ public/              fichiers statiques servis (manifest, sw.js, robots, well-known, offline)
├─ Dockerfile           image non-root + tini + healthcheck
├─ docker-compose.yml   profil Synology
└─ .github/workflows/   build & push ghcr.io
```

## Mise en ligne (Synology)

1. Créer l'arborescence :
   ```
   /volume1/docker/ladiosa/
     ├─ docker-compose.yml     ← copier depuis ce dépôt
     ├─ .env                   ← copier .env.example puis remplir
     └─ data/                  ← vide au premier démarrage
   ```
2. Configurer `.env` (voir `.env.example`) — au minimum :
   - `PUBLIC_ORIGIN=https://ladiosa.fr`
   - `ALLOWED_ORIGINS=https://ladiosa.fr`
   - `ADMIN_PASSWORD=<mot de passe fort 12+ caractères>` (peut être retiré après le premier lancement)
3. `chmod 700 data && chmod 600 .env`
4. Depuis `/volume1/docker/ladiosa/` :
   ```bash
   docker compose pull
   docker compose up -d
   docker compose logs -f
   ```
5. Dans DSM → **Portail applicatif / Reverse Proxy** : mapper `https://ladiosa.fr` (443) vers `127.0.0.1:1106`. Activer HSTS + HTTP/2 + Let's Encrypt.

Le site est accessible sur `https://ladiosa.fr`. L'admin se trouve sur `https://ladiosa.fr/#/tulum`.

## Mise à jour

```bash
cd /volume1/docker/ladiosa
docker compose pull
docker compose up -d
```

Chaque `git push` sur `main` déclenche le build + push de l'image `ghcr.io/<owner>/ladiosa:latest` via GitHub Actions.

## Sécurité

Voir [SECURITY.md](SECURITY.md) pour le modèle de menace, les mitigations et le contact pour signaler une faille.

## Licence

Code source personnel — tous droits réservés (contenu du site inclus).
