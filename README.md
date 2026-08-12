<img width="500" height="500" alt="image-removebg-preview (17)" src="https://github.com/user-attachments/assets/19b6ff5a-965f-43a4-8ca9-03ab8e60cc6e" />

# La Diosa

![Node](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white) ![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white) [![Release](https://img.shields.io/github/v/release/infinition/ladiosa?style=flat)](https://github.com/infinition/ladiosa/releases)

Source code for [ladiosa.fr](https://ladiosa.fr), a personal culinary blog and recipe catalog.

This repository contains only the technical structure (server + frontend). No recipes, articles, media, or secrets are versioned here. All content lives on the production server.

---

## Stack

- **Backend**: Node.js 20 + Express (REST API, RSS, sitemap, OG share, comment moderation)
- **Frontend**: Vanilla JS SPA (`index.html`, hash-based routing), secure Markdown rendering via DOMPurify, installable as PWA
- **Persistence**: JSON files + `medias/` folder on a bind-mount volume (no database)
- **Deployment**: Docker image published to `ghcr.io`, running on a Synology NAS behind DSM reverse proxy with Let's Encrypt HTTPS

---

## File layout

```
server.js            Hardened Express server
index.html           Full SPA frontend
assets/icons/        Logos and favicons
public/              Static files (manifest, sw.js, robots, well-known, offline)
Dockerfile           Non-root image with tini and healthcheck
docker-compose.yml   Synology profile
.github/workflows/   Build and push to ghcr.io
```

---

## Deploying on Synology

1. Create the folder structure:

   ```
   /volume1/docker/ladiosa/
     docker-compose.yml   (copy from this repo)
     .env                 (copy .env.example and fill in)
     data/                (empty on first run)
   ```

2. Set at minimum in `.env`:
   - `PUBLIC_ORIGIN=https://ladiosa.fr`
   - `ALLOWED_ORIGINS=https://ladiosa.fr`
   - `ADMIN_PASSWORD=<strong 12+ char password>` (can be removed after first launch)

3. Set permissions: `chmod 700 data && chmod 600 .env`

4. Start:

   ```bash
   docker compose pull
   docker compose up -d
   docker compose logs -f
   ```

5. In DSM: Application Portal / Reverse Proxy, map `https://ladiosa.fr` (443) to `127.0.0.1:1106`. Enable HSTS + HTTP/2 + Let's Encrypt.

Admin panel: `https://ladiosa.fr/#/tulum`

---

## Updating

```bash
cd /volume1/docker/ladiosa
docker compose pull
docker compose up -d
```

Each push to `main` triggers a build and push of `ghcr.io/<owner>/ladiosa:latest` via GitHub Actions.

---

## Security

See [SECURITY.md](SECURITY.md) for the threat model, mitigations, and vulnerability reporting contact.

---

## License

Personal source code. All rights reserved. Site content included.
