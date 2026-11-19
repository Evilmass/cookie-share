# Cookie-share Server

Embedded TypeScript Node.js backend for Cookie-share.

Requires Node.js `22.5.0+` because the server uses the built-in `node:sqlite` module instead of a native addon.

## Development

```bash
npm install
copy .env.example .env
npm run dev
```

## Production

```bash
npm install
copy .env.example .env
npm run build
npm start
```

## Environment Variables

- `PORT`: HTTP port, default `3000`
- `HOST`: Listen address, default `0.0.0.0` (`.env.example` sets `127.0.0.1`)
- `PATH_SECRET`: Required path prefix secret. Letters, digits, `-`, `_`, `.`, `~` and `/` are safe; whitespace and `< > ; ? # \ : * { } ( ) [ ] ! +` are rejected
- `ADMIN_PASSWORD`: Required admin API password, at least 16 characters
- `TRANSPORT_SECRET`: Required transport encryption secret, at least 16 characters
- `DB_PATH`: SQLite path, default `./data/cookie_share.db`
- `TRUST_PROXY`: `true` when exactly one reverse proxy is in front, so rate limits use the client address from `X-Forwarded-For`
- `ALLOW_WEAK_SECRETS`: `true` skips the placeholder/reuse/length checks (not recommended)

Generate each of the three secrets separately:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

The server refuses to start when a secret is still a placeholder such as `change-me`, when two of the three are equal, or when `ADMIN_PASSWORD` / `TRANSPORT_SECRET` is shorter than 16 characters. Every response is encrypted with one of these secrets, so a guessable value can be brute-forced offline by anyone who captures a response.

## Deployment security

- **Always serve it over HTTPS.** The server itself speaks plain HTTP, and the admin page sends `ADMIN_PASSWORD` in a request header on every call. Run it behind a TLS-terminating reverse proxy (Caddy, nginx, Traefik, Cloudflare Tunnel) and keep the server port off the public network.
- `docker-compose.yml` publishes the port on `127.0.0.1` only. `COOKIE_SHARE_PORT` changes the host port; `COOKIE_SHARE_BIND=0.0.0.0` publishes it on all interfaces and is only appropriate on a trusted network.
- Behind a reverse proxy set `TRUST_PROXY=true`, otherwise all clients share the proxy's address and one rate-limit bucket. Do not set it when clients can reach the server directly, because the header could then be forged.
- Built-in limits per client address and minute: 600 requests and 30 failed admin passwords (then `429`, including for the correct password, until the minute ends). They are in-memory and per process.
- Requests outside `/<PATH_SECRET>/` and failed admin authentication get plain-text errors; nothing is encrypted with a secret before the caller is on a valid route.
- Device tokens, protocol v2, admin sessions and storage encryption are Worker-only; see `docs/SECURITY_UPGRADE.md`. On this backend `TRANSPORT_SECRET` is an instance-wide credential and the SQLite file holds cookies in plain text, so protect the data volume and its backups.
