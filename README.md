# SecureVPN — Zero-Trust Freemium VPN Middleware

A production-grade, security-first backend + admin stack for running a **freemium VPN service** on top of a [Rebecca (Marzban-fork) panel](https://github.com/rebeccapanel) and Xray/sing-box nodes.

The design premise: **the client is hostile.** Mobile apps never talk to the VPN panel, never see node credentials, and never decide their own entitlement. A NestJS middleware is the sole authority — every minute of VPN time is granted server-side, verified end-to-end, and revocable in one click.

```
 ┌──────────────┐   HTTPS (pinned)   ┌─────────────────────┐   private net   ┌─────────────┐
 │ Flutter app   │ ─────────────────▶ │  NestJS middleware  │ ──────────────▶ │ Rebecca     │
 │ (Android/iOS) │  attested, ECDH-   │  Postgres + Redis   │  outbox worker  │ panel       │
 │  sing-box     │  encrypted configs │  sole authority     │  (never in-tx)  │ Xray nodes  │
 └──────────────┘                    └─────────┬───────────┘                 └─────────────┘
                                               │
                                     ┌─────────▼───────────┐
                                     │  Next.js admin       │
                                     │  dashboard + Telegram│
                                     │  ops bot             │
                                     └─────────────────────┘
```

## Highlights

- **Zero-trust provisioning** — clients earn VPN time by watching rewarded ads, verified via **AdMob SSV** (server-side verification with a server-issued nonce). 2 ads → 60 minutes. No client-side checks to patch out; Lucky Patcher gets nothing.
- **Device attestation** — Play Integrity (Android) / App Attest (iOS) with **key binding**: the attestation covers the device's ECDH public key, so a stolen token can't be replayed from another device.
- **Encrypted config delivery** — VPN configs are sealed per-session with X25519 + HKDF-SHA256 + AES-256-GCM to the attested device key. They are never visible in transit, in logs, or to MITM proxies.
- **Real auth** — anonymous-first onboarding, Argon2id passwords, 15-minute access JWTs, rotating refresh tokens with **family reuse detection** (token replay revokes the whole family).
- **Strict DB lock discipline** — external I/O (panel, Google) never happens inside a DB transaction. Panel convergence runs through a durable **outbox** drained by background workers, so a slow panel can never wedge the API.
- **Admin command center** — Next.js dashboard (stats, user search, ban/tier, session kick, audit feed) + Telegram ops bot behind an absolute ID whitelist.
- **Node operations** — health cards with live load/connections, **Drain** (graceful: no new users) and **Evacuate / Force-Migrate** (emergency: drain + instantly revoke every session on the node so clients fail over).
- **Non-negotiable audit trail** — every destructive admin action is logged; bans, panic revokes and node evacuations write their audit row **inside the same transaction** (if the audit write fails, the action rolls back).

## Quick start

One line on any Linux server (or anything with Docker):

```bash
curl -fsSL https://raw.githubusercontent.com/sina99778/securevpn/main/install.sh | bash
```

The installer:

1. checks Docker + Compose, clones this repo,
2. generates strong secrets (JWT, Postgres) and writes `.env` / `backend/.env` — never overwriting existing ones,
3. stages Apple's App Attest root CA + attestation placeholders under `./secrets/`,
4. builds and starts the full stack — Postgres 16, Redis 7, DB migrator, API, dashboard,
5. waits for `/api/v1/health`, then walks you through creating the first **admin account**.

When it finishes:

| Service | URL |
|---|---|
| Admin dashboard | http://localhost:3001 |
| API | http://localhost:3000/api/v1 |
| Health probe | http://localhost:3000/api/v1/health |

Unattended install (CI / cloud-init) — note the variables go on the **bash** side of the pipe, where the installer actually runs:

```bash
curl -fsSL https://raw.githubusercontent.com/sina99778/securevpn/main/install.sh | \
  PUBLIC_API_URL=https://vpn.example.com \
  PANEL_BASE_URL=https://panel.internal:8000 \
  PANEL_ADMIN_USER=ops PANEL_ADMIN_PASS=secret \
  ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='a-strong-password' \
  bash
```

> Already cloned? Just run `bash install.sh` from the repo root. Add `--no-start` to only prepare config, `--no-admin` to skip the admin bootstrap.

### Manual install

```bash
git clone https://github.com/sina99778/securevpn.git && cd securevpn
cp .env.example .env                       # set POSTGRES_PASSWORD, NEXT_PUBLIC_API_URL
cp backend/.env.example backend/.env       # set JWT_SECRET, PANEL_*, attestation config
mkdir -p secrets && cp certs/Apple_App_Attestation_Root_CA.pem secrets/
docker compose up -d --build
bash scripts/create-admin.sh               # first admin account
```

## Operating the service

Sign in at the dashboard with the admin account. Highlights:

- **Dashboard** — live stats (active sessions, ads today, users, premium) and the **Panic Button**: one typed-phrase-confirmed click revokes *every* free-tier session (mass incident response).
- **Users** — search, see live sessions, grant/revoke premium, **ban** (instantly revokes all the user's sessions, atomically audited).
- **Nodes** — per-node health, load and live connection count, plus:
  - **Drain** — node leaves rotation; existing sessions run out naturally. For planned maintenance.
  - **Evacuate** — *emergency*: drain **and** instantly revoke every session on the node; clients reconnect to healthy nodes. For dead hosts / blocked IPs. Irreversible and audited (a confirmation dialog spells this out).
- **Audit** — color-coded feed of every admin action (who, from which IP, what, outcome), paginated.

The Telegram ops bot (optional — set `TELEGRAM_BOT_TOKEN` + `ADMIN_TELEGRAM_IDS`) mirrors the essentials: `/stats`, `/find <email>`, `/kick_<session-id>`.

### Key API surface

| Route | Purpose |
|---|---|
| `POST /auth/anon` → `register` / `login` / `refresh` / `logout` | identity funnel (rotating refresh families) |
| `POST /device/attest/challenge` + `/device/attest/verify` | Play Integrity / App Attest with ECDH key binding |
| `POST /connect` | entitlement check → session grant (free tier gets a grant + ad nonce, no config yet) |
| `POST /ads/request-ad-token` + AdMob SSV callback + `verify-ad-reward` | server-verified rewarded ads → encrypted VPN config |
| `POST /admin/auth/login` | device-less admin login |
| `GET /admin/stats·users·audit·nodes/health` | command center reads |
| `POST /admin/users/:id/mutate`, `sessions/:id/kick`, `panic/revoke-free-sessions` | destructive ops (audited) |
| `PATCH /admin/nodes/:id/status`, `POST /admin/nodes/:id/migrate` | drain / force-migrate |

## Configuration

Everything is environment-driven. Compose-level settings live in `.env` (see [.env.example](.env.example)); API settings in `backend/.env` (see [backend/.env.example](backend/.env.example)). The ones you must get right for production:

| Variable | What it is |
|---|---|
| `JWT_SECRET` | HS256 signing secret (installer generates 96 hex chars) |
| `PANEL_BASE_URL`, `PANEL_ADMIN_USER/PASS` | your Rebecca panel — keep it on a **private network**; only the middleware talks to it |
| `NEXT_PUBLIC_API_URL` | the API URL as seen from the **admin's browser** (build-time, rebuild `web` after changing) |
| `ANDROID_PACKAGE_NAME`, `GOOGLE_APPLICATION_CREDENTIALS` | your app's package + Play Integrity service-account JSON (`secrets/play-integrity-sa.json`) |
| `APPLE_TEAM_ID`, `APPLE_BUNDLE_ID` | your iOS app identity for App Attest |
| `ADMIN_TELEGRAM_IDS` | absolute whitelist for the ops bot — empty disables everyone |

## Repository layout

```
backend/      NestJS middleware — auth, attestation, connect, ads/SSV, admin, workers
web/          Next.js admin dashboard (Tailwind)
flutter_app/  Flutter client skeleton — Riverpod, platform channels to sing-box
db/           schema.sql + idempotent migrations (run by the compose migrator)
docs/         architecture & phase design docs (start with docs/PHASE1_ARCHITECTURE.md)
certs/        vendored PUBLIC certs (Apple App Attest root CA)
install.sh    one-line installer
scripts/      create-admin.sh and friends
```

## Production hardening checklist

- [ ] Put a TLS reverse proxy (Caddy/nginx) in front; expose **only** 443. Set `TRUST_PROXY_HOPS` accordingly and bind ports 3000/3001 to localhost or an internal network.
- [ ] Point `PANEL_BASE_URL` at the real Rebecca panel over a private network/WireGuard — the panel must never be internet-reachable.
- [ ] Replace attestation placeholders: real Play Integrity service account, your package/bundle IDs, signing-cert digests (`ANDROID_CERT_SHA256_B64`).
- [ ] Build the mobile apps with certificate pinning and the hardening flags from `docs/phase4-hardening-build.md` (R8/obfuscation, anti-Frida fail-closed).
- [ ] Back up the `pgdata` volume; the audit log lives there.
- [ ] Alert on `audit write failed` log lines and outbox retry exhaustion.

## Updating

```bash
cd securevpn
git pull
docker compose up -d --build      # migrator re-runs idempotently before the api starts
```

## Documentation

Deep dives live in [docs/](docs/): architecture ([PHASE1_ARCHITECTURE.md](docs/PHASE1_ARCHITECTURE.md)), the ads/reward trust model, the panel contract, Flutter architecture, hardening/build flags, and [deployment notes](docs/deployment.md).

---

**Note:** this stack manages VPN infrastructure you own/operate. Compliance with local law and app-store policy (rewarded-ad and VPN rules included) is on you.
