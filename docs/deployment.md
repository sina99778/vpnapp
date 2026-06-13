# Deployment

## Stack

`docker-compose.yml` brings up four services:

| Service | Role |
|---|---|
| `postgres` | DB, persistent volume `pgdata`, `pg_isready` health check |
| `redis` | Throttler counter store (ephemeral, LRU-capped) |
| `migrator` | Init container: runs `db/migrate.sh` (schema + ordered migrations), then exits 0 |
| `api` | The NestJS middleware (multi-stage image, non-root) |

`api` waits for `postgres`/`redis` **healthy** and `migrator` **completed** before booting (`depends_on` conditions), so it never starts against an un-migrated DB.

## First run

```bash
cp backend/.env.example backend/.env      # fill JWT secret, panel creds, attestation cfg
mkdir -p secrets                          # place the attestation secret files here:
#   secrets/play-integrity-sa.json        (GOOGLE_APPLICATION_CREDENTIALS)
#   secrets/Apple_App_Attestation_Root_CA.pem  (APPLE_APPATTEST_ROOT_CA_PEM)
# point those two env vars at /secrets/... (the api mounts ./secrets:/secrets:ro)

docker compose up -d --build
docker compose logs -f api
curl localhost:3000/api/v1/health         # {"status":"ok","db":"up"}
```

The migrator is idempotent (a `schema_migrations` table tracks applied files), so `docker compose up` is safe to re-run; new migration files are picked up in lexical order.

## Native deps (argon2)

The `builder`/`proddeps` stages install `python3 make g++` so `argon2` builds from
source if no prebuilt binary is available; the compiled `.node` is produced on the
**same `node:20-bookworm-slim` glibc base** as the runtime stage, so it's ABI-
compatible. The runtime image carries only production `node_modules` + `dist` and
runs as the unprivileged `node` user under `tini` (clean SIGTERM → graceful worker
shutdown).

## Behind a reverse proxy / WAF

Terminate TLS at the proxy (Nginx/Traefik/WAF); the `api` speaks plain HTTP on
`:3000` on the internal network only.

**Real client IP (so the throttler limits the right address):** the app calls
`set('trust proxy', N)` where `N = TRUST_PROXY_HOPS`. Set it to the **exact number
of trusted proxy hops** in front of the api:

- Nginx only → `TRUST_PROXY_HOPS=1`
- WAF → LB → Nginx → `TRUST_PROXY_HOPS=3`

> ⚠️ Never set it higher than your real hop count (and never `true`). Express
> reads the *N-th-from-last* `X-Forwarded-For` entry; over-trusting lets a client
> inject a fake `X-Forwarded-For` and evade the per-IP limits on `/auth/anon`.

The proxy MUST forward `X-Forwarded-For` (Nginx: `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;`).

**AdMob SSV callback** (`GET /api/v1/ads/admob/ssv`): the signature is verified
over the **raw query string**, so the proxy must NOT rewrite or re-encode the URI.
Plain `proxy_pass` preserves it; avoid `rewrite`/normalization on that path.

Example Nginx location:
```nginx
location /api/v1/ {
    proxy_pass http://api_upstream;          # no trailing slash → URI preserved
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Horizontal scaling

Scale the api freely (`docker compose up -d --scale api=N` behind the proxy):

- **Rate limits stay accurate** — the throttler shares counters in Redis
  (`REDIS_URL` set), so the `/auth/anon` budget is global, not per-pod.
- **Workers are multi-instance-safe** — the reaper and outbox drainer claim rows
  with `FOR UPDATE SKIP LOCKED`, so running them in every pod causes no double
  work; leases reclaim a crashed pod's in-flight rows.

## Hardening checklist

- [ ] Don't expose `postgres`/`redis` ports publicly (drop the `api` port mapping
      too once it's behind the proxy; route only via the proxy).
- [ ] Secrets via your orchestrator's secret store (not committed `.env`); the
      `JWT_SECRET`/`JWT_PRIVATE_KEY`, panel creds, and SA JSON are sensitive.
- [ ] Strong `POSTGRES_PASSWORD`; least-privilege DB role for the api if possible.
- [ ] Pin image digests for reproducible builds.
- [ ] Ship logs to a central sink; alert on `reuse_detected`, `attestation
      rejected`, and outbox `DEAD` ops.
```
