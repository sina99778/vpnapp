# Admin Dashboard (Next.js + Tailwind)

Next.js App Router frontend for the admin API. Talks to the middleware's
`/api/v1/admin/*` endpoints (behind `JwtAuthGuard` + `AdminGuard`).

## Layout

```
web/
  package.json
  next.config.mjs
  tailwind.config.ts
  postcss.config.mjs
  tsconfig.json
  .env.local                  # NEXT_PUBLIC_API_URL=https://api.example-vpn.com/api/v1
  app/
    layout.tsx                # root layout + Tailwind globals
    globals.css
    login/page.tsx            # email/password → POST /auth/login, store token
    dashboard/page.tsx        # stats grid + Panic Button (this file provided)
    users/page.tsx            # paginated user table (uses adminApi.listUsers)
  lib/
    api.ts                    # Axios instance, injects admin JWT, handles 401
    types.ts                  # shared response types (mirror the backend DTOs)
  components/
    StatCard.tsx, PanicButton.tsx, ...
```

## Run

```bash
cd web
cp .env.local.example .env.local      # set NEXT_PUBLIC_API_URL
npm install
npm run dev                            # http://localhost:3001
```

## Auth model

The admin signs in via `/auth/login` (a user whose `role='admin'`); the access
JWT is stored client-side and attached as `Authorization: Bearer` by the Axios
client. Refresh rotation uses `/auth/refresh`.

> **Security note:** this reference stores the token in `localStorage` (simple,
> but readable by any XSS). For production, prefer an **httpOnly, Secure,
> SameSite=Strict cookie** set by a small BFF route + CSRF protection, so the
> token is never reachable from JS. The Axios client below is written so swapping
> the token source is a one-function change.
