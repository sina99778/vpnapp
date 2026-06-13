# Phase 1 — Middleware Backend & Rebecca (Rebeka) Panel Integration

> Stack: NestJS (TypeScript) · PostgreSQL 16 · Redis · Rebecca panel (Marzban fork)
> with Rebecca-node agents running Xray on each VPN node.
>
> Detailed design notes (panel API contract, schema rationale, state machines):
> [phase1-architecture-notes.md](phase1-architecture-notes.md)

## 0. Trust model (one paragraph that governs everything)

The Flutter app is **untrusted display hardware**. It never learns a node IP,
panel URL, or credential except inside a server-built, encrypted, short-lived
connection payload — and even that payload only contains credentials that the
backend can kill remotely at any second. "Premium" exists only as a row in
PostgreSQL and as inbound assignments on the Xray nodes. A fully
reverse-engineered client gains nothing durable: tier enforcement happens at
the Xray inbound level (a free session's UUID simply does not exist on premium
inbounds), and every credential dies minutes after its heartbeats stop.

## 1. Topology & trust boundaries

```
┌─────────────┐  TLS + cert pinning   ┌──────────────────────┐
│ Flutter app │ ────────────────────► │  Middleware API      │
│ (untrusted) │  JWT + attestation    │  (NestJS)            │
└─────────────┘                       │   ├─ PostgreSQL      │
      │                               │   ├─ Redis           │
      │ Xray/sing-box data plane      │   └─ Workers:        │
      │ (VLESS/Trojan to node IPs     │      node-sync,      │
      │  revealed only in payloads)   │      reaper,         │
      ▼                               │      outbox-drainer  │
┌─────────────┐                       └─────────┬────────────┘
│  VPN nodes  │ ◄── Rebecca-node TLS ──┐        │ private network /
│ (Xray data  │                        │        │ mTLS + IP allowlist
│  plane:443) │               ┌────────┴─────┐  │
└─────────────┘               │ Rebecca panel│ ◄┘  admin API (JWT,
                              │ (FastAPI)    │     non-sudo admin)
                              └──────────────┘
External webhooks → Middleware: Google RTDN (Pub/Sub push, OIDC-verified),
Apple ASSN V2 (JWS, x5c-verified), Rebecca webhooks (x-webhook-secret + IP allowlist).
```

Network rules:
- Rebecca panel and its admin API are **never** internet-reachable. They live
  on a private network (VPC / WireGuard mesh) with the middleware as the only
  client. `DOCS=False` in production. Subscription URL prefix points at an
  internal hostname; the panel's subscription HTTP endpoints are not public.
- VPN nodes expose only Xray data ports publicly. The Rebecca-node control
  port is firewalled to the panel's IP.
- The middleware authenticates to Rebecca with a **dedicated non-sudo admin**
  (Rebecca multi-admin). That admin owns only middleware-created users and
  cannot touch nodes, inbounds, or other admins' users — bounding the blast
  radius if the middleware credential ever leaks. Sudo credentials stay in a
  secrets manager and are used only by ops tooling.

## 2. Identity, attestation, and tokens

Three token types, distinct lifetimes, distinct purposes:

| Token | Issued by | Lifetime | Carried in | Purpose |
|---|---|---|---|---|
| Access JWT | `/auth/*` | 15 min | `Authorization: Bearer` | identity (user_id, device_id) — **never tier** |
| Refresh token (opaque) | `/auth/*` | 30 d, rotating | body of `/auth/refresh` | session continuity; hash stored, reuse = family revoked |
| Device-integrity token (JWT) | `/attest/*` | 30–60 min | `X-Device-Token` | proof this *binary on this device* passed Play Integrity / App Attest recently |

Sensitive endpoints (`POST /connections`, IAP linking) require access JWT
**and** a valid device-integrity token. Catalog reads require only the access JWT.

Attestation flows (server-verified, challenge-bound, single-use):
- **Android:** client requests a challenge → builds Play Integrity *standard
  request* with `requestHash = SHA256(challenge ‖ canonical request body)` →
  server calls `playintegrity.googleapis.com/v1/…:decodeIntegrityToken`,
  checks `requestHash` match, package name, cert digest, `timestampMillis`
  freshness, `appRecognitionVerdict == PLAY_RECOGNIZED`,
  `deviceRecognitionVerdict ⊇ MEETS_DEVICE_INTEGRITY` (free) /
  `MEETS_STRONG_INTEGRITY` preferred (premium-grade actions), licensing verdict.
- **iOS:** one-time `attestKey` validation at device registration (x5c chain →
  Apple App Attest root, nonce check, keyId == SHA256(pubkey), counter == 0,
  prod aaguid); store pubkey + receipt + counter. Per-sensitive-request
  `generateAssertion` verified against stored key with strictly-increasing
  counter. Where App Attest is unsupported (per Apple gu