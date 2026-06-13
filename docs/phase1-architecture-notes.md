# Phase 1 — Detailed Design Notes (Middleware Backend & Rebecca Integration)

> These are the in-depth Phase-1 design notes. For the polished overview, start
> with [PHASE1_ARCHITECTURE.md](PHASE1_ARCHITECTURE.md).

## 0. Identification note

There is no panel literally spelled **"Rebeka"**. The "Rebeka Panel" referred to
throughout this project is the **Rebecca** panel (`github.com/rebeccapanel/Rebecca`)
— Persian community name **پنل ربکا**, which transliterates to *Rebeka*. It is an
AGPL-3.0 **fork of Marzban**: FastAPI backend + React UI, with a Go node agent
(`Rebecca-node`) the master controls over a TLS REST API. The endpoint names below
were read from Rebecca's actual router source, not assumed.

> **AGPL-3.0 caveat:** Rebecca is AGPL. A *middleware* calling its HTTP API
> over the network does **not** become a derivative work, so the backend and
> Flutter app can stay proprietary. But *modifying Rebecca itself* and letting
> users interact with it over a network obliges offering that modified panel's
> source (AGPL §13). Run Rebecca unmodified, or budget for source disclosure of
> panel changes only.

---

## 1. Trust model — one sentence

**The client is untrusted display hardware; the middleware is the sole authority
on identity, entitlement, and what VPN credential exists at any moment.** Every
security requirement you listed is a corollary of that sentence.

| Your requirement | How Phase 1 satisfies it |
|---|---|
| Client never talks to the panel | Only the middleware holds the panel JWT, on a private network. No panel hostname or token ever ships in the app. |
| Client never decides Premium | Tier is computed server-side by `effective_tier()` from store-verified `subscriptions`. The connect endpoint reads it; the client cannot pass it. |
| No server IP/token leak to unauthenticated users | Real node addresses live in `node_endpoints`, returned **only** inside an authenticated, attested, per-session encrypted payload — never from the catalog endpoint. |
| Ephemeral / restricted credentials | Each connect mints a **new** panel user with a short `expire`, a `data_limit`, and only tier-appropriate inbound tags; it is revoked on disconnect/expiry. |

---

## 2. Component topology

```
 ┌─────────────┐   HTTPS + cert pinning + attestation   ┌──────────────────────┐
 │ Flutter app │ ─────────────────────────────────────► │   Middleware (NestJS) │
 └─────────────┘   AES-256-GCM payload (per session)     │  Postgres · Redis     │
        ▲                                                 └───────────┬──────────┘
        │ encrypted config payload                     server-to-server│ (private net / WG)
        │                                                  panel JWT    ▼
        │                                              ┌────────────────────────┐
        └────────── dials node directly ─────────────►│  Rebecca master (panel) │
                    (VLESS/Trojan over Xray)           └───────────┬────────────┘
                                                          TLS REST  │ controls
                                                                    ▼
                                                        ┌────────────────────────┐
                                                        │ Rebecca-node × N (Xray) │◄── client traffic
                                                        └────────────────────────┘
```

**Network rule:** the Rebecca master's API binds to a private interface
(WireGuard/VPC) reachable only by the middleware. Public ingress to the panel is
blocked at the firewall. The only public surfaces are (a) the middleware API and
(b) the Xray inbound ports on the nodes.

---

## 3. API routing architecture

All endpoints under `/api/v1`. Auth tiers:
**P** = public, **A** = access-JWT (15 min), **AT** = access-JWT **+** fresh
attestation token bound to this request.

### Auth & device
| Method | Path | Tier | Purpose |
|---|---|---|---|
| POST | `/auth/anon` | P | First launch: create anonymous user+device, issue tokens. |
| POST | `/auth/register` | A | Claim anon account with email+password (argon2id). |
| POST | `/auth/login` | P | Email+password → tokens. Rate-limited, lockout on abuse. |
| POST | `/auth/refresh` | P | Rotate refresh token (reuse-detection revokes the family). |
| POST | `/auth/logout` | A | Revoke current refresh token. |
| POST | `/device/attest/challenge` | A | Issue one-time challenge (Play Integrity requestHash / App Attest clientDataHash). |
| POST | `/device/attest/verify` | A | Verify verdict/attestation server-side; bind to device. |

### Catalog & connection
| Method | Path | Tier | Purpose |
|---|---|---|---|
| GET | `/nodes` | A | Tier-filtered node list — **display metadata only** (id, country, city, load, premium flag). No addresses, ports, SNI, or keys. |
| POST | `/connect` | AT | The core endpoint. Verify entitlement → mint ephemeral panel user → return **encrypted** payload. |
| POST | `/sessions/{id}/heartbeat` | AT | Slide `expires_at`, return updated usage. Missing heartbeats → reaper revokes. |
| POST | `/sessions/{id}/disconnect` | A | Best-effort immediate revoke (outbox guarantees it). |
| GET | `/me` | A | Profile, tier, active session, quota remaining. |

### Store webhooks (server-to-server, not app traffic)
| Method | Path | Tier | Purpose |
|---|---|---|---|
| POST | `/webhooks/google/rtdn` | P* | Pub/Sub push. Dedupe on `messageId`, then `purchases.subscriptionsv2.get` (source of truth). |
| POST | `/webhooks/apple/assn` | P* | ASSN V2. Verify JWS x5c → Apple root, dedupe on `notificationUUID`. |

`P*` = unauthenticated path but cryptographically verified: Google via OIDC token
on the Pub/Sub push (audience check) + the API call being the real source of
truth; Apple via the signed JWS chain. Both are **idempotent** and persisted to
`store_notifications` before processing.

**Abuse controls on the public/auth surface (don't ship without these):**
- `/auth/anon` is the cheapest way to flood the DB. Rate-limit per IP and per
  install fingerprint, and require an attestation token before the *first*
  `/connect` so anonymous accounts can't farm free quota at scale.
- `/auth/login` and `/auth/refresh`: rate-limit + lockout; refresh-reuse
  detection revokes the whole `family_id` lineage atomically.
- JWTs are **always** signature-verified server-side. Pinning is a transport
  control, not an authorization one — never infer trust from "the TLS held."
- **Panel-down posture:** `/connect` fails closed. If the panel is unreachable
  past a threshold, stop minting sessions and surface a clear retry; never fall
  back to a long-lived/shared credential. Existing sessions degrade to
  `limited` rather than being trusted blindly.

---

## 4. The `/connect` flow (the heart of Phase 1)

This is where "the backend decides, the client obeys" becomes concrete.

```
1.  Authn        Cryptographically verify the access JWT signature (NEVER trust
                 it on the basis of TLS/pinning alone) → user_id, device_id.
2.  Attestation  Require a fresh attestation token for THIS request, and:
                 (a) challenge.purpose == 'connect' (reject a verdict minted for
                     device_register/iap_link — purpose confusion defense),
                 (b) the client ephemeral pubkey is bound into requestHash /
                     clientDataHash (see §6), reject on mismatch,
                 (c) Android: appRecognitionVerdict=PLAY_RECOGNIZED AND
                     appLicensingVerdict=LICENSED AND device label present;
                     iOS: assertion counter strictly > stored, signature valid.

   ── steps 3–7 run inside ONE SERIALIZABLE transaction ──────────────────────
3.  Entitlement  tier := effective_tier(user_id).  -- server-computed, never client-sent
                 Load plan limits (max_concurrent_sessions, ttl, data caps).
4.  Quota gate   Free tier: SELECT ... FROM daily_usage
                   WHERE user_id=$1 AND day=current_date FOR UPDATE.
                 remaining_bytes := plan cap − bytes_used today.
                 Reject (or serve throttled) if exhausted. Locking here is what
                 stops two simultaneous connects each seeing the full cap.
5.  Concurrency  SELECT ... FROM vpn_sessions WHERE user_id=$1
                   AND status IN ('provisioning','active','limited') FOR UPDATE.
                 If count >= max_concurrent_sessions: reject (429), OR if policy
                 is revoke-oldest, revoke the oldest *on the panel first* and
                 only then continue (never create the new user while the old one
                 may still be live). Partial unique index = one live/device.
6.  Node pick    Choose an 'active' node whose tier <= user tier, lowest load.
7.  Reserve      Generate panel_username = "s_" + base62(22) + fresh credential
                 UUID. INSERT vpn_sessions (status='provisioning') and enqueue a
                 create_user op in panel_operations — all in this same tx, which
                 now COMMITS. The panel call itself happens just after commit so
                 we never hold the panel's latency inside the DB lock.
   ───────────────────────────────────────────────────────────────────────────
8.  Provision    Call Rebecca POST /api/user {
                   username, expire = now + ttl, data_limit = remaining_bytes,
                   data_limit_reset_strategy = "no_reset", status = "active",
                   proxies = { vless: { id: <uuid>, flow } },
                   inbounds = { <protocol>: [<tier tags>] }  // REQUIRED, never empty
                 }
                 Then GET the user back and assert expire round-trips (seconds vs
                 ms guard) before trusting the session. inbounds MUST be a
                 non-empty tier-scoped allow-list — omitting it grants ALL
                 inbounds on the node.
9.  Build config Join the panel user with node_endpoints for the chosen node's
                 tier-appropriate inbound(s). Construct the sing-box/Xray
                 outbound JSON (the ONLY place real address/port/SNI/Reality
                 keys appear).
10. Encrypt      AES-256-GCM with the per-session key (§6). Return
                 { session_id, expires_at, alg, iv, ciphertext, tag, key_ref }.
11. Activate     Session stays 'provisioning' until the first successful
                 heartbeat (panel user confirmed reachable) flips it to 'active'.
                 The reaper fails any session still 'provisioning' after
                 provisioning_timeout (~30s) and revokes its panel user. This
                 absorbs the documented node-propagation delay — the client uses
                 short backoff on its first dial rather than assuming instant
                 availability.
```

**Session state machine:** `provisioning → active → (limited | expired |
revoked) → closed`, plus `provisioning → failed` (no heartbeat within timeout)
and any state `→ failed` on panel error. `limited` = data cap hit;
`expired` = TTL reached; `revoked` = entitlement/subscription pulled.

**Tier can only improve within a session, never degrade.** At heartbeat we
re-check `effective_tier`; if it rose (free→premium) we raise `data_limit` and
push it via `PUT /api/user`. If it fell, the current session runs to its
existing bound and the *next* connect is throttled — we don't yank an
in-flight connection.

**Why ephemeral users and not one fixed user per account:** a leaked config is
worthless within minutes (short `expire`), is traffic-capped (`data_limit`), is
revocable independently of the account, and naturally enforces concurrency.

---

## 5. How the backend proxies the panel without leaking IPs or tokens

Five concrete defenses:

1. **Token isolation.** The Rebecca admin JWT is obtained at boot
   (`POST /api/admin/token`, OAuth2 password form) using credentials from the
   secrets manager, cached in memory/Redis, refreshed before the
   `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` window. It is **never** serialized into any
   client response, log line, or error body.

2. **Address segregation in the schema.** Display metadata (`nodes`) and dial
   secrets (`node_endpoints`) are separate tables. The `/nodes` serializer
   physically cannot emit an address because it never queries that table. Only
   the payload-builder service (running as a restricted DB role with `SELECT` on
   `node_endpoints`) can.

3. **Secrets only inside the encrypted, per-session, attested payload.** Real
   addresses/ports/SNI/Reality keys leave the backend exclusively as AES-256-GCM
   ciphertext, produced only after authn + attestation + entitlement all pass.
   An unauthenticated or unattested caller never receives them in any form.

4. **No raw subscription-link passthrough.** Rebecca *can* hand out
   `/{token}/` subscription URLs, but those embed node hostnames and are
   guessable/shareable. We **do not** proxy them. The middleware fetches the
   user object server-side, extracts only the fields it needs, and rebuilds the
   config itself. The panel's subscription URL prefix is never revealed.

5. **Outbox-guaranteed revocation.** `panel_operations` makes revoke/delete
   durable. If the panel is briefly down when a session ends, the op retries
   until the ephemeral user is gone — leaked configs cannot outlive their TTL
   because both `expire` (panel-side) and the reaper (backend-side) bound them.

**Reality of "live kick" (from research):** deleting/disabling a panel user does
not always drop an already-established TCP connection immediately (confirmed
conditional for 3x-ui; not guaranteed across Marzban-family panels). We do not
rely on instant kick — the short `expire` + `data_limit` are the real bound, and
revocation is the backstop. This is a deliberate design choice, documented so we
don't assume a guarantee the panel doesn't make.

---

## 6. Payload encryption (Phase 1 contract; Phase 3 implements client side)

- **Cipher:** AES-256-GCM (authenticated; rejects tampering). 96-bit random IV
  per payload, 128-bit tag.
- **Key, done right:** *not* a static app-embedded key (that is the thing
  attackers extract first). The session key is derived per session:
  `HKDF-SHA256(ikm = ECDH(server_ephemeral, client_session_pub), salt = session_id, info = "vpncfg|v1")`.
  The client generates an ephemeral X25519 keypair at `/connect` time and sends
  its public key; the server replies with its ephemeral public key in `key_ref`.
  Result: a unique key per session, no shared secret in the binary, forward
  secrecy, and the obfuscated-key requirement is met by construction rather than
  by hiding a constant.
- **CRITICAL — bind the client key to attestation (closes a real hole).** ECDH
  alone does *not* stop a rooted client (or an attacker who defeats pinning)
  from substituting *its own* ephemeral public key, receiving the payload, and
  decrypting it with the matching private key — attestation proves the *device*
  is genuine, not that *this key* belongs to this request. So the client public
  key MUST be bound into the attestation:
  - **Android:** `requestHash = SHA-256(client_pub || session_nonce)`; the
    server recomputes it from the submitted key and rejects on mismatch before
    deriving the secret.
  - **iOS:** include `SHA-256(client_pub)` in the App Attest assertion's
    `clientDataHash` for the `/connect` call.
  Without this binding the per-session encryption is theatre; with it, a
  substituted key fails attestation and never reaches HKDF.
- **Defense in depth, not a TLS replacement:** this rides *inside* TLS with cert
  pinning (Phase 3). The encrypted payload protects the config even against a
  user who defeats pinning on a rooted device — they still can't read a payload
  whose key never existed in the binary.

---

## 7. Entitlement source of truth (store-driven)

The client's purchase receipt is a *hint*; entitlement is established only by
server verification:

- **Google:** RTDN (Pub/Sub) tells us *something changed*; we then call
  `purchases.subscriptionsv2.get` — the documented source of truth — and write
  `subscriptionState`, `expiryTime`, `linkedPurchaseToken`, etc. Grace period →
  keep access; on-hold/revoked → cut access immediately. Acknowledge new
  purchases within 3 days.
- **Apple:** ASSN V2 signed payload (verify JWS chain to Apple root) +
  App Store Server API `Get All Subscription Statuses`. Key on
  `originalTransactionId`; map to our user via the `appAccountToken` UUID we set
  at purchase. Grace → entitle until `gracePeriodExpiresDate`; REFUND/REVOKE
  (status 5) → cut.

`effective_tier()` reads only verified `subscriptions` rows, so a modded client
that fakes a receipt changes nothing server-side.

**`subscription_status` mapping (entitled = `active` or `in_grace` only):**

| Store event | → `subscriptions.status` | Entitled? |
|---|---|---|
| Google PURCHASED / RENEWED / RECOVERED · Apple SUBSCRIBED / DID_RENEW | `active` | ✅ |
| Google IN_GRACE_PERIOD · Apple DID_FAIL_TO_RENEW (GRACE_PERIOD) | `in_grace` (until `grace_period_end`) | ✅ |
| Google ON_HOLD · Apple status 3 (billing retry, no grace) | `on_hold` | ❌ |
| Google PAUSED | `paused` | ❌ |
| Google CANCELED · Apple DID_CHANGE_RENEWAL_STATUS(off) | `canceled` (access until period end) | ✅ until end |
| Google EXPIRED · Apple EXPIRED | `expired` | ❌ |
| Google REVOKED · Apple REFUND / REVOKE (status 5) | `revoked` | ❌ (cut now) |

On Google resubscribe-after-expiry, the new notification carries
`linkedPurchaseToken` → look up the superseded row via
`subscriptions.google_linked_purchase_token` and mark it `canceled` before the
new row goes `active`. Acknowledge new Google purchases within 3 days
(`google_acknowledged_at`); an unacked worker scan catches stragglers.

---

## 8. Attestation gate (Phase 1 wiring; Phase 4 hardens)

- **Android — Play Integrity:** use **standard requests** (warm-up + low latency)
  on `/connect`; bind with `requestHash`. Server-decode via
  `decodeIntegrityToken`. Require `PLAY_RECOGNIZED` + `LICENSED`; gate premium on
  device label. **Note the May 2025 change:** `MEETS_DEVICE_INTEGRITY` on
  Android 13+ now needs hardware-backed locked-bootloader proof, so rooted /
  custom-ROM devices fail — set policy (block vs. degrade) deliberately.
- **iOS — App Attest:** one-time `attestKey` at device registration (store
  keyId, public key, receipt, counter); per-`/connect` `generateAssertion` with
  strictly increasing counter (enforced by the `devices` counter trigger +
  app check). **Fallback is wired into the schema:** when a platform can't
  attest (iOS simulator, Mac Catalyst, some extensions), set
  `devices.attestation_capable = false` and serve free tier only, with extra
  rate-limiting — don't hard-fail. For Android, `devices.rooted_indicator`
  records the absence of `MEETS_DEVICE_INTEGRITY` (post-May-2025 rooted devices)
  so the rooted policy (block / free-only / degrade) is a config decision, not
  scattered logic.

---

## 9. Open decisions for you (don't block Phase 1 coding)

1. **Anonymous-first vs. mandatory signup** before any free connection.
2. **Concurrency-exceeded policy:** reject the new connect, or revoke the oldest
   session?
3. **Rooted/jailbroken policy:** hard block, or allow free tier only?
4. **Free quota dimension:** daily data cap, daily time cap, or both?
5. **Panel substitution stance:** Rebecca is a small AGPL fork on a stalled
   upstream (Marzban). The integration layer (§5, §11) is written against the
   common Marzban-family API, so Marzneshin/PasarGuard/Remnawave remain drop-in
   alternatives if Rebecca maintenance lapses.

---

## 10. Phase 1 build order

1. DB migrations from [`db/schema.sql`](../db/schema.sql) + plan seed.
2. `PanelClient` (typed Rebecca wrapper: token cache, create/extend/revoke user,
   list nodes/inbounds/usage) — see §11.
3. Auth (anon, register, login, refresh rotation) + argon2id.
4. Node sync worker (panel → `nodes`/`node_inbounds`/`node_endpoints`).
5. `/connect` transactional flow + AES-GCM/HKDF payload builder.
6. Heartbeat + reaper + `panel_operations` worker.
7. Store webhook intake (Google RTDN, Apple ASSN V2) + `effective_tier`.
8. Attestation verification services (Play Integrity decode, App Attest validate).

The DB schema in [`db/schema.sql`](db/schema.sql) is the deliverable to lock
first — §11 below is the panel-integration contract that the rest builds on.
