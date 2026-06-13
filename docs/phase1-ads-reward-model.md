# Phase 1 (update) — Time-Based Reward Model via Ads

Replaces the daily data cap. **Connection time is earned by watching rewarded
ads, proven by server-side verification (SSV) — never by the client.**

## Trust anchor

The client's `verify-ad-reward` call is **not** trusted to assert "I watched an
ad." The proof comes from a **server-to-server SSV callback** that the ad
network (AdMob) sends directly to our backend, carrying a signature we verify
against the network's public keys. A patched client (Lucky Patcher et al.)
cannot forge that signature because the key is Google's, never on the device.
`verify-ad-reward` only **claims** rewards we already proved.

## The three endpoints

```
POST /ads/request-ad-token   (auth)   issue a single-use grant + nonce
GET  /ads/admob/ssv          (public, signed)  AdMob → us: the proof
POST /ads/verify-ad-reward   (auth)   claim a fulfilled grant → +60 min
```

## Flow (connect = 2 ads → exactly 60 min)

```
Client                Middleware                AdMob servers         Rebecca panel
  │  request-ad-token ──▶│ create grant(nonce,            │                  │
  │                      │   required_ads=2)              │                  │
  │◀── {grantId,nonce} ──│                                │                  │
  │                                                       │                  │
  │  show ad #1 (custom_data = nonce) ───────────────────▶│                  │
  │                      │◀── GET /ads/admob/ssv (signed)─│ (verify sig,     │
  │                      │      insert ad_rewards,        │  bump grant→1)   │
  │  show ad #2 ─────────────────────────────────────────▶│                  │
  │                      │◀── GET /ads/admob/ssv (signed)─│ (grant→2 = fulfilled)
  │                                                       │                  │
  │  verify-ad-reward ──▶│ TX: lock grant+session,        │                  │
  │   {grantId,sessionId}│  check verified_ads≥2,         │                  │
  │                      │  expires_at += 60m, consume,   │                  │
  │                      │  enqueue outbox op. COMMIT ────┼──(locks released)│
  │                      │  setUserExpiry(now+60m) ───────┼─────────────────▶│ (Xray drops at expiry)
  │◀── {expiresAt} ──────│                                │                  │
```

## The two invariants this design holds

1. **No DB locks during external I/O.** Every panel/ad-network call happens
   *after* the transaction commits. `verify-ad-reward` does all locked work
   (validate → extend `expires_at` → consume grant → enqueue outbox op) inside
   one short transaction, commits, *then* calls the panel. The outbox worker
   drains the same way: claim under `FOR UPDATE SKIP LOCKED` → commit → dispatch.
   If the inline panel call fails, the DB expiry is already authoritative and
   the worker converges the panel; the reaper enforces expiry regardless.

2. **A grant funds exactly one session, exactly once.** `verify-ad-reward`
   rejects a `sessionId` that doesn't match the grant's bound session; the grant
   is `consumed` inside the locked transaction so concurrent calls can't
   double-spend it; replay returns the grant's own bound session, not the
   request's.

## Replay / fraud defenses (layered)

- **Signature** over the raw SSV query string (ECDSA-P256/SHA-256, AdMob keys).
- **`unique(network, transaction_id)`** — a redelivered callback can't be
  counted twice.
- **`nonce` (custom_data)** ties each callback to one grant; single-use.
- **Timestamp freshness** (≤10 min) caps the stale-callback window.
- **Grant window** (`expires_at`, ~15 min) — rewards only count while open.

## Connection model — DECIDED: Provisioning Model

`/connect` (attested) creates the session in `provisioning` with a **short 5-min
TTL** and, in the same call, mints the `connect` grant bound to that session
(`required_ads=2`, `grant_minutes=60`). It returns `{sessionId, grantId, nonce,
requiredAds, provisioningExpiresAt}` and **does NOT return the encrypted
payload**. The client watches its 2 ads (passing `nonce` as `custom_data`), then
calls `verify-ad-reward`, which extends the session to a full 60 minutes, flips
it to `active`, and **only then returns the encrypted config payload**. No ads →
the provisioning session simply lapses after 5 minutes and is reaped; the client
never receives a usable config.

This means the client ephemeral public key (for the per-session ECDH payload
key, Phase 1 §6) is sent and bound into attestation at `/connect`, while the
server's ephemeral public key + ciphertext come back from `verify-ad-reward`.

## Other wiring (noted, not blocking)

- AdMob SSV requires a single, stable public callback URL configured in the
  AdMob console, and a reverse proxy that does **not** rewrite URL encoding
  (the signature is byte-exact).
- The same pattern accepts other networks (AppLovin/Unity) behind the
  `ad_network` enum — each needs its own signature verifier.
