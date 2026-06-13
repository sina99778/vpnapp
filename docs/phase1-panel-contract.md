# §11 — Rebecca (Marzban-family) integration contract

Verified against Rebecca's router source (`app/routers/`). All paths are on the
panel's **private** interface. The middleware holds exactly one admin identity.

## Auth
```
POST /api/admin/token            # OAuth2 password form (username, password)
  → { access_token, token_type } # JWT bearer; cache, refresh before TTL
```
`JWT_ACCESS_TOKEN_EXPIRE_MINUTES` default 1440. There is **no static API key** —
the JWT is the only credential, so treat it like one (memory/Redis, never logged).

## Operations the middleware actually calls

| Intent | Rebecca call | Notes |
|---|---|---|
| Mint ephemeral user | `POST /api/user` | `expire` (unix ts), `data_limit` (bytes), `status`, `proxies`, `inbounds` (tag allow-list). Inbound tags are the tier gate. |
| Extend on heartbeat | `PUT /api/user/{username}` | push `expire` forward; raise `data_limit` if tier improved. **Verify whether PUT is a full replace or a partial patch (see below) — a full replace with a delta body would wipe `proxies`/`inbounds`.** |
| Revoke immediately | `PUT /api/user/{username}` `status=disabled` then `DELETE /api/user/{username}` | disable first (fast), delete to reclaim. When revoking-oldest for concurrency, the disable MUST land before the new user is provisioned. |
| Read usage | `GET /api/user/{username}/usage?start=&end=` | feeds `vpn_sessions.bytes_used` / `daily_usage`. |
| Sync nodes | `GET /api/nodes`, `GET /api/node/{id}` | → `nodes` (+ health/load). |
| Sync inbounds | `GET /api/inbounds/full` | → `node_inbounds` + `node_endpoints` (address/port/security). |
| Garbage-collect | `DELETE /api/users/expired` | belt-and-suspenders for orphaned ephemerals. |

## Field semantics to verify against a live `/docs`
- `expire`: Marzban uses a **unix timestamp** (seconds). Rebecca inherits this;
  confirm on your instance — a milliseconds/seconds mix-up silently makes
  sessions never expire. **This is the single most important field to verify.**
  Enforce it in code: after every `create_user`, GET the user back and assert
  the returned `expire` matches what was sent (±1s); fail closed on mismatch.
- `data_limit`: **bytes** (0 = unlimited — never send 0 for free tier).
- `data_limit_reset_strategy`: use `no_reset` for ephemerals.
- `inbounds`: omitting it may grant **all** inbounds — always send an explicit
  non-empty tier-scoped allow-list. Treat a missing/empty `inbounds` in the
  payload builder as a hard error, not a default.
- `proxies`: include every proxy type the chosen tier's inbounds actually use
  (vless/trojan/vmess/shadowsocks); a node whose inbound is Trojan won't accept
  a user that only carries a VLESS credential.
- **PUT update semantics:** confirm on your instance whether `PUT /api/user`
  replaces the whole object or patches fields. If it replaces, the extend path
  must GET-merge-PUT so it doesn't blank `proxies`/`inbounds`/`status`. Cover
  this with an integration test (create with specific inbounds → extend → GET →
  assert inbounds unchanged).

## Application-layer enforcement (don't trust the panel blindly)
The panel is the credential authority, not a trusted guarantor. Keep a second
layer in the middleware:
- Reconcile `vpn_sessions.bytes_used` / `daily_usage` from the panel usage API
  at each heartbeat; if cumulative use exceeds the issued `data_limit`, mark the
  session `limited` yourself rather than waiting on the panel.
- Don't assume revoke/delete drops a live TCP connection — short `expire` +
  `data_limit` + the reaper are the real bound.
- Garbage-collect disabled/expired panel users (`DELETE /api/users/expired`,
  plus a sweep of long-disabled users) so a delete that failed while the panel
  was down can't accumulate.

## Webhooks (optional, recommended)
Set `WEBHOOK_ADDRESS` → middleware ingest; verify `x-webhook-secret`
(`WEBHOOK_SECRET`). Useful events: `user_expired`, `user_limited`,
`user_deleted`, `data_usage_reset`. These let the backend close
`vpn_sessions` promptly instead of waiting on the poll loop.

## Failure handling (non-negotiable)
- **Idempotency:** `panel_username` is unique and random; retried `create_user`
  ops must tolerate "already exists."
- **Outbox:** every mutating call is mirrored in `panel_operations`; a revoke is
  never fire-and-forget.
- **No instant-kick assumption:** disabling/deleting may not drop a live TCP
  connection at once. Short `expire` + `data_limit` are the real bound; revoke is
  the backstop (see architecture §5).
- **Panel-down posture:** `/connect` fails **closed** (no session, clear error) —
  never fall back to a long-lived or shared credential.
