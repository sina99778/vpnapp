# Phase 2 — Flutter Client Architecture

## State management: Riverpod 2 (not BLoC)

Chosen over BLoC for three reasons that matter to *this* app:

1. **It is also our DI container.** The composition root in
   [`connection_providers.dart`](../flutter_app/lib/features/connection/presentation/connection_providers.dart)
   wires `SecureStore → ApiClient → ConnectionRepository → ConnectionFlowController`
   with override points for tests — no second DI package, no service locator,
   and providers are reachable from background callbacks (VPN event stream, ad
   flow) where a `BuildContext` may not exist.
2. **Streams are first-class.** The native VPN core pushes state + traffic over
   an `EventChannel`; `StreamProvider` turns those into reactive UI with
   auto-dispose and last-value caching.
3. **Less ceremony than BLoC** for what is fundamentally one sequential state
   machine. The flow is a plain controller emitting an immutable
   `ConnectionFlowState`, exposed via `StateNotifierProvider`.

BLoC maps 1:1 onto this (a `Cubit` per service, a `Bloc` for the flow) if
preferred — nothing outside `features/` would change. The flow logic lives in
**pure Dart** (`domain/connection_flow.dart`) with zero Flutter imports, so it
is unit-testable headless and survives obfuscation.

## Directory structure (feature-first, obfuscation-ready)

```
lib/
  main.dart                      # bootstrap: init ads SDK, ProviderScope
  core/                          # cross-cutting, no feature knowledge
    config/app_config.dart       # --dart-define values, channel names, pins
    crypto/payload_crypto.dart   # X25519 + HKDF + AES-256-GCM (pure Dart)
    network/api_client.dart      # dio + TLS pinning + auth refresh
    storage/secure_store.dart    # Keychain / EncryptedSharedPreferences
    errors/failures.dart         # sealed AppFailure hierarchy
  features/
    ads/
      domain/ad_reward_service.dart      # interface + AdPresentation
      data/admob_reward_service.dart     # AdMob + SSV nonce injection
    vpn/
      domain/vpn_engine_service.dart     # interface + state/traffic models
      data/singbox_vpn_engine.dart       # MethodChannel + EventChannel bridge
    connection/
      data/connection_repository.dart    # /connect + /verify-ad-reward + decrypt
      domain/connection_flow.dart        # the state machine
      presentation/connection_providers.dart  # Riverpod wiring
  shared/
    models/connection_models.dart        # DTOs + decrypted VpnProfile
```

## Zero-Trust principles enforced on the client

1. **The client decides nothing about entitlement.** It never computes tier and
   never trusts AdMob's *client-side* `onUserEarnedReward` for credit — that
   callback only advances the UX; the **server** counts ads via SSV.
2. **No secrets in the binary.** No panel host, no admin token, no static AES
   key. The payload key is derived per session via ECDH; the client holds only
   an ephemeral private key that lives for one session in memory.
3. **The config is opaque until the server releases it.** The encrypted payload
   arrives only from `verify-ad-reward`, after the ads are server-verified, and
   is JSON-shape-checked before it crosses the channel to native.
4. **Fail closed.** Any step failing (decrypt, MAC check, engine start, or a
   tunnel that never reports `connected`) aborts the flow and tears down — never
   falls back to a cached config.

## Why obfuscation-ready

- All crypto is **pure Dart** (`cryptography`), so `flutter build --obfuscate`
  has no native blob to skip and the key-agreement code is renamed/minified.
- Obfuscation renames symbols but **not** string literals — channel names and
  URLs stay visible. That is *why* security lives in SSL pinning + payload
  encryption + SSV, not in hiding strings.
- Domain logic has no Flutter coupling, so tree-shaking/renaming are
  unconstrained.
- Release: `flutter build apk --obfuscate --split-debug-info=build/symbols`
  (keep symbol files to symbolicate crashes).

## What is intentionally NOT in Dart

Per the research, the sing-box runtime, the tun interface, socket protection,
the Android foreground service, and the iOS `NEPacketTunnelProvider` / App Group
container **must** be native (Kotlin/Swift) — Dart cannot subclass `VpnService`
or run the core's goroutine runtime. Phase 2 delivers the **Dart side and the
channel contract**; the native modules are stubs to fill next, against the exact
shapes in `singbox_vpn_engine.dart`.

## Native channel contract (what the Kotlin/Swift side must implement)

`MethodChannel('app.securevpn/vpn')` — calls from Dart:
- `prepare() -> bool` — Android: `VpnService.prepare()` + Activity result; iOS:
  load/save `NETunnelProviderManager`. Returns whether consent is granted.
- `start({sessionId, config, hardExpiryEpochMs}) -> void` — feed `config`
  (sing-box JSON) to the core; self-terminate at `hardExpiryEpochMs`. Throw
  `PlatformException(code: 'consent_denied'|'already_running'|'bad_config')`.
- `stop() -> void` — idempotent teardown.
- `status() -> String` — one of the state names.

`EventChannel('app.securevpn/vpn_events')` — events to Dart (maps):
- `{type:'state', state:'connecting'|'connected'|...}`
- `{type:'traffic', uploadBytes, downloadBytes, uploadSpeed, downloadSpeed}` —
  **throttled on the native side** (the core emits 100+/s; coalesce to ~1/s).

## Backend contract note (sentinel nonce)

The best-effort "watch 1 ad to disconnect" step shows a closing ad with the
sentinel nonce `closing-session-no-grant`. The middleware MUST treat this
`custom_data` value as never-grantable, so even a validly-signed SSV callback
for it cannot fund any grant.
