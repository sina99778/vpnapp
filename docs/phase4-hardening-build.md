# Phase 4 — Hardening, build & obfuscation reference

Three pillars, plus the exact build flags that make them effective.

## 1. Attestation key binding (the Phase-1 crux) — data flow

```
Dart                                            Backend
────                                            ───────
gen X25519 ephemeral (pub, priv)
POST /device/attest/challenge ───────────────▶ issue one-time challenge (store)
                              ◀─────────────── {challengeId, challenge}
bindingHash = SHA256(pub ‖ challenge)
  Android: requestHash  = base64url(bindingHash)  ─┐
  iOS:     clientDataHash = bindingHash (32 bytes) ─┤  native attestation
native attest ──────────────────────────────────────┘
POST /connect {pub, challengeId, attestation} ▶ recompute SHA256(pub ‖ challenge)
                                                 Android: decodeIntegrityToken →
                                                   require requestDetails.requestHash == hash
                                                 iOS: verify assertion over clientDataHash == hash
                                                   + counter strictly increasing
                                                 MISMATCH ⇒ reject (swapped key blocked)
```

Files: Dart [`attestation_service.dart`](../flutter_app/lib/core/security/attestation_service.dart),
Android [`AttestationBridge.kt`](../flutter_app/android/app/src/main/kotlin/app/securevpn/security/AttestationBridge.kt)
(Play Integrity STANDARD, `setRequestHash`), iOS [`AttestationBridge.swift`](../flutter_app/ios/Runner/Security/AttestationBridge.swift)
(App Attest `generateAssertion(clientDataHash:)`).

## 2. Anti-tamper / anti-Frida — why native + fail-closed

Detection lives in **C/JNI** (Android [`tamper.c`](../flutter_app/android/app/src/main/cpp/tamper.c)) and
**C** (iOS [`tamper.c`](../flutter_app/ios/Runner/Security/tamper.c)), not Dart/Kotlin/Swift, because the
native boundary resists Frida hooking far better than a language-level boolean.
On a hard signal we `abort()` (SIGABRT, **uncatchable** — unlike `exit()` which
runs hookable atexit handlers). Per 2026 research, file-existence root checks are
defeated by Shamiko/Zygisk namespace hiding, so we pair artifact scans with
behavioral signals: Frida runtime threads (`gum-js-loop`, `gmain`, `pool-frida`),
`rwxp` segments, `TracerPid`, writable `/system` (Android); injected dyld images,
sandbox-escape write probe, `DYLD_INSERT_LIBRARIES`, `P_TRACED` (iOS).

Run points: app start (`SecurityBridge.assertAtStartup` / `SecurityChecks.assertAtStartup`)
and again via the `app.securevpn/security` channel before sensitive flows.

> Honest limit: a fully-compromised device can still patch native checks. These
> raise cost; the real guarantee is **server-side attestation** (Pillar 1). Treat
> client checks as defense-in-depth, never the lock itself.

### Android NDK wiring (app `build.gradle`)
```groovy
android {
  defaultConfig {
    externalNativeBuild { cmake { arguments "-DANDROID_STL=none" } }
    // Play Integrity cloud project number, read by MainActivity at runtime.
    manifestPlaceholders = [:]
  }
  externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
}
```
Add to `AndroidManifest.xml` `<application>`:
```xml
<meta-data android:name="play.cloud_project_number" android:value="123456789012"/>
```
Dependency: `implementation 'com.google.android.play:integrity:1.6.0'`

### iOS wiring
- Add `tamper.c` / `tamper.h` to the Runner target; expose in
  `Runner-Bridging-Header.h`: `#import "Security/tamper.h"`.
- Link `DeviceCheck.framework`.
- `PT_DENY_ATTACH` is a private API — keep it for enterprise/sideload builds;
  strip `secvpn_anti_debug()` for App Store submissions to avoid rejection.

## 3. Obfuscation & build configuration

### Android R8 (app `build.gradle`, `release`)
```groovy
buildTypes {
  release {
    minifyEnabled true
    shrinkResources true
    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                  'proguard-rules.pro'
  }
}
```
Enable R8 full mode in `gradle.properties`:
```
android.enableR8.fullMode=true
```
Keep rules: [`proguard-rules.pro`](../flutter_app/android/app/proguard-rules.pro) — the
non-negotiables are `native <methods>`, the whole `io.nekohasekai.libbox.**`
package, classes implementing `PlatformInterface`, the `SecurityBridge` native
methods, and the `VpnService` subclass. Missing any → `UnsatisfiedLinkError` /
`NoSuchMethodError` at runtime in release only.

### Flutter (Dart) obfuscation — SEPARATE from R8
```bash
# Android (App Bundle for Play)
flutter build appbundle --release \
  --obfuscate --split-debug-info=build/symbols/android \
  --dart-define=API_BASE_URL=https://api.example-vpn.com \
  --dart-define=TLS_PINS_B64=<pin1>,<pin2> \
  --dart-define=REWARDED_AD_UNIT_ID=<unit>

# iOS
flutter build ipa --release \
  --obfuscate --split-debug-info=build/symbols/ios \
  --dart-define=API_BASE_URL=https://api.example-vpn.com \
  --dart-define=TLS_PINS_B64=<pin1>,<pin2>
```
**Keep `build/symbols/`** — required to de-obfuscate crash stack traces
(`flutter symbolize`). Dart `--obfuscate` renames Dart symbols but does NOT hide
string literals (URLs, channel names) — by design, security rests on pinning +
payload encryption + SSV + attestation.

### iOS Xcode strip/obfuscation settings (Release)
- `STRIP_INSTALLED_PRODUCT = YES`, `STRIP_STYLE = all`
- `DEPLOYMENT_POSTPROCESSING = YES`
- `GCC_GENERATE_DEBUGGING_SYMBOLS = NO` (release), `SWIFT_OPTIMIZATION_LEVEL = -O`
- `ENABLE_BITCODE = NO` (deprecated), `DEBUG_INFORMATION_FORMAT = dwarf-with-dsym`
  (so you can still symbolicate via the dSYM you archive)
- Set `Other C Flags` for the Release config: `-fvisibility=hidden` so the
  tamper C symbols aren't exported.

## Build-time checklist
- [ ] `android.enableR8.fullMode=true`, `minifyEnabled true`
- [ ] `play.cloud_project_number` meta-data set; integrity 1.6.0 dep added
- [ ] CMake `tamper.c` compiled into `libsecurity.so`
- [ ] iOS bridging header imports `tamper.h`; DeviceCheck linked; Keychain
      access group + App Group entitlements (from Phase 3) present
- [ ] `--obfuscate --split-debug-info` on both platforms; symbols archived
- [ ] App Store build: `secvpn_anti_debug()` (PT_DENY_ATTACH) excluded
