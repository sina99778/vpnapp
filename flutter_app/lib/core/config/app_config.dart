/// Compile-time configuration. Values are injected with --dart-define so that
/// different flavors (dev/staging/prod) ship different endpoints, ad units, and
/// pinned certificates without code changes.
///
/// Zero-Trust note: NONE of these strings are secrets. Obfuscation does not
/// hide them. Security comes from SSL pinning (the cert fingerprints below) and
/// per-session payload encryption — never from hiding the base URL.
class AppConfig {
  const AppConfig._();

  /// Middleware base URL. The app NEVER talks to the Rebecca panel directly.
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://api.example-vpn.com',
  );

  /// SHA-256 fingerprints (base64) of the pinned certificate DER. Provide at
  /// least two (current leaf + backup/next) so a rotation can't brick clients.
  /// Compute with:  openssl x509 -in cert.pem -outform der | openssl dgst -sha256 -binary | base64
  /// Empty in dev builds => falls back to system trust (see ApiClient).
  static const String _pinsRaw = String.fromEnvironment('TLS_PINS_B64');
  static List<String> get tlsPinsBase64 =>
      _pinsRaw.isEmpty ? const [] : _pinsRaw.split(',');

  /// AdMob rewarded ad unit (platform-specific value injected per build).
  static const String rewardedAdUnitId = String.fromEnvironment(
    'REWARDED_AD_UNIT_ID',
    // Google's official test unit; replaced per-platform in real builds.
    defaultValue: 'ca-app-pub-3940256099942544/5224354917',
  );

  /// Number of ads the backend requires to fund a connect grant. The client
  /// shows this many, but the BACKEND is authoritative (it counts SSV
  /// callbacks); this is only a UI hint, refreshed from /connect's response.
  static const int defaultRequiredAds = 2;

  // Platform channel identifiers (must match the native side byte-for-byte).
  static const String vpnMethodChannel = 'app.securevpn/vpn';
  static const String vpnEventChannel = 'app.securevpn/vpn_events';

  /// Payload crypto context — MUST match the middleware's HKDF `info` and the
  /// algorithm tag returned in the encrypted payload. Changing either side
  /// without the other makes every connect fail closed (by design).
  static const String payloadAlg = 'x25519-hkdf-sha256-aes256gcm';
  static const String payloadHkdfInfo = 'vpncfg|v1';

  /// How long the provisioning window lasts before the server reaps it. Used
  /// only to fail the client fast with a friendly message; the server clock is
  /// authoritative.
  static const Duration provisioningBudget = Duration(minutes: 5);
}
