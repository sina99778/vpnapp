/// Typed, exhaustive failure model. Every layer converts low-level exceptions
/// (DioException, PlatformException, FormatException, crypto errors) into one of
/// these so the UI can switch on a closed set and never leaks a raw stack trace.
sealed class AppFailure implements Exception {
  const AppFailure(this.message, {this.cause});

  /// Human-safe message (no secrets, no internal detail).
  final String message;

  /// Original error for logging only — never shown to the user.
  final Object? cause;

  @override
  String toString() => '$runtimeType: $message';
}

/// No network / timeout / DNS — retryable.
class NetworkFailure extends AppFailure {
  const NetworkFailure([String message = 'Network unavailable.', {Object? cause})
      : super(message, cause: cause);
}

/// TLS pin mismatch. This is a hard security stop — likely MITM. NOT retryable
/// and must be surfaced distinctly so we can alert/telemetry on it.
class PinningFailure extends AppFailure {
  const PinningFailure([String message = 'Secure connection could not be verified.', {Object? cause})
      : super(message, cause: cause);
}

/// 4xx/5xx from the middleware with a parsed error code.
class ApiFailure extends AppFailure {
  const ApiFailure(super.message, {required this.statusCode, this.code, super.cause});

  final int statusCode;

  /// Machine-readable error code from the backend body, e.g. 'grant_expired'.
  final String? code;
}

/// Auth/attestation rejected — re-auth or re-attest required.
class AuthFailure extends AppFailure {
  const AuthFailure([String message = 'Authentication required.', {Object? cause})
      : super(message, cause: cause);
}

/// Ad failed to load/show, or the user dismissed it before completion.
class AdFailure extends AppFailure {
  const AdFailure(super.message, {this.kind = AdFailureKind.unknown, super.cause});
  final AdFailureKind kind;
}

enum AdFailureKind { noFill, showFailed, dismissedEarly, timeout, unknown }

/// Payload could not be decrypted/parsed. Treated as a security failure (the
/// config is untrusted garbage) — fail closed, never start the tunnel.
class PayloadFailure extends AppFailure {
  const PayloadFailure([String message = 'Server configuration was invalid.', {Object? cause})
      : super(message, cause: cause);
}

/// Native VPN engine error (consent denied, tun setup failed, core crashed).
class VpnEngineFailure extends AppFailure {
  const VpnEngineFailure(super.message, {this.kind = VpnFailureKind.unknown, super.cause});
  final VpnFailureKind kind;
}

enum VpnFailureKind { consentDenied, startFailed, alreadyRunning, coreCrash, unknown }

/// The provisioning window lapsed before the user finished the ads.
class ProvisioningExpiredFailure extends AppFailure {
  const ProvisioningExpiredFailure([String message = 'Time window expired — please reconnect.', {Object? cause})
      : super(message, cause: cause);
}
