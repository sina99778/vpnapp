import 'package:flutter/services.dart';

/// Thin Dart front for the NATIVE anti-tamper checks. The real work (Frida
/// scan, root/JB detection, anti-debug) lives in C/JNI and Swift/C and FAILS
/// CLOSED by `abort()` on detection — so a positive result usually never
/// returns to Dart at all. This method exists so Dart can (a) trigger the
/// native sweep at key moments and (b) react gracefully in the rare case a
/// soft signal is reported instead of an immediate abort.
///
/// Zero-Trust note: this is defense in depth only. The real guarantee is
/// server-side attestation ([AttestationService]); a fully-compromised device
/// can patch any client-side check. We make that expensive, not impossible.
class IntegrityGuard {
  IntegrityGuard([MethodChannel? channel])
      : _channel = channel ?? const MethodChannel('app.securevpn/security');

  final MethodChannel _channel;

  /// Run the native sweep. Returns normally when the environment looks clean.
  /// If native reports a soft signal, returns false; on a hard signal native
  /// has already aborted the process. Treat any thrown/clean-miss as suspicious.
  Future<bool> isEnvironmentClean() async {
    try {
      final ok = await _channel.invokeMethod<bool>('assertIntegrity');
      return ok ?? false;
    } on PlatformException {
      // Channel error on a security check is itself suspicious → fail closed.
      return false;
    } on MissingPluginException {
      return false;
    }
  }
}
